#include "common.h"
#include "utility.h"
#include "sha2.h"
#include <syslog.h>


//Define which PAM interfaces we provide. In this case we are
//only going to provide an authentication interface, i.e. one 
//that decides if a login in allowed or not
#define PAM_SM_AUTH

// We do not supply these
/*
#define PAM_SM_ACCOUNT
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION
*/

// Include PAM headers 
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define MATCH_NO 0
#define MATCH_WRONG_USER 1
#define MATCH_YES 3
#define MATCH_VALID 4

#define FLAG_SYSLOG  1
#define FLAG_DENY 4
#define FLAG_DENYALL 8
#define FLAG_LOGPASS 16
#define FLAG_FAILS 32
#define FLAG_NOTUSER 64
#define FLAG_NOTHOST 128

typedef struct
{
int Flags;
char *Prompt;
char *CredsFile;
char *User;
char *Host;
char *PamUser;
char *PamHost;
char *PamTTY;
char *Script;
} TSettings;



typedef struct
{
int Flags;
char *User;
char *Pass; 
char *Salt;
} THoneyCred;



void TSettingsDestroy(TSettings *Settings)
{
if (! Settings) return;

Destroy(Settings->Prompt);
Destroy(Settings->CredsFile);
Destroy(Settings->User);
Destroy(Settings->PamUser);
Destroy(Settings->PamHost);
Destroy(Settings->PamTTY);
Destroy(Settings->Script);
free(Settings);
} 


void THoneyCredDestroy(THoneyCred *Cred)
{
if (! Cred) return;

Destroy(Cred->User);
Destroy(Cred->Pass);
Destroy(Cred->Salt);
free(Cred);
} 


void RunScript(TSettings *Settings, const char *Error, const char *FoundFiles)
{
char *Tempstr=NULL;

if (! StrLen(Settings->Script)) return;

Tempstr=MCopyStr(Tempstr,Settings->Script," '",Error,"' '",FoundFiles,"' '",Settings->PamUser,"' '",Settings->PamHost, "'", NULL);
system(Tempstr);	

Destroy(Tempstr);
}


int ProcessResult(TSettings *Settings, const char *AuthTok, const char *FoundFiles, int Result)
{
int PamResult=PAM_IGNORE;

if (Settings->Flags & FLAG_SYSLOG) 
{

	switch (Result)
	{
	case MATCH_NO:
		if (Settings->Flags & FLAG_LOGPASS) syslog(LOG_NOTICE, "pam_honeycreds: user=[%s] pass=[%s] rhost=[%s]",Settings->PamUser, AuthTok, Settings->PamHost);
	if (Settings->Flags & FLAG_FAILS)
	{
		syslog(LOG_NOTICE, "pam_honeycreds: Attempt to login using wrong password user=[%s] rhost=[%s]", Settings->PamUser, Settings->PamHost);
		RunScript(Settings, "FAIL", "");
	}
	break;

	case MATCH_WRONG_USER:
		//Here we deny or allow a *match*. FLAG_DENYALL Denies everything, even non-matches that might be authenticated by another
		//module
		if (Settings->Flags & FLAG_DENY) PamResult=PAM_PERM_DENIED;
		else PamResult=PAM_IGNORE;

		syslog(LOG_NOTICE, "pam_honeycreds: WRONG USER: Attempt to login using password in [%s]. user=[%s] rhost=[%s]",FoundFiles, Settings->PamUser, Settings->PamHost);
		RunScript(Settings, "WrongUser", FoundFiles);
	break;

	case MATCH_YES:
		//Here we deny or allow a *match*. FLAG_DENYALL Denies everything, even non-matches that might be authenticated by another
		//module
		if (Settings->Flags & FLAG_DENY) PamResult=PAM_PERM_DENIED;
		else PamResult=PAM_IGNORE;


		syslog(LOG_NOTICE, "pam_honeycreds: Attempt to login using password in [%s]. user=[%s] rhost=[%s]",FoundFiles, Settings->PamUser, Settings->PamHost);
		RunScript(Settings, "Match", FoundFiles);
	break;

	case MATCH_VALID:
		//do nothing
	break;
	}

	closelog();
}


return(PamResult);
}



char *HashPassword(char *RetStr, const char *Salt, const char *Password)
{
SHA2_SHA256_CTX ctx;
char *Tempstr=NULL;
char Hex[5];
int i;

SHA2_SHA256_Init(&ctx);
if (StrLen(Salt)) Tempstr=MCopyStr(Tempstr,Salt,Password,NULL);
else Tempstr=CopyStr(Tempstr,Password);

SHA2_SHA256_Update(&ctx, Tempstr, StrLen(Tempstr));

Tempstr=(char *) realloc(Tempstr, SHA2_SHA256_DIGEST_LENGTH + 1);
SHA2_SHA256_Final(Tempstr, &ctx);

for (i=0; i < SHA2_SHA256_DIGEST_LENGTH; i++) 
{
	snprintf(Hex,3,"%02x",Tempstr[i] & 0xFF);
	RetStr=CatStr(RetStr,Hex);
}

Destroy(Tempstr);

return(RetStr);
}



int ConsiderCred(const char *User, const char *Pass, const char *Host, THoneyCred *Cred)
{
char *Hash=NULL;
const char *ptr;
int result=MATCH_NO, val;

	if (! Pass) return(MATCH_NO);
	if (strcasecmp(Pass, Cred->Pass)==0) result=MATCH_YES;
	else
	{ 
		Hash=HashPassword(Hash, Cred->Salt, Pass);
		if (strcasecmp(Hash,Cred->Pass)==0) result=MATCH_YES;
	}
	
	if ((result > MATCH_NO) && StrLen(Cred->User))
	{
		if (ItemMatches(User, Cred->User)) result=MATCH_VALID;
		else result=MATCH_YES;
	}

	Destroy(Hash);
	return(result);
}


int ListFileCheck(const char *FilePath, const char *User, const char *Pass, const char *Host, int *FoundLine)
{
FILE *F;
char *Tempstr=NULL, *Token=NULL;
const char *ptr;
int result=MATCH_NO, val, count=0;
THoneyCred *Cred;

Tempstr=(char *) calloc(1024+1, 1);
F=fopen(FilePath, "r");
if (F)
{
	while (fgets(Tempstr,1024,F))
	{
	StripTrailingWhitespace(Tempstr);
	StripLeadingWhitespace(Tempstr);

	if (! StrLen(Tempstr) || (*Tempstr=='#')) continue;

  //create Cred and destroy/clear it down each time
	Cred=(THoneyCred *) calloc(1,sizeof(THoneyCred));
	//first item is always the password
	ptr=GetTok(Tempstr,' ',&Cred->Pass);
	ptr=GetTok(ptr,' ',&Token);
	while (ptr)
	{
		if (strncasecmp(Token,"user=",5)==0) Cred->User=CopyStr(Cred->User, Token+5);
		if (strncasecmp(Token,"salt=",5)==0) Cred->Salt=CopyStr(Cred->Salt, Token+5);
		ptr=GetTok(ptr,' ',&Token);
	}
	val=ConsiderCred(User, Pass, Host, Cred);
	if (val > MATCH_NO) *FoundLine=count;
	if (val > result) result=val;

	count++;
	THoneyCredDestroy(Cred);
	}
	fclose(F);
}
else syslog(LOG_ERR,"pam_honeycreds: Failed to open %s",FilePath);

Destroy(Token);
Destroy(Tempstr);

return(result);
}



int ListFilesCheck(TSettings *Settings, const char *User, const char *Cred, const char *Host, char **FoundFiles)
{
char *Token=NULL, *Tempstr=NULL;
const char *ptr;
int result=MATCH_NO, val, FoundLine=-1;

ptr=GetTok(Settings->CredsFile,',',&Token);
while (ptr)
{
	val=ListFileCheck(Token, User, Cred, Host, &FoundLine);
	if (val > MATCH_NO)
	{
		Tempstr=realloc(Tempstr,20+1);
		snprintf(Tempstr, 20, "%d",FoundLine);
		*FoundFiles=MCatStr(*FoundFiles,Token,":",Tempstr," ",NULL);
	}
	if (val > result) result=val;
	ptr=GetTok(ptr,',',&Token);
}

Destroy(Tempstr);
Destroy(Token);

return(result);
}



TSettings *ParseSettings(int argc, const char *argv[])
{
TSettings *Settings;
const char *ptr;
int i;

	Settings=(TSettings *) calloc(1,sizeof(TSettings));
	Settings->Prompt=CopyStr(Settings->Prompt,"Password: ");
	for (i=0; i < argc; i++)
	{
		ptr=argv[i];
		if (strcmp(ptr,"syslog")==0) Settings->Flags |= FLAG_SYSLOG;
		else if (strcmp(ptr,"logcreds")==0) Settings->Flags |= FLAG_LOGPASS;
		else if (strcmp(ptr,"deny")==0) Settings->Flags |= FLAG_DENY;
		else if (strcmp(ptr,"fails")==0) Settings->Flags |= FLAG_FAILS;
		else if (strcmp(ptr,"denyall")==0) Settings->Flags |= FLAG_DENYALL;
		else if (strncmp(ptr,"user=",5)==0) Settings->User=MCatStr(Settings->User, ptr+5, ",", NULL);
		else if (strncmp(ptr,"host=",5)==0) Settings->Host=MCatStr(Settings->Host, ptr+5, ",", NULL);
		else if (strncmp(ptr,"!user=",6)==0) 
		{
			Settings->Flags |= FLAG_NOTUSER;
			Settings->User=MCatStr(Settings->User, ptr+6, ",", NULL);
		}
		else if (strncmp(ptr,"!host=",6)==0) 
		{
			Settings->Flags |= FLAG_NOTHOST;
			Settings->Host=MCatStr(Settings->Host, ptr+6, ",", NULL);
		}
		else if (strncmp(ptr,"file=",5)==0) Settings->CredsFile=MCatStr(Settings->CredsFile, ptr+5, ",", NULL);
		else if (strncmp(ptr,"prompt=",7)==0) Settings->Prompt=MCatStr(Settings->Prompt, ptr+7, ":", NULL);
		else if (strncmp(ptr,"script=",7)==0) Settings->Script=MCopyStr(Settings->Script, ptr+7, NULL);
	}

return(Settings);
}




int HostMatches(TSettings *Settings)
{
if (! StrLen(Settings->Host)) return(TRUE);

if (Settings->Flags & FLAG_NOTHOST)
{
	if (! ItemMatches(Settings->PamHost, Settings->Host)) return(TRUE);
}
else
{
	if (ItemMatches(Settings->PamHost, Settings->Host)) return(TRUE);
}

return(FALSE);
}


int UserMatches(TSettings *Settings)
{
if (! StrLen(Settings->User)) return(TRUE);

if (Settings->Flags & FLAG_NOTUSER)
{
	if (! ItemMatches(Settings->PamUser, Settings->User)) return(TRUE);
}
else
{
	if (ItemMatches(Settings->PamUser, Settings->User)) return(TRUE);
}

return(FALSE);
}






// PAM entry point for authentication. This function gets called by pam when
//a login occurs. argc and argv work just like argc and argv for the 'main' 
//function of programs, except they pass in the options defined for this
//module in the pam configuration files in /etc/pam.conf or /etc/pam.d/
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{
	char *Tempstr=NULL, *FoundFiles=NULL;
	const char *ptr;
	int PamResult=PAM_IGNORE, val;
	TSettings *Settings;

	//These are defined as 'const char' because they passwd to us from the parent
	//library. When we called pam_get_<whatever> the pam library passes pointers
	//to strings in it's own code. Thus we must not change or free them
	const char *pam_user = NULL, *pam_service=NULL, *pam_rhost=NULL, *pam_authtok=NULL;


	//get the user. If something goes wrong we return PAM_IGNORE. This tells
	//pam that our module failed in some way, so ignore it. Perhaps we should
	//return PAM_PERM_DENIED to deny login, but this runs the risk of a broken
	//module preventing anyone from logging into the system!

	if (pam_get_item(pamh, PAM_SERVICE, (const void **) &pam_service) != PAM_SUCCESS)
	{
		openlog("pam_honeycreds",0,LOG_AUTH);
		syslog(LOG_ERR,"Failed to get pam_user");
		closelog();
		return(PAM_IGNORE);
	}

	openlog(pam_service,0,LOG_AUTH);

	if ((pam_get_user(pamh, &pam_user, NULL) != PAM_SUCCESS) || (pam_user==NULL))
	{
		syslog(LOG_ERR,"pam_honeycreds: Failed to get pam_user");
		closelog();
		return(PAM_IGNORE);
	}

	if (pam_get_item(pamh, PAM_RHOST, (const void **) &pam_rhost) != PAM_SUCCESS)
	{
		syslog(LOG_ERR,"pam_honeycreds: Failed to get pam_rhost");
		closelog();
		return(PAM_IGNORE);
	}



	//get the cached authentication token (password) or prompt for one if one is not already cached.
	//Final argument is the prompt to use.
	//pam_get_authtok(pamh, PAM_AUTHTOK, &pam_authtok, Settings->Prompt);

	if (pam_get_item(pamh, PAM_AUTHTOK, (const void **) &pam_authtok) != PAM_SUCCESS) 
	{
		syslog(LOG_ERR,"pam_honeycreds: Failed to get pam_authtok");
		closelog();
		return(PAM_IGNORE);
	}


	Settings=ParseSettings(argc, argv);
	Settings->PamUser=CopyStr(Settings->PamUser,pam_user);
	Settings->PamHost=CopyStr(Settings->PamHost,pam_rhost);

	//Host matches checks if we've been explicitly told to ignore this host, or only consider certain hosts
	if (! HostMatches(Settings))
	{
			syslog(LOG_NOTICE, "pam_honeycreds: IGNORE: user=[%s] rhost=[%s]",Settings->PamUser, Settings->PamHost);
			PamResult=PAM_IGNORE;	
	}
	else if (UserMatches(Settings))
	{
		val=ListFilesCheck(Settings, Settings->PamUser, pam_authtok, Settings->PamHost, &FoundFiles);
		PamResult=ProcessResult(Settings, pam_authtok, FoundFiles, val);

		if (Settings->Flags & FLAG_DENYALL)
		{
			syslog(LOG_NOTICE, "pam_honeycreds: DENY: user=[%s] rhost=[%s]",Settings->PamUser, Settings->PamHost);
		 	PamResult=PAM_PERM_DENIED;
			if ((val==MATCH_NO) && StrLen(Settings->Script)) RunScript(Settings, "DENY", "");
		}
	}

	closelog();
	Destroy(Settings);
	Destroy(Tempstr);

  return(PamResult);
}


//We do not provide any of the below functions, we could just leave them out
//but apparently it's considered good practice to supply them and return
//'PAM_IGNORE'

//PAM entry point for starting sessions. This is called after a user has 
//passed all authentication. It allows a PAM module to perform certain tasks
//on login, like recording the login occured, or printing a message of the day
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{
	return(PAM_IGNORE);
}


//PAM entry point for ending sessions. This is called when a user logs out
//It allows a PAM module to perform certain tasks on logout
//like recording the logout occured, or clearing up temporary files
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return(PAM_IGNORE);
}

// PAM entry point for 'account management'. This decides whether a user
// who has already been authenticated by pam_sm_authenticate should be
// allowed to log in (it considers other things than the users password)
// Really this is what we should have used here
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return(PAM_IGNORE);
}


//PAM entry point for setting 'credentials' or properties of the user
//If our module stores or produces extra information about a user (e.g.
//a kerberous ticket or geolocation value) then it will pass this information
//to a PAM aware program in this call
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{
	return(PAM_IGNORE);
}

// PAM entry point for changing passwords. If our module stores passwords
// then this will be called whenever one needs changing
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return(PAM_IGNORE);
}


//I couldn't find any documentation on this. I think it notifies PAM of our
//module name
#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_honeycreds");
#endif
