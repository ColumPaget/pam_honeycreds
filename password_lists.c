#include "password_lists.h"
#include "utility.h"
#include "sha2.h"
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>

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




//Probe for binary search by considering one line
int SortedFileProbe(const char *Block, const char *Pass, int PassLen)
{
const char *sptr, *eptr;
int val;

	sptr=Block;

	//find start
	while ((*sptr !='\0') && (*sptr !='\n')) sptr++;
	if (sptr=='\0') return(1);


	if (*sptr=='\n')
	{
		sptr++;
		eptr=sptr;
		while ((*eptr !='\0') && (*eptr !='\n')) eptr++;

		val=strncmp(sptr, Pass, eptr-sptr);
		if ((val==0) && (PassLen > (eptr-sptr))) return(-1);
		return(val);
	}

	return(-1);
}

//Check a block of lines for containing a match
int SortedFileSearch(const char *Block, const char *Pass, int PassLen, int StartPos)
{
const char *sptr, *eptr;

	sptr=Block;

	//unless we are at start of file, we will likely be in the middle of a line
	//so find start of the enxt line
	if (StartPos > 0) while ((*sptr !='\0') && (*sptr !='\n')) sptr++;

	//if we have a blank block return false
	if (sptr=='\0') return(FALSE);

	do
	{
		sptr++;
		eptr=sptr;
		while ((*eptr !='\0') && (*eptr !='\n')) eptr++;

		if (
				((eptr-sptr) == PassLen) &&
				(strncmp(sptr, Pass, eptr-sptr)==0) 
			) return(TRUE);
		sptr=eptr;
	}
	while (*sptr=='\n');

	return(FALSE);
}



int SortedFileCheck(const char *FilePath, const char *Pass)
{
int fd, result, Found=FALSE, PassLen=0;
char *Tempstr=NULL;
const char *sptr, *eptr;
struct stat Stat;
off_t jump, pos;

PassLen=strlen(Pass);
Tempstr=(char *) calloc(BUFSIZ+1, 1);
if ( (stat(FilePath, &Stat) ==0) && (Stat.st_size > 0) )
{
	jump=Stat.st_size / 2;
	pos=jump;
	fd=open(FilePath, O_RDONLY);
	if (fd > -1)
	{
		while (jump > 0)
		{
			if (pos < 0) pos=0;
			lseek(fd, pos, SEEK_SET);
			result=read(fd, Tempstr,BUFSIZ);
			Tempstr[result]='\0';
			jump=jump / 2;

			result=SortedFileProbe(Tempstr, Pass, PassLen);
			if (result==0) 
			{
				Found=TRUE;
				break;
			}
			else if (result < 0) pos += jump;
			else if (result > 0) pos -= jump;
		}

		//haven't found it yet, seek back a bit and do exhaustive search
		if (! Found)
		{
			pos-=BUFSIZ / 2;
			if (pos < 0) pos=0;
			lseek(fd, pos, SEEK_SET);
			result=read(fd, Tempstr,BUFSIZ);
			Tempstr[result]='\0';
			Found=SortedFileSearch(Tempstr, Pass, PassLen, pos);
		}
	close(fd);
	}
	else syslog(LOG_ERR,"pam_honeycreds: Failed to open %s",FilePath);
}
else syslog(LOG_ERR,"pam_honeycreds: Failed to open %s",FilePath);

if (Tempstr) free(Tempstr);

return(Found);
}





int ListFilesCheck(TSettings *Settings, const char *User, const char *Cred, const char *Host, char **FoundFiles)
{
char *Token=NULL, *Tempstr=NULL;
const char *ptr;
int result=MATCH_NO, val, FoundLine=-1;

ptr=GetTok(Settings->CredsFiles,',',&Token);
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

ptr=GetTok(Settings->SortedFiles,',',&Token);
while (ptr)
{
	if (SortedFileCheck(Token, Cred))
	{
		Tempstr=realloc(Tempstr,20 + 1);
		*FoundFiles=MCatStr(*FoundFiles,Token," ",NULL);
		if (result < MATCH_YES) result=MATCH_YES;
	}
	ptr=GetTok(ptr,',',&Token);
}

Destroy(Tempstr);
Destroy(Token);

return(result);
}



