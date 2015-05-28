#PAM HONEYCREDS

This is a simple PAM (Pluggable Authentication Modules) that watches for certain passwords being used. A list of passwords can be stored either in cleartext or as a list of salted sha256 hashes. It can also log passwords that do not match any list, but will not log passwords that are in a list, instead reporting them by file and line. In addition to logging events, a script can be run.

Uses of this PAM module are:

## 1) 'Honey credentials'. 

Fake passwords are made available where they might be found by intruders. If they are ever used it may indicate a network compromise, and in this event pam_honeycreds can be set up to notify the network administrator. Given that people frequently forget/mistype their passwords, a simple 'failed login' alert will cause a lot of noise, and will eventually be ignored by the sysadmin. An actual match against a list of prohibitted passwords should be a clearer signal. Alternatively one can simply watch for passwords from any of the 'common passwords' lists that are available on the internet, in order to detect bruteforce attempts happening within your network.

## 2) Watching for passwords appearing in brute-force attempts against web-facing servers.   

Anyone with internet-facing ssh, web or SMTP servers has seen bruteforce password-guessing attempts that run through a dictionary of stolen passwords. pam_honeycreds can be used to watch for your own passwords appearing in this list, either indicating that your password databases have been stolen, or that you've picked poor passwords.

## 3) Harvesting of passwords used by bruteforcers.

pam_honeycreds can be setup to log the passwords used by bruteforcers trying to break into your systems.


#BIG FAT WARNING

Firstly, you should be aware that changing your PAM configuration could result in locking yourself out of your own computer systems if you get something wrong or  encounter some kind of weird error. If you forget to supply a key= option in the config, then you will have effectively created a 'deny' rule Thus you should first test this module on the 'su' configuration on a non-essential machine that allows root login on the vitual terminals tty1 tty2 ... ttyN. Thus, if something goes wrong, you'll still be able to log in as root and correct it.

If you are watching for your own passwords turning up in places where they shouldn't, then you should store them as salted sha-256 hashes in a file readable only by root. This file itself is a stealable resource, so passwords should not be stored in the clear. Ideally you should mix your passwords in with decoy passwords that are also salted and hashed. A script 'buildpasswords.sh' is provided to generate these hashes, though it requires the sha256sum utility to be present.


This PAM module is free software under the Gnu Public Licence version 3,  and comes with no express or implied warranties or guarentees of anything. 



# INSTALL

The usual proceedure:

```
./configure
make
make install
```

should work. The 'make install' stage will have to be done as root. This will copy the pam_honeycreds.so file into /lib/security.



# CONFIGURATION

pam_honeycreds.so is configured by adding a line to the appropriate file in /etc/pam.d. So, for example, if we wish to add pam_honeycreds to the 'sshd' service, we would add the following line to /etc/pam.d/sshd
```
auth    required  pam_honeycreds.so user=root file=/etc/10k-common-passwords.txt
```
This specifies that, for user root, we should check for honeycreds in the file /etc/10k-common-passwords.txt, which is a cleartext list of commonly used passwords.

Configuration options are:

**user=[user patterns]**  
Comma separated list of fnmatch (shell-style) patterns that identify users for whom this rule applies. To match all users either leave this out, leave it blank, or explicitly set it to 'user=\*'. A '!' character at the start of the pattern allows inversion, so to match all users but root use: 'user=!root'

**file=[path to creds file]**  
Comma separated list of files in which to check for matching passwords. File format is discussed below.

**syslog**  
Record events via syslog messages

**logcreds**  
If this option appears, then passwords will be logged in syslog messages, *but only if they do not appear in any of the file lists*. If your own passwords appear in the list files (as sha256 salted hashes, of course) they will not be logged. Remember, your log files could be compromised too, so you want to avoid revealing your passwords in them.

**script=[path]**  
Run script in the event of a match. Arguments passed to the script will be 'Event Type', 'Matching File Entry' 'User' 'Host', where 'Event Type' will be 'Match' or 'WrongUser', 'Matching File Entry' will have the form '[file path]:[line in file]', 'Host' will be the host from which the login has been attempted, and 'User' will be the user that is being logged in.

**deny**  
Deny user to continue log in if their password matches one of the file lists. 


**fails**
Log and run 'script' for all passwords that are *not* in any list. This can be used to monitor particular account names for password-guessing activity.

**denyall**  
Deny all logins, whether a match is found or not. This is normally used against a user for whom we want to go through the authentication process, but whom we never wish to allow to log in. Applications like sshd allow us to specify which users can log in, but users not in this list are not properly processed through pam_honeycreds. Thus we configure sshd to allow login by any user, but use the 'denyall' option at the pam_honeycreds level to block certain users from logging in at all. So, if we want to monitor the users root and admin, but we never want to allow those users to log in, we might add this to the /etc/pam.d/sshd file:
```
auth    required  pam_honeycreds.so user=root,admin syslog logcreds denyall file=/etc/honeycreds.lst script=/usr/local/bin/root-login.sh
```
If a denyall rule has a script entry, then the script will be run for any event, even if no match is found within the credentials files. This allows triggering against some users (e.g. root) that should never login via some services (say, ssh).

**prompt=[prompt]** 
: If pam_honeycreds is the first module in the stack to ask for the users password, then this will be the password prompt message that the user sees. The default is 'Password: '. Ideally, instead of using this option,  pam_honeycreds should appear in the pam module list *after* a module like pam_unix.so, so that the normal configured prompting proceedure is followed.


# CREDENTIALS FILE FORMAT

The credentials to watch for are stored in text-files as one credential-per-line in either plaintext or as sha256 hashes. A few options can appear on the same line after the credential. Options are separated with a single space. Options are:

**salt=[salt]**  
A string that is prepended to the credential before hashing. This is intended to complicate the use of 'rainbow tables', which are pregenerated tables of hashes for all popular passwords, as the rainbow table must now be built for all possible random strings that could be prefixed to the password.

**user=[user pattern]**  
An fnmatch pattern that matches usernames *for which this string is actually the password*. This will suppress the creation of an event, or any logging, or running of a script for this user (unless 'denyall' is set, in which case a script will run if it is provided).


# EXAMPLES

## Global config examples


Deny login to root, log passwords in syslog messages and run a script for any attempted login. Don't bother looking for any matching passwords.
```
auth	required  pam_honeycreds.so user=root syslog logcreds denyall script=/usr/local/bin/root-login.sh
```


Do all the above, except match against 3 users (root, admin and mail) and check passwords against /etc/mypasswords.txt (thus don't log those that match)
```
auth	required  pam_honeycreds.so user=root,admin,mail syslog logcreds denyall file=/etc/mypasswords.txt script=/usr/local/bin/root-login.sh
```


Deny login for any user, log all passwords (effectively a honeypot)
```
auth required pam_honeycreds.so syslog logcreds denyall
```


For any user other than root, log passwords, allow login, check for creds in the files /etc/honeycreds.conf and /etc/10k-common-passwords.txt. Run script /usr/local/bin/honeycreds-match.sh upon finding a match
```
auth	required  pam_honeycreds.so user=!root syslog logcreds file=/etc/honeycreds.conf,/etc/10k-common-passwords.txt script=/usr/local/bin/honeycreds-match.sh
```


For user 'admin' monitor against /etc/honeycreds.conf, but never log actual passwords
```
auth	required pam_honeycreds.so user=admin syslog file=/etc/honeycreds.conf
```

## Credentials files examples

_Basic cleartext format:_
```
password
monkey
dragon
letmein
8characters
password\ with\ spaces
password\\with\\slashes
```

_Salted hash format_
```
9ea9803cd51b6b393149daf9f777d089c286a0c610c56979364a41ccf2cbdce1 salt=230400
```

_Salted hash format with specified usernames (users named 'localXXX' where 'XXX' is a number) for whom this password is valid_
```
9ea9803cd51b6b393149daf9f777d089c286a0c610c56979364a41ccf2cbdce1 salt=230400 user=local[0-9][0-9][0-9]
```

# CONFIG FOR SSHD

SSHD must be compiled with the --with-pam configuration option, and the 'UsePAM' option must be set to 'yes' in the sshd_config file. It will only pass passwords for user-accounts that are allowed to log in with ssh, so if you want to monitor accounts that are not allowed to login, you have to set them to be allowed at the ssh level, and then use 'denyall' to block them within the pam_honeycreds configuration. 

