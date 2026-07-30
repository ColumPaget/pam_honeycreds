/*
Copyright (c) 2015 Colum Paget <colums.projects@googlemail.com>
* SPDX-License-Identifier: GPL-3.0
*/


#ifndef USBAUTH_COMMON_H
#define USBAUTH_COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>

#define VERSION "2.0"
#define FALSE 0
#define TRUE 1

#define MATCH_NO 0              //no match found in password lists
#define MATCH_YES 3             //match found, but user does not exist
#define MATCH_VALID 4           //match found for existing user

#define FLAG_SYSLOG  1
#define FLAG_DENY 4
#define FLAG_DENYALL 8
#define FLAG_LOGPASS 16
#define FLAG_FAILS 32
#define FLAG_NOTUSER 64
#define FLAG_NOTHOST 128
#define FLAG_IGNORE_BLANK 256
#define FLAG_LOGFOUND 512

typedef struct
{
int Flags;
char *Prompt;
char *CredsFiles;
char *SortedFiles;
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

#endif
