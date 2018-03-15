/*
Copyright (c) 2015 Colum Paget <colums.projects@googlemail.com>
* SPDX-License-Identifier: GPL-3.0
*/

#ifndef PAM_HONEYCREDS_PASSLISTS_H
#define  PAM_HONEYCREDS_PASSLISTS_H

#include "common.h"

int ListFileCheck(const char *FilePath, const char *User, const char *Pass, const char *Host, int *FoundLine);
int ListFilesCheck(TSettings *Settings, const char *User, const char *Cred, const char *Host, char **FoundFiles);
int SortedFileCheck(const char *FilePath, const char *Pass);

#endif
