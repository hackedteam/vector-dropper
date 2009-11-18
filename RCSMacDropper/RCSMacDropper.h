#ifdef WIN32
#pragma once
#include <Windows.h>
#endif
//
// Type of strings
//
#define STRING_SYMBOL 0x0001
#define STRING_DATA   0x0002

typedef unsigned long vm_offset_t;
typedef unsigned long vm_size_t;
typedef int cpu_type_t;
typedef int cpu_subtype_t;
typedef int kern_return_t;
typedef int vm_prot_t;

//typedef long long       off_t;
//typedef unsigned long   size_t;

typedef unsigned char   uint8_t;
typedef unsigned short  uint16_t;
typedef unsigned int    uint32_t;

typedef signed char     int8_t;
typedef short           int16_t;
typedef int             int32_t;

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
  uint32_t type;
  char name[32];
  char path[32];
  uint32_t size;
} resourceHeader;
