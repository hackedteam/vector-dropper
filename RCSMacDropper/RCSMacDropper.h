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