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
extern void secondStageDropper ();
extern void dropperEnd ();