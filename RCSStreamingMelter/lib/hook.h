/* 
 * File:   hook.h
 * Author: daniele
 *
 * Created on January 4, 2011, 2:47 PM
 */

#ifndef HOOK_H
#define	HOOK_H

#include <beaengine/BeaEngine.h>

typedef struct {
    DISASM d;
    std::size_t len;
} disassembled_instruction;

enum {
    STAGE1_STUB_SIZE = 5,	// call near, 32bit address
};

#endif	/* HOOK_H */

