#ifndef __debug_h
#define __debug_h

#define D_EXCESSIVE 5
#define D_VERBOSE   4
#define D_DEBUG     3
#define D_INFO      2
#define D_WARNING   1
#define D_ERROR     0

#define DEBUG_MSG(l, x, ...) debug_fn()(l, x, ## __VA_ARGS__ )

#endif /* __debug_h */
