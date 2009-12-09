#ifndef _SMC_H
#define _SMC_H

#define ENDIFY(x) #x ## "_End"
#define FUNCTION_END_DECL(x) void x ## _End()
#define FUNCTION_END(x) FUNCTION_END_DECL(x) { char * y = ENDIFY(x); return; }

#endif /* _SMC_H */