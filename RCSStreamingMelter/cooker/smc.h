#ifndef smc_h__
#define smc_h__

#define END_OF(x) #x ## "_End"
#define FUNCTION_END_DECL(x) void x ## _End()
#define FUNCTION_END(x) FUNCTION_END_DECL(x) { char * y = END_OF(x); return; }
#define FUNC_SIZE(x) ( (DWORD) END_OF(x) - (DWORD)x )

#endif /* smc_h__ */
