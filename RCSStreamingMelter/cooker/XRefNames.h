#ifndef xrefnames_h__
#define xrefnames_h__

typedef struct _XREF_NAMES
{
	char *dll;
	char *calls[64];
} XREFNAMES;

#endif /* xrefnames_h__ */