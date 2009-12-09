#ifndef _XREF_NAMES_H
#define _XREF_NAMES_H

typedef struct _XREF_NAMES
{
	char *dll;
	char *calls[64];
} XREFNAMES;

#endif /* _XREF_NAMES_H */