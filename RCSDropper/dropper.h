#ifndef _DROPPER_H
#define _DROPPER_H

#define DROPPERDLL	"DROPPER.DLL"
#define DROPPERFUNC	"_make_host_pe"
#define DROPPERERROR "_get_last_error"

#define ERROR_OUTPUT			-1
#define ERROR_EMBEDDING			-2
#define ERROR_POLYMER			-3
#define ERROR_MANIFEST			-4
#define ERROR_NO_DROPPER		-100
#define ERROR_INVALID_DROPPER	-101

typedef bool (*DropperT)(int, char **);
typedef DWORD(*GetLastErrorT) (void); 

#endif /* _DROPPER_H */
