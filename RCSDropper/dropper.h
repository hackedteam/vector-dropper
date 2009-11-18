

#define DROPPERDLL L"DROPPER.DLL"
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


typedef struct _melter_struct {
	CHAR core[MAX_PATH];
	CHAR conf[MAX_PATH];
	CHAR driver[MAX_PATH];
	CHAR codec[MAX_PATH];
	CHAR instdir[MAX_PATH];
	BOOL manifest;
} MelterStruct, *pMelterStruct;