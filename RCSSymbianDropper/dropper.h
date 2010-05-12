
#define ERROR_OUTPUT			-1
#define ERROR_EMBEDDING			-2
#define ERROR_POLYMER			-3
#define ERROR_MANIFEST			-4
#define ERROR_NO_DROPPER		-100
#define ERROR_INVALID_DROPPER	-101


#define SIS_UNINST	0
#define SIS_CORE	1


extern BOOL SignSis(TCHAR *wsFile, TCHAR *wsCert, TCHAR *wsKey);
extern BOOL CreateSis(UINT flag, TCHAR *wsFile);