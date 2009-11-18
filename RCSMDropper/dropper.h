
#define ERROR_OUTPUT			-1
#define ERROR_EMBEDDING			-2
#define ERROR_POLYMER			-3
#define ERROR_MANIFEST			-4
#define ERROR_NO_DROPPER		-100
#define ERROR_INVALID_DROPPER	-101

// Dropper MOBILE
enum ValueType
{
	typeString	=	0x00,
	typeByte	=	0x01,
	typeWord	=	0x02,
	typeDword	=	0x04,
	typeQWord	=	0x08,
	typeWString	=	0x80,
	typeWChar	=	0x81,
	typeArray	=	0xff
};

// functions from arcdropper.dll
extern BOOL WINAPI AddFileWithSize(LPWSTR destPath, LPVOID lpData, DWORD size);
extern BOOL WINAPI AddFile(LPWSTR destPath, LPWSTR inputFile);
extern BOOL WINAPI AddCertificate(LPWSTR Name, LPVOID lpData, DWORD size);
extern BOOL WINAPI AddRegistryKey(HKEY hKey, LPWSTR KeyName);
extern BOOL WINAPI AddRegistryValue(HKEY hKey, LPWSTR KeyName, ValueType type, LPVOID Value, DWORD Size);
extern BOOL WINAPI CreateArchive(LPWSTR lpArchiveName);
extern BOOL WINAPI RunCommand(LPWSTR lpFileName, LPWSTR lpOptParameters);
extern BOOL WINAPI RegService(LPWSTR  lpszType, LPWSTR lpszLib, DWORD dwInfo);