HANDLE hPEFile;
HANDLE hMappedFile;

void UnloadPE(BYTE * FileBase)
{

		if(FileBase != NULL)
			UnmapViewOfFile((LPCVOID)FileBase);

		if(hMappedFile != INVALID_HANDLE_VALUE)
			CloseHandle(hMappedFile);

		if(hPEFile != INVALID_HANDLE_VALUE)
			CloseHandle(hPEFile);

}


LPVOID LoadPE(WCHAR *FileName, unsigned int * len)
{

	if (FileName == NULL) {
		return NULL;
	}

	hPEFile = CreateFile(FileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if(hPEFile == INVALID_HANDLE_VALUE)
		return NULL;

	*len = (unsigned int) GetFileSize(hPEFile, NULL);

	 hMappedFile = CreateFileMapping( hPEFile, NULL, PAGE_READWRITE, NULL, *len, NULL);
	if( hMappedFile == INVALID_HANDLE_VALUE )
	{
		CloseHandle(hPEFile);
		return NULL;
	}

	LPVOID FileBase = MapViewOfFile(hMappedFile, FILE_MAP_READ | FILE_MAP_WRITE, NULL, NULL, 0);
	if( FileBase == NULL)
	{
		CloseHandle(hPEFile);
		CloseHandle(hMappedFile);
		return NULL;
	}

	return FileBase;
}



