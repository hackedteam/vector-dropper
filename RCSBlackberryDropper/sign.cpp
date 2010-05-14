#include "stdafx.h"
#include <Windows.h>
#include "dropper.h"

/*
 * assumo che nella directory di esecuzione ci siano i seguenti file:
 * $wsFile$.cod
 * $wsFile$.csl
 * signtool.csk
 * signtool.db
 * signtool.set
 * SignatureTool.jar
 *
 * Al termine dell'operazione, se va a buon fine, si trova BBB.cod
 */

const char cod_sign[] = "52424200=RIM Blackberry Apps API\r\n"
						"52525400=RIM Runtime API\r\n"
						"52435200=RIM Crypto API - RIM\r\n";


BOOL SignCod(TCHAR *wsFile, TCHAR *wsKey)
{
	HANDLE              hFile;
	char				szComm[2048];
	STARTUPINFOA		start_Info;
	PROCESS_INFORMATION proc_Info;
	SECURITY_ATTRIBUTES sSec_attrib;
	DWORD				dwRetCode, dwRet;
	BOOL				bRet = FALSE;
	WCHAR				wsFileCsl[MAX_PATH];
	WCHAR				wsFileName[MAX_PATH];
	WCHAR *p;

	// trim the file extension
	wsprintf(wsFileName, L"%s", wsFile);

	if ((p = wcschr(wsFileName, L'.')) != NULL)
		*p = 0;

	wsprintf(wsFileCsl, L"%s.csl", wsFileName);

	if ((hFile = CreateFile(wsFileCsl, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL)) == INVALID_HANDLE_VALUE)
		return FALSE;

	WriteFile(hFile, cod_sign, strlen(cod_sign), &dwRet, NULL);

	CloseHandle(hFile);

	ZeroMemory(szComm, sizeof(szComm));	
	ZeroMemory(&start_Info,  sizeof(start_Info));
	ZeroMemory(&proc_Info,   sizeof(proc_Info));
	ZeroMemory(&sSec_attrib, sizeof(sSec_attrib));

	sSec_attrib.bInheritHandle = true;
	sSec_attrib.nLength = sizeof(sSec_attrib);

	start_Info.cb = sizeof(start_Info);
	start_Info.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	start_Info.wShowWindow = SW_HIDE;

	sprintf_s(szComm, sizeof(szComm), "javaw -jar SignatureTool.jar -p %S -a -c %S", wsKey, wsFile);

	if ((bRet = CreateProcessA(NULL, szComm, 0, 0, true, 0, 0, 0, &start_Info, &proc_Info)) == false) {
		//DeleteFile(wsFileCsl);
		return bRet;
	}

	if( proc_Info.hProcess != INVALID_HANDLE_VALUE ) {
		dwRet = WaitForSingleObject(proc_Info.hProcess, 600000);
		GetExitCodeProcess(proc_Info.hProcess, &dwRetCode);
	}

	if( !bRet || dwRet == WAIT_TIMEOUT || dwRetCode != 0 ) { 
		DWORD ret = GetLastError();
		//DeleteFile(wsFileCsl);
		return false;
	} 

	//DeleteFile(wsFileCsl);

	return true;
}
