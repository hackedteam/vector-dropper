#include "stdafx.h"
#include "polymer.h"
#include <Windows.h>


BOOL SignCod(TCHAR *wsFile, TCHAR *wsKey)
{
	char				szComm[2048];
	STARTUPINFOA		start_Info;
	PROCESS_INFORMATION proc_Info;
	SECURITY_ATTRIBUTES sSec_attrib;
	DWORD				dwRetCode, dwRet;
	BOOL				bRet = FALSE;
	WCHAR				wsFileCod[MAX_PATH];

	wsprintf(wsFileCod, L"%s.cod", wsFile);

	ZeroMemory(szComm, sizeof(szComm));	
	ZeroMemory(&start_Info,  sizeof(start_Info));
	ZeroMemory(&proc_Info,   sizeof(proc_Info));
	ZeroMemory(&sSec_attrib, sizeof(sSec_attrib));

	sSec_attrib.bInheritHandle = true;
	sSec_attrib.nLength = sizeof(sSec_attrib);

	start_Info.cb = sizeof(start_Info);
	start_Info.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	start_Info.wShowWindow = SW_HIDE;

	sprintf_s(szComm, sizeof(szComm), "\"signcod\" %S %S %S", wsFileCod, wsFile, wsKey);

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

	DeleteFile(wsFileCod);

	return true;
}
