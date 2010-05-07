#include "stdafx.h"
#include "polymer.h"
#include <Windows.h>

const char pkg_uninstall[] = "#{\"%S\"},(0x2002EF81),1,0,0\r\n"
							 "%%{\"Vendor-EN\"}\r\n"
							 ":\"Vendor\"\r\n"
							 "\"%S.exe\" - \"C:\\sys\\bin\\%S.exe\"\r\n";


const char pkg_core[] = "#{\"%s\"},(0x2002EF81),1,0,0\r\n"
						"%%{\"Vendor-EN\"}\r\n"
						":\"Vendor\"\r\n"
						"\"%s.exe\" - \"C:\\sys\\bin\\%s.exe\"\r\n"
						"\"uninstaller.SISX\" - \"C:\\sys\\bin\\uninstaller.SISX\"\r\n";

BOOL SignSis(TCHAR *wsFile, TCHAR *wsCert, TCHAR *wsKey)
{
	char				szComm[2048];
	STARTUPINFOA		start_Info;
	PROCESS_INFORMATION proc_Info;
	SECURITY_ATTRIBUTES sSec_attrib;
	DWORD				dwRetCode, dwRet;
	BOOL				bRet = FALSE;
	WCHAR				wsFileSis[MAX_PATH];

	wsprintf(wsFileSis, L"%s.SIS", wsFile);

	ZeroMemory(szComm, sizeof(szComm));	
	ZeroMemory(&start_Info,  sizeof(start_Info));
	ZeroMemory(&proc_Info,   sizeof(proc_Info));
	ZeroMemory(&sSec_attrib, sizeof(sSec_attrib));

	sSec_attrib.bInheritHandle = true;
	sSec_attrib.nLength = sizeof(sSec_attrib);

	start_Info.cb = sizeof(start_Info);
	start_Info.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	start_Info.wShowWindow = SW_HIDE;

	sprintf_s(szComm, sizeof(szComm), "\"signsis.exe\" %S %S.SISX %S %S", wsFileSis, wsFile, wsCert, wsKey);

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

	wsprintf(wsFilePkg, L"uninstaller.pkg", wsFile);

	if ((hFile = CreateFile(wsFilePkg, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL)) == INVALID_HANDLE_VALUE)
		return FALSE;

	ZeroMemory(buff, sizeof(buff));

	switch(flag){
		case SIS_UNINST:
			sprintf_s(buff, sizeof(buff), pkg_uninstall, wsFile, wsFile, wsFile);
			break;
		case SIS_CORE:
			sprintf_s(buff, sizeof(buff), pkg_core, wsFile, wsFile, wsFile);
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


BOOL Compress(TCHAR *wsFile, BOOL flags)
{
	char				szComm[2048];
	STARTUPINFOA		start_Info;
	PROCESS_INFORMATION proc_Info;
	SECURITY_ATTRIBUTES sSec_attrib;
	DWORD				dwRetCode, dwRet;
	BOOL				bRet = FALSE;
	WCHAR FileNameExe[MAX_PATH];

	if (wsFile == NULL)
		return FALSE;

	wsprintf(FileNameExe, L"%s.exe", wsFile);

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
		sprintf_s(szComm, sizeof(szComm), "\"petran.exe\" -compress %S", FileNameExe);
	else
		sprintf_s(szComm, sizeof(szComm), "\"petran.exe\" -nocompress %S", FileNameExe);

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
