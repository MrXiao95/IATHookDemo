// IATHookTest.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <string>
#include <TlHelp32.h>
#pragma comment(lib,"Advapi32.lib")
using namespace std;

bool EnableDebugPriv(WCHAR * name)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return false;
	if (!LookupPrivilegeValue(NULL, name, &luid))
		return false;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = luid;
	if (!AdjustTokenPrivileges(hToken,0,&tp,sizeof(TOKEN_PRIVILEGES),NULL,NULL))
		return false;
	return true;
}
bool InjectDll(char * DllFullPath, DWORD dwRemoteProcessID)
{
	bool res = false;
	HANDLE hRemoteProcess;
	if (!EnableDebugPriv(SE_DEBUG_NAME))
	{
		printf("提升进程权限失败");
		return res;
	}
	if ((hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwRemoteProcessID))==NULL)
	{
		printf("打开目标进程失败");
		return res;
	}
	char * pszLibFileRemote;
	pszLibFileRemote = (char *)VirtualAllocEx(hRemoteProcess, NULL, strlen(DllFullPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (pszLibFileRemote == NULL)
	{
		printf("目标进程内申请内存失败");
		return res;
	}
	DWORD dwWritten;
	if (WriteProcessMemory(hRemoteProcess,pszLibFileRemote,(void *)DllFullPath,strlen(DllFullPath)+1,&dwWritten)==0)
	{
		printf("目标进程内改写内存失败");
		VirtualFreeEx(hRemoteProcess, pszLibFileRemote, strlen(DllFullPath) + 1, MEM_COMMIT);
		CloseHandle(hRemoteProcess);
		return res;
	}
	else
	{
		if (dwWritten != strlen(DllFullPath) + 1)
		{
			printf("目标进程内改写内存失败");
			VirtualFreeEx(hRemoteProcess, pszLibFileRemote, strlen(DllFullPath) + 1, MEM_COMMIT);
			CloseHandle(hRemoteProcess);
			return res;
		}
		else
			printf("写入目标进程成功");
	}

	LPVOID pFunc = LoadLibraryA;
	DWORD dwID;
	HANDLE hThread = CreateRemoteThread(hRemoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFunc, pszLibFileRemote, 0, &dwID);
	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(hRemoteProcess, pszLibFileRemote, strlen(DllFullPath) + 1, MEM_COMMIT);
	CloseHandle(hThread);
	CloseHandle(hRemoteProcess);
	printf("DLL加载到了目标进程");
	return res;
}
//通过一个进程名字获取进程ID
DWORD GetProcessID(WCHAR * wszProcessName)
{
	DWORD res = 0;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("创建进程快照失败");
		return res;
	}
	bool bProcess = Process32First(hProcessSnap, &pe32);
	while (bProcess)
	{
		wstring sName = pe32.szExeFile;
		if (-1 != sName.find(wszProcessName))
		{
			res = pe32.th32ProcessID;
			CloseHandle(hProcessSnap);
			return res;
		}
		bProcess = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
	return res;
}
int _tmain(int argc, _TCHAR* argv[])
{
	DWORD Pid = GetProcessID(L"EXCEL.EXE");
	if (Pid == 0)
	{
		printf("未能查找到目标进程");
		return -1;
	}
	char DllPath[256];
	GetCurrentDirectoryA(sizeof(DllPath), DllPath);
	strcat_s(DllPath, sizeof(DllPath), "\\IATHookDll.dll");
	InjectDll(DllPath, Pid);
	printf("Done");
	return 0;
}

