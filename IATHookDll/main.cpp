#include <windows.h>
#include <tchar.h>
#include <winsock.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

using namespace std;
HANDLE g_hModuleHandle;
HMODULE hModuleInject = NULL;
HANDLE hInjectThread = NULL;
IMAGE_DOS_HEADER* pDosHeader = NULL;
IMAGE_OPTIONAL_HEADER* pOpNtHeader = NULL; //这里加24  
IMAGE_IMPORT_DESCRIPTOR* pImportDesc = NULL;

HANDLE hInfoFile = INVALID_HANDLE_VALUE;

int WINAPI MyMsgBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	MessageBoxW(hWnd, lpText, L"拦截的消息", uType);
	return IDYES;
}

VOID WINAPI MyPostQuitMessage(_In_ int nExitCode)
{
	MessageBoxW(NULL, L"Fuck", L"拦截的消息", MB_OK);
	PostQuitMessage(nExitCode);
}

DWORD GetProcessAddrss(char * libname, char * funname)
{
	HMODULE htmp = LoadLibraryA(libname);
	DWORD hret = 0;
	if (htmp != NULL)
	{
		hret = (DWORD)GetProcAddress(htmp, funname);
	}
	return hret;
}

DWORD WINAPI injectThread(LPARAM lparam)
{

	char modulefilename[MAX_PATH];

	GetModuleFileNameA(NULL, modulefilename, MAX_PATH);
	MessageBoxA(NULL, modulefilename, "DLL已进入目标进程", MB_OK);

	hModuleInject = ::GetModuleHandleA(NULL);
	pDosHeader = (IMAGE_DOS_HEADER*)hModuleInject;
	pOpNtHeader = (IMAGE_OPTIONAL_HEADER*)((BYTE*)hModuleInject + pDosHeader->e_lfanew + 24); //这里加24  
	pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hModuleInject + pOpNtHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	while (pImportDesc->FirstThunk)
	{
		TCHAR* pszDllName = (TCHAR*)((BYTE*)hModuleInject + pImportDesc->Name);
		//printf("模块名称:%s\n", pszDllName);  

		DWORD n = 0;

		IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)((BYTE*)hModuleInject + pImportDesc->OriginalFirstThunk);

		while (pThunk->u1.Function)
		{
			//取得函数地址  
			PDWORD lpAddr = (DWORD*)((BYTE*)hModuleInject + pImportDesc->FirstThunk) + n; //从第一个函数的地址  

			LPDWORD lpd = (LPDWORD)pThunk;

			DWORD oldp;
			VirtualProtect((LPVOID)lpAddr, 8, PAGE_EXECUTE_READWRITE, &oldp);
			//if(strcmp(pszFuncName,"MessageBoxW")==0)
			if (*lpAddr == (unsigned long)MessageBoxW)
			{
				MessageBox(NULL,L"已监控目标进程中 MessageBoxW 函数", pszDllName, MB_ICONINFORMATION);
				*(lpAddr) = (unsigned long)MyMsgBoxW;
			}
			if (*lpAddr == (unsigned long)PostQuitMessage)
			{
				MessageBox(NULL,L"已监控目标进程中 PostQuitMessage 函数", pszDllName, MB_ICONINFORMATION);
				*(lpAddr) = (unsigned long)MyPostQuitMessage;
			}
			if (*lpAddr == (unsigned long)GetSubMenu)
			{
				MessageBox(NULL,L"已监控目标进程中 GetSubMenu 函数", pszDllName, MB_ICONINFORMATION);
				*(lpAddr) = (unsigned long)MyPostQuitMessage;
			}
			VirtualProtect((LPVOID)lpAddr, 8, oldp, &oldp);

			n++; //每次增加一个DWORD  
			pThunk++;
		}
		pImportDesc++;
	}
	return 0;
}
BOOL APIENTRY DllMain(HMODULE hSelfModule,
					  DWORD  ul_reason_for_call,
					  LPVOID lpReserved
					  )
{
	g_hModuleHandle = (HMODULE)hSelfModule;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls((HMODULE)hSelfModule);
		hInjectThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)injectThread, 0, 0, 0);
		CloseHandle(hInjectThread);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:

		CloseHandle(hInfoFile);

		MessageBox(NULL, L"目标进程已经退出", L"Information", MB_ICONINFORMATION);
		break;
	}
	return TRUE;
}