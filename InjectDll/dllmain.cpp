// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <string>
#include <fstream>

#define CUSTOM_ERROR_CODE 5

using namespace std;

char openProcessCode[12] = { 0 };
char oldOpenProcessCode[12] = { 0 };
char codeA[12] = { 0 };
char oldCodeA[12] = { 0 };
char codeW[12] = { 0 };
char oldCodeW[12] = { 0 };
FARPROC openProcessProc;
FARPROC formatMessageAProc;
FARPROC formatMessageWProc;

string GetSelfLoc()
{
	MEMORY_BASIC_INFORMATION info;
	VirtualQuery(GetSelfLoc, &info, sizeof(info));
	char buffer[1024];
	GetModuleFileName((HMODULE)info.AllocationBase, buffer, sizeof(buffer));
	string filename(buffer);
	return filename.substr(0, filename.find_last_of('\\') + 1);
}

HANDLE WINAPI NewOpenProcess(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwProcessId
)
{
	HANDLE hProcess = NULL;
	DWORD OldSettings, dwPid;
	ifstream ifs;
	ifs.open(GetSelfLoc() + "pid.txt");
	ifs >> dwPid;
	ifs.close();
	if (dwPid != dwProcessId)
	{
		if (VirtualProtectEx(GetCurrentProcess(), openProcessProc, 12, PAGE_EXECUTE_READWRITE, &OldSettings))
		{
			WriteProcessMemory(GetCurrentProcess(), openProcessProc, oldOpenProcessCode, 12, NULL);
			hProcess = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
			char buffer[1024];
			GetProcessImageFileName(hProcess, buffer, sizeof(buffer));
			if (lstrcmpi(buffer + strlen(buffer) - 11, "conhost.exe") == 0)
			{
				CloseHandle(hProcess);
				hProcess = NULL;
				SetLastError(CUSTOM_ERROR_CODE);
			}
			WriteProcessMemory(GetCurrentProcess(), openProcessProc, openProcessCode, 12, NULL);
			VirtualProtectEx(GetCurrentProcess(), openProcessProc, 12, OldSettings, &OldSettings);
		}
	}
	else
	{
		SetLastError(CUSTOM_ERROR_CODE);
	}
	return hProcess;
}

void HookOpenProcess()
{
	HMODULE hModule = LoadLibrary("kernel32.dll");
	if (hModule != NULL)
	{
		openProcessProc = GetProcAddress(hModule, "OpenProcess");
		openProcessCode[0] = 0x48;
		openProcessCode[1] = 0xB8;
		openProcessCode[10] = 0x50;
		openProcessCode[11] = 0xC3;
		void* nopp = NewOpenProcess;
		memcpy(openProcessCode + 2, &nopp, sizeof(void*));
		DWORD OldSettings;
		if (VirtualProtectEx(GetCurrentProcess(), openProcessProc, 12, PAGE_EXECUTE_READWRITE, &OldSettings))
		{
			memcpy(oldOpenProcessCode, openProcessProc, 12);
			WriteProcessMemory(GetCurrentProcess(), openProcessProc, openProcessCode, 12, NULL);
			DWORD buffer;
			VirtualProtectEx(GetCurrentProcess(), openProcessProc, 12, OldSettings, &buffer);
			return;
		}
	}
	MessageBox(NULL, "HOOK FAILED!", "HOOK FAILED!", MB_ICONERROR);
	return;
}

_Success_(return != 0)
DWORD
WINAPI
NewFormatMessageA(
	_In_     DWORD dwFlags,
	_In_opt_ LPCVOID lpSource,
	_In_     DWORD dwMessageId,
	_In_     DWORD dwLanguageId,
	_When_((dwFlags& FORMAT_MESSAGE_ALLOCATE_BUFFER) != 0, _At_((LPSTR*)lpBuffer, _Outptr_result_z_))
	_When_((dwFlags& FORMAT_MESSAGE_ALLOCATE_BUFFER) == 0, _Out_writes_z_(nSize))
	LPSTR lpBuffer,
	_In_     DWORD nSize,
	_In_opt_ va_list* Arguments
)
{
	DWORD retVal = 0;
	DWORD OldSettings;
	if (VirtualProtectEx(GetCurrentProcess(), formatMessageAProc, 12, PAGE_EXECUTE_READWRITE, &OldSettings))
	{
		WriteProcessMemory(GetCurrentProcess(), formatMessageAProc, oldCodeA, 12, NULL);
		retVal = FormatMessageA(dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments);
		if (dwMessageId == CUSTOM_ERROR_CODE)
		{
			if (dwFlags & FORMAT_MESSAGE_ALLOCATE_BUFFER)
			{
				const char text[] = "人家害怕被关啦！不要结束我！QAQ";
				HLOCAL* pointer = (HLOCAL*)lpBuffer;
				LocalFree(*pointer);
				HLOCAL addr = LocalAlloc(LMEM_FIXED, sizeof(text));
				memcpy(addr, text, sizeof(text));
				*pointer = addr;
			}
			else
			{
				const char text[] = "人家害怕被关啦！不要结束我！QAQ";
				memcpy(lpBuffer, text, (nSize >= sizeof(text)) ? sizeof(text) : nSize);
				lpBuffer[nSize - 1] = '\0';
			}
		}
		WriteProcessMemory(GetCurrentProcess(), formatMessageAProc, codeA, 12, NULL);
		VirtualProtectEx(GetCurrentProcess(), formatMessageAProc, 12, OldSettings, &OldSettings);
	}
	return retVal;
}

_Success_(return != 0)
DWORD
WINAPI
NewFormatMessageW(
	_In_     DWORD dwFlags,
	_In_opt_ LPCVOID lpSource,
	_In_     DWORD dwMessageId,
	_In_     DWORD dwLanguageId,
	_When_((dwFlags& FORMAT_MESSAGE_ALLOCATE_BUFFER) != 0, _At_((LPWSTR*)lpBuffer, _Outptr_result_z_))
	_When_((dwFlags& FORMAT_MESSAGE_ALLOCATE_BUFFER) == 0, _Out_writes_z_(nSize))
	LPWSTR lpBuffer,
	_In_     DWORD nSize,
	_In_opt_ va_list* Arguments
)
{
	DWORD retVal = 0;
	DWORD OldSettings;
	if (VirtualProtectEx(GetCurrentProcess(), formatMessageWProc, 12, PAGE_EXECUTE_READWRITE, &OldSettings))
	{
		WriteProcessMemory(GetCurrentProcess(), formatMessageWProc, oldCodeW, 12, NULL);
		retVal = FormatMessageW(dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments);
		if (dwMessageId == CUSTOM_ERROR_CODE)
		{
			if (dwFlags & FORMAT_MESSAGE_ALLOCATE_BUFFER)
			{
				const WCHAR text[] = L"人家害怕被关啦！不要结束我！QAQ";
				HLOCAL* pointer = (HLOCAL*)lpBuffer;
				LocalFree(*pointer);
				HLOCAL addr = LocalAlloc(LMEM_FIXED, sizeof(text));
				memcpy(addr, text, sizeof(text));
				*pointer = addr;
			}
			else
			{
				const WCHAR text[] = L"人家害怕被关啦！不要结束我！QAQ";
				memcpy(lpBuffer, text, (nSize >= sizeof(text)) ? sizeof(text) : nSize);
				lpBuffer[nSize - 1] = '\0';
			}
		}
		WriteProcessMemory(GetCurrentProcess(), formatMessageWProc, codeW, 12, NULL);
		VirtualProtectEx(GetCurrentProcess(), formatMessageWProc, 12, OldSettings, &OldSettings);
	}
	return retVal;
}

void HookFormatMessage()
{
	formatMessageAProc = (FARPROC)FormatMessageA;
	formatMessageWProc = (FARPROC)FormatMessageW;
	codeW[0] = codeA[0] = 0x48;
	codeW[0] = codeA[1] = 0xB8;
	codeW[0] = codeA[10] = 0x50;
	codeW[0] = codeA[11] = 0xC3;
	void* nfma = NewFormatMessageA;
	void* nfmw = NewFormatMessageW;
	memcpy(codeA + 2, &nfma, sizeof(void*));
	memcpy(codeW + 2, &nfmw, sizeof(void*));
	DWORD OldSettingsA, OldSettingsW;
	if (VirtualProtectEx(GetCurrentProcess(), formatMessageAProc, 12, PAGE_EXECUTE_READWRITE, &OldSettingsA)
		&& VirtualProtectEx(GetCurrentProcess(), formatMessageWProc, 12, PAGE_EXECUTE_READWRITE, &OldSettingsW))
	{
		memcpy(oldCodeA, formatMessageAProc, 12);
		memcpy(oldCodeW, formatMessageWProc, 12);
		WriteProcessMemory(GetCurrentProcess(), formatMessageAProc, codeA, 12, NULL);
		WriteProcessMemory(GetCurrentProcess(), formatMessageWProc, codeW, 12, NULL);
		VirtualProtectEx(GetCurrentProcess(), formatMessageAProc, 12, OldSettingsA, &OldSettingsA);
		VirtualProtectEx(GetCurrentProcess(), formatMessageWProc, 12, OldSettingsW, &OldSettingsW);
		return;
	}
	MessageBox(NULL, "HOOK FAILED!", "HOOK FAILED!", MB_ICONERROR);
	return;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		srand((unsigned int)time(NULL));
		HookOpenProcess();
		HookFormatMessage();
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

