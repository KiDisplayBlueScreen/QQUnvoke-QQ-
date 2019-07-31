#include <iostream>
#include<Windows.h>
#include <TlHelp32.h>
using namespace std;
ULONG QQPID[10] = { 0 };
//BYTE Patch4E80E[10] = { 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };
//BYTE Patch4E313[1] = { 0x90 };
//BYTE Patch4E317[5] = { 0x90,0x90,0x90,0x90,0x90 };
//BYTE Patch4E31E[4] = { 0x90,0x90,0x90,0x90 };

// 51 68 D0 6E 8B 5A 56 FF 50 78


BYTE Patch4DFBC[1] = { 0x90 };
BYTE Patch4DFC0[5] = { 0x90,0x90, 0x90, 0x90, 0x90 };
BYTE Patch4DFC7[4] = { 0x90,0x90, 0x90, 0x90 };
BYTE Patch4E4B7[10] = { 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };

BYTE Patch4E96C[1] = { 0x90 };
BYTE Patch4E970[5] = { 0x90,0x90, 0x90, 0x90, 0x90 };
BYTE Patch4E977[4] = { 0x90,0x90, 0x90, 0x90 };
BYTE Patch4EE67[10] = { 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };

BYTE Patch4EC21[1] = { 0x90 };
BYTE Patch4EC25[5] = { 0x90,0x90, 0x90, 0x90, 0x90 };
BYTE Patch4EC2C[4] = { 0x90,0x90, 0x90, 0x90 };
BYTE Patch4F11C[10] = { 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };//Version 9.1.5


BYTE Patch50CE4[1] = { 0x90 };
BYTE Patch50CE8[5] = { 0x90,0x90, 0x90, 0x90, 0x90 };
BYTE Patch50CEF[4] = { 0x90,0x90, 0x90, 0x90 };
BYTE Patch511DF[10] = { 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };//Version 9.1.6


#define GROUP_PATCH_OFFEST1  0x50CE4
#define GROUP_PATCH_OFFEST2  0x50CE8
#define GROUP_PATCH_OFFEST3  0x50CEF
#define PRIVATE_PATCH_OFFEST  0x511DF

#define GROUP_PATCH_POINT1 (LPVOID)Patch50CE4
#define GROUP_PATCH_POINT2 (LPVOID)Patch50CE8
#define GROUP_PATCH_POINT3 (LPVOID)Patch50CEF
#define PRIVATE_PATCH_POINT (LPVOID)Patch511DF



#define ERROR_REPORT printf("Error : 0x%08X \n", GetLastError());
BOOL ElevateDebugPrivileges()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;
	tkp.PrivilegeCount = 1;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))//取得进程令牌句柄.
		return FALSE;//失败返回0.
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);//获取对其他进程进行调试的特权.
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))//设定打开该特权
	{
		return FALSE;
	}
	return TRUE;
}
DWORD WINAPI GetQQID()
{
	DWORD Id;
	BYTE i = 0;
	LPCWSTR PROCESSNAME = L"QQ.exe";
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W ProcessInfo;
	ProcessInfo.dwSize = sizeof(ProcessInfo);
	BOOL bMore = Process32FirstW(hSnapShot, &ProcessInfo);
	while (bMore)
	{
		if (wcscmp(PROCESSNAME, ProcessInfo.szExeFile) == 0)
		{
			Id = ProcessInfo.th32ProcessID;
			QQPID[i] = Id;
			i++;

		}
		bMore = Process32NextW(hSnapShot, &ProcessInfo);
	}
	CloseHandle(hSnapShot);
	return i;
}
BYTE* GetIMModuleAddr(ULONG QQPid)
{
	LPCWSTR ModName = L"IM.dll";
	DWORD Id = QQPid;
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, Id);
	if (Snapshot == 0 || Id == 0)
	{
		cout << "Invalid Snapshot Handle" << endl;
		return 0;
	}
	MODULEENTRY32W Mod;
	Mod.dwSize = sizeof(Mod);
	BYTE* pbModBase = NULL;
	BOOL bMore = Module32FirstW(Snapshot, &Mod);
	while (bMore)
	{
		if (wcscmp(ModName, Mod.szModule) == 0)
		{
			pbModBase = Mod.modBaseAddr;
			break;
		}
		bMore = Module32NextW(Snapshot, &Mod);
	}
	CloseHandle(Snapshot);
	if (pbModBase != 0)
		return pbModBase;
	else return 0;
}


int main()
{
	ElevateDebugPrivileges();
	DWORD NumberOfQQ = GetQQID();
	printf("Now %d QQ are Runing.\n \n", NumberOfQQ);
	DWORD OldProtect = 0;
	BYTE i = 0;

	while (QQPID[i] != 0)
	{
		PBYTE IMBase = GetIMModuleAddr(QQPID[i]);
		if (IMBase != 0)
		{
			printf("No. %d QQ's IM.dll BaseAddr is 0x%08X \n", i + 1, IMBase);
			
		}
		HANDLE QQHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, QQPID[i]);
		VirtualProtectEx(QQHandle, (LPVOID)(IMBase + 0x1000), 0x324000, PAGE_EXECUTE_READWRITE, &OldProtect);
		WriteProcessMemory(QQHandle, (PVOID)(IMBase + PRIVATE_PATCH_OFFEST), PRIVATE_PATCH_POINT, 10, 0);
		ERROR_REPORT

		WriteProcessMemory(QQHandle, (PVOID)(IMBase + GROUP_PATCH_OFFEST1), GROUP_PATCH_POINT1, 1, 0);
		ERROR_REPORT

		WriteProcessMemory(QQHandle, (PVOID)(IMBase + GROUP_PATCH_OFFEST2), GROUP_PATCH_POINT2, 5, 0);
		ERROR_REPORT

		WriteProcessMemory(QQHandle, (PVOID)(IMBase + GROUP_PATCH_OFFEST3), GROUP_PATCH_POINT3, 4, 0);
		ERROR_REPORT

		VirtualProtectEx(QQHandle, (LPVOID)(IMBase + 0x1000), 0x324000, OldProtect, &OldProtect);
		i++;
	}
	system("pause");
	return 0;
}

