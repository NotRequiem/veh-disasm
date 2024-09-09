#include "utils.h"

ULONG __fastcall __ntqip(const HMODULE ntdll, const HANDLE hProcess) 
{
    NtQueryInformationProcess_t NtQueryInformationProcess =
        (NtQueryInformationProcess_t)GetProcAddress(ntdll, "NtQueryInformationProcess");

    ULONG cookie = 0;
    const ULONG ProcessCookieClass = 36;

    const NTSTATUS success = NtQueryInformationProcess(hProcess,
        (PROCESSINFOCLASS)ProcessCookieClass,
        &cookie,
        sizeof(cookie),
        NULL);

    if (success != 0)
        return 0;

    return cookie;
}

BOOL __get_module(const HANDLE hProcess, PVOID pvPoint, TCHAR* modName) 
{
    DWORD dwRet, dwMods;
    HMODULE* hModule = (HMODULE*)malloc(4096 * sizeof(HMODULE)); // prevents stack overflow for function

    if (hModule == ((void*)0)) {
        printf("Failed to allocate memory for modules\n");
        return 0;
    }

    if (K32EnumProcessModules(hProcess, hModule, 4096 * sizeof(HMODULE), &dwRet) == 0) {
        printf("Failed to enumerate modules\n");
        free(hModule);
        return 0;
    }

    dwMods = dwRet / sizeof(HMODULE);

    for (DWORD modCount = 0; modCount < dwMods; modCount++) {
        TCHAR cModule[MAX_PATH];
        GetModuleBaseName(hProcess, hModule[modCount], cModule, MAX_PATH);

        MODULEINFO modNFO;

        if (K32GetModuleInformation(hProcess, hModule[modCount], &modNFO, sizeof(modNFO)) == 1) {
            DWORD64 dwAddress = (DWORD64)pvPoint;

            if (dwAddress > (DWORD64)modNFO.lpBaseOfDll && dwAddress < ((DWORD64)modNFO.lpBaseOfDll + modNFO.SizeOfImage)) {
                wcscpy_s(modName, MAX_PATH, cModule);
                free(hModule);
                return 1;
            }
        }
    }

    free(hModule);
    return 0;
}