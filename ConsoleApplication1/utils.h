#pragma once

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tchar.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

    typedef NTSTATUS(__stdcall* NtQueryInformationProcess_t) (
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
        );

    ULONG __fastcall __ntqip(const HMODULE ntdll);
    BOOL __get_module(const HANDLE hProcess, PVOID pvPoint, TCHAR* modName);

#ifdef __cplusplus
}
#endif