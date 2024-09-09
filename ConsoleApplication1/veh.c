#include "def.h"

int main() {
    const HMODULE hntdll = GetModuleHandleW(L"ntdll.dll");
    if (hntdll == NULL) {
        printf("Could not get ntdll module handle.\n");
        system("pause");
        return 1;
    }

    /*
    .text:00000001800XXXXX  xor     r8d, r8d
    .text:00000001800XXXXX  jmp     RtlpAddVectoredHandler
    */
    BYTE* RtlpAddVectoredHandler =
        (BYTE*)(GetProcAddress(hntdll, "RtlAddVectoredExceptionHandler")) + 0x3;

    PBYTE pVehListAddress = __disassemble(RtlpAddVectoredHandler);
    if (!pVehListAddress) {
        printf("Could not locate LdrpVectorHandlerList.\n");
        system("pause");
        return 1;
    }

    PLDRP_VECTOR_HANDLER_LIST resolvedVehList = (PLDRP_VECTOR_HANDLER_LIST)pVehListAddress;

#ifdef _DEBUG
    printf("RtlAddVectoredExceptionHandler: 0x%p\n", RtlpAddVectoredHandler - 0x3);
    printf("RtlpAddVectoredHandler: 0x%p\n", RtlpAddVectoredHandler);
    printf("Resolved VEH list (x64 IP relative): 0x%p\n", resolvedVehList);
    AddVectoredExceptionHandler(0, (PVECTORED_EXCEPTION_HANDLER)__veh);
#endif

    LIST_ENTRY* listHead = &resolvedVehList->LdrpVehList;
    BOOL foundHandler = FALSE;
    const HANDLE hProcess = GetCurrentProcess();

    while (1) {
        for (LIST_ENTRY* entry = listHead->Flink; entry != listHead; entry = entry->Flink) {
            PVECTOR_HANDLER_ENTRY pEntry = (PVECTOR_HANDLER_ENTRY)((PCHAR)(entry)-(ULONG_PTR)(&((PVECTOR_HANDLER_ENTRY)0)->ListEntry));
            LPVOID pExceptionHandler = __decode_pointer(hntdll, pEntry->EncodedHandler, hProcess);

            TCHAR modName[MAX_PATH];
            __get_module((HANDLE)-1, pExceptionHandler, modName);

#ifdef UNICODE
            printf("VEH Ptr: 0x%p | Module: %ls | RefCount: %lld | Unk0: %lu | Pad0: %lu\n",
                pExceptionHandler, modName, *pEntry->pRefCount, pEntry->unk_0, pEntry->pad_0);
#else
            printf("VEH Ptr: 0x%p | Module: %s | RefCount: %lld | Unk0: %lu | Pad0: %lu\n",
                pExceptionHandler, modName, *pEntry->pRefCount, pEntry->unk_0, pEntry->pad_0);
#endif
            foundHandler = TRUE;
        }

        if (!foundHandler)
            printf("No VEH handler found in the current process.\n");

        Sleep(1000);
    }

#ifdef _DEBUG
    RemoveVectoredExceptionHandler((PVECTORED_EXCEPTION_HANDLER)__veh);
#endif

    return 0;
}