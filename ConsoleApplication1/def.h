#pragma once

#include "utils.h"
#include "disasm.h"

typedef struct _LDRP_VECTOR_HANDLER_LIST {
    PSRWLOCK   LdrpVehLock;
    LIST_ENTRY LdrpVehList;
    PSRWLOCK   LdrpVchLock;
    LIST_ENTRY LdrpVchList;
} LDRP_VECTOR_HANDLER_LIST, * PLDRP_VECTOR_HANDLER_LIST;

typedef struct _VECTOR_HANDLER_ENTRY {
    LIST_ENTRY ListEntry;
    PLONG64    pRefCount;
    DWORD      unk_0;
    DWORD      pad_0;
    PVOID      EncodedHandler;
} VECTOR_HANDLER_ENTRY, * PVECTOR_HANDLER_ENTRY;

#ifdef _DEBUG
LONG __stdcall __veh(PEXCEPTION_POINTERS* ExceptionInfo) {
    return 0;
}
#endif