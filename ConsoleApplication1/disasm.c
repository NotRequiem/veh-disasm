#include "disasm.h"
#include "utils.h"

__inline PVOID __fastcall __rel32_to_abs(void* address, unsigned long long instructionSize) {
    unsigned char* next = (unsigned char*)address + instructionSize;
    return next + (*(unsigned int*)(next - 4));
}

inline unsigned __int64 __fastcall __rol8(unsigned __int64 value, int count)
{
    const unsigned int nbits = sizeof(value) * 8;

    /*
    const unsigned int nbits = sizeof(value) * 8;
    count %= nbits;
    return (value << count) | (value >> (nbits - count));
    */
    if (count > 0) {
        count %= nbits;
        unsigned __int64 high = value >> (nbits - count);
        value = (value << count) | high;
    }
    else {
        count = -count % nbits;
        unsigned __int64 low = value << (nbits - count);
        value = (value >> count) | low;
    }
    return value;
}

PVOID __fastcall __decode_pointer(const HMODULE hinstance, const PVOID pointer)
{
    static ULONG processCookie = 0;

    if (!processCookie) {
        processCookie = __ntqip(hinstance);

        if (!processCookie)
            return 0;
    }

    return (PVOID)(__rol8((ULONGLONG)pointer, processCookie & 0x3F) ^ processCookie);
}

LONG __stdcall __dummy_veh(PEXCEPTION_POINTERS* ExceptionInfo) {
    return 0;
}

PBYTE __disassemble(CONST PBYTE baseAddress) {
    PBYTE address = NULL;
    PBYTE current_address = baseAddress;

    const BYTE pattern[] = {
        0x80, 0x04, 0x2B, 0x9E, 0xFF, 0x7F, 0x00, 0x00,
        0x70, 0x75, 0x2C, 0x9E, 0xFF, 0x7F, 0x00, 0x00
    };
    const size_t pattern_size = sizeof(pattern);

    while (current_address < baseAddress + 0xFFFFF) {
        if (memcmp(current_address, pattern, pattern_size) == 0) {
            address = current_address + pattern_size - 8;
            break;
        }
        current_address++;
    }

    if (address == NULL) {
        const PVOID dummyHandler = AddVectoredExceptionHandler(0, &__dummy_veh);

        if (dummyHandler == NULL) {
            printf("[-] Failed to register a dummy handler");
            return NULL;
        }

        address = ((PLIST_ENTRY)dummyHandler)->Flink;
        RemoveVectoredExceptionHandler(__dummy_veh);
    }

    return address;
}