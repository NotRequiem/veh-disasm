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

PVOID __fastcall __decode_pointer(const HMODULE hinstance, const PVOID pointer, const HANDLE hProcess)
{
    static ULONG processCookie = 0;

    if (!processCookie) {
        processCookie = __ntqip(hinstance, hProcess);

        if (!processCookie)
            return 0;
    }

    return (PVOID)(__rol8((ULONGLONG)pointer, processCookie & 0x3F) ^ processCookie);
}

PBYTE __disassemble(PBYTE baseAddress)
{
    PBYTE address = NULL;
    PBYTE current_address = baseAddress;

    // Check for LEA instruction with RIP-relative addressing
    while (current_address < baseAddress + 0x1000) {
        // "lea rdi, [address]" pattern
        if (current_address[0] == 0x48 && current_address[1] == 0x8D &&
            current_address[2] == 0x3D) {  // lea rdi, [rip+offset]
            // Calculate the address
            int offset = *(int*)(current_address + 3);
            address = (PBYTE)__rel32_to_abs(current_address + 7, offset);  // 7 is the instruction size
            break;
        }
        current_address++;
    }

    return address;
}