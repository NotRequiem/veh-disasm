#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

	__inline PVOID __fastcall __rel32_to_abs(void* address, unsigned long long instructionSize);
	inline unsigned __int64 __fastcall __rol8(unsigned __int64 value, int count);
	PVOID __fastcall __decode_pointer(const HMODULE hinstance, const PVOID pointer);
	PBYTE __fastcall __disassemble(const PBYTE baseAddress);

#ifdef __cplusplus
}
#endif
