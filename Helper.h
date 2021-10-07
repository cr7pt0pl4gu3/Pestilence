#pragma once
#include "ResolvedObject.h"

class Helper
{
public:
	Helper() = default;

	template<typename T>
	ResolvedObject<T> ResolveFunction(const unsigned char* function, T functionType, const wchar_t* dll = nullptr);
};

template<typename T>
ResolvedObject<T> Helper::ResolveFunction(const unsigned char* function, T functionType, const wchar_t* dll)
{
	// Handling nullptr default case, in which we look for kernel32.dll function
	if (dll == nullptr)
	{
		constexpr wchar_t wsKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
		dll = wsKernel32;
	}

	if (const HMODULE hmModule = GetModuleHandle(dll))
	{
		// Resolving function address
		T functionPointer = reinterpret_cast<T>(GetProcAddress(hmModule, reinterpret_cast<LPCSTR>(function)));
		
		return ResolvedObject(functionPointer, hmModule);
	}
	ExitProcess(GetLastError());
}