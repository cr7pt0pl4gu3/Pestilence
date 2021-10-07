#pragma once
#include "Windows.h"

template<typename T>
class ResolvedObject
{
public:
	T call;
	HMODULE moduleHandle = nullptr;

	ResolvedObject<T>(T call, HMODULE moduleHandle);
	~ResolvedObject();
};

template<typename T>
ResolvedObject<T>::ResolvedObject(T call, const HMODULE moduleHandle)
{
	this->call = call;
	this->moduleHandle = moduleHandle;
}

// Freeing the .dll
template<typename T>
ResolvedObject<T>::~ResolvedObject()
{
	try
	{
		constexpr wchar_t wsKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
		constexpr unsigned char sFreeLibrary[] = { 'F', 'r', 'e', 'e', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 0x0 };

		typedef BOOL(WINAPI* FreeLibrary_t)(HMODULE);

		if (const HMODULE hmKernel32 = GetModuleHandle(wsKernel32))
		{
			const auto FreeLibrary_p =
				reinterpret_cast<FreeLibrary_t>(
					GetProcAddress(hmKernel32, reinterpret_cast<LPCSTR>(sFreeLibrary)));
			FreeLibrary_p(this->moduleHandle);
		}
		else
		{
			ExitProcess(GetLastError());
		}
	}
	catch (...)
	{
		ExitProcess(GetLastError());
	}
}





