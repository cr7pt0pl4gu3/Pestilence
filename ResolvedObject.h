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

// Freeing the .dll (currently disabled because of bugprone FreeLibrary)
template<typename T>
ResolvedObject<T>::~ResolvedObject()
{
	try
	{
		// constexpr wchar_t wsKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
		// constexpr unsigned char sFreeLibrary[] = { 'F', 'r', 'e', 'e', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 0x0 };

		// typedef BOOL(WINAPI* FreeLibrary_t)(HMODULE);

		// if (const HMODULE hmKernel32 = GetModuleHandle(wsKernel32))
		// {
			// const auto FreeLibrary_p =
			// 	reinterpret_cast<FreeLibrary_t>(
			//		GetProcAddress(hmKernel32, reinterpret_cast<LPCSTR>(sFreeLibrary)));
			// Yes, we could free library for stealth, but it is very bugprone so do it at your own risk:
			// std::wcout << L"You can be ultra fucked here:\n";
			// FreeLibrary_p(this->moduleHandle);
		// }
		// else
		// {
		// 	ExitProcess(GetLastError());
		// }
	}
	catch (...)
	{
		ExitProcess(GetLastError());
	}
}





