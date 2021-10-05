#include "Collector.h"
#include <Windows.h>
#include <sstream>

auto Collector::GetWindowsVersion() const->std::wstring
{
	// Stack wide strings
	constexpr wchar_t wsKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
	constexpr wchar_t wsVersion[] = { 'v', 'e', 'r', 's', 'i', 'o', 'n', '.', 'd', 'l', 'l', 0x0 };

	// Dynamically loading version.dll and resolving its functions
	LoadLibrary(wsVersion);

	typedef DWORD(WINAPI *GetFileVersionInfoSize_t)(LPCWSTR, LPDWORD);
	typedef DWORD(WINAPI *GetFileVersionInfo_t)(LPCWSTR, DWORD, DWORD, LPVOID);
	typedef BOOL(WINAPI *VerQueryValue_t)(LPCVOID, LPCWSTR, LPVOID, PUINT);

	constexpr unsigned char sGetFileVersionInfoSize[] = {
		'G', 'e', 't', 'F', 'i', 'l', 'e', 'V', 'e', 'r', 's', 'i', 'o', 'n', 'I', 'n', 'f', 'o', 'S', 'i', 'z', 'e',
		'W', 0x0 };
	constexpr unsigned char sGetFileVersionInfo[] = {
		'G', 'e', 't', 'F', 'i', 'l', 'e', 'V', 'e', 'r', 's', 'i', 'o', 'n', 'I', 'n', 'f', 'o',
		'W', 0x0
	};
	constexpr unsigned char sVerQueryValue[] = {
		'V', 'e', 'r', 'Q', 'u', 'e', 'r', 'y', 'V', 'a', 'l', 'u', 'e',
		'W', 0x0
	};

	const HMODULE hmVersion = GetModuleHandle(wsVersion);

	if (hmVersion)
	{
		const auto GetFileVersionInfoSize_p = 
			reinterpret_cast<GetFileVersionInfoSize_t>(
				GetProcAddress(hmVersion, reinterpret_cast<LPCSTR>(sGetFileVersionInfoSize)));
		const auto GetFileVersionInfo_p = 
			reinterpret_cast<GetFileVersionInfo_t>(
				GetProcAddress(hmVersion, reinterpret_cast<LPCSTR>(sGetFileVersionInfo)));
		const auto VerQueryValue_p = 
			reinterpret_cast<VerQueryValue_t>(
				GetProcAddress(hmVersion, reinterpret_cast<LPCSTR>(sVerQueryValue)));

		// Retrieving version-information resource
		const DWORD buffer_size = GetFileVersionInfoSize_p(static_cast<LPCWSTR>(wsKernel32), nullptr);
		void* buffer = ::operator new(buffer_size);
		GetFileVersionInfo_p(static_cast<LPCWSTR>(wsKernel32), 0, buffer_size, buffer);

		// Querying the resource for windows version & build number
		VS_FIXEDFILEINFO* version = nullptr;
		unsigned int version_len = 0;
		VerQueryValue_p(buffer, L"\\", reinterpret_cast<LPVOID*>(&version), &version_len);

		// Return std::wstring representation of the windows version & build number
		std::wstringstream ss;
		ss << HIWORD(version->dwFileVersionMS)
		<< '.' << LOWORD(version->dwFileVersionMS)
		<< '.' << HIWORD(version->dwFileVersionLS)
		<< '.' << LOWORD(version->dwFileVersionLS);
		std::wstring ret = ss.str();

		// Cleanup
		FreeLibrary(hmVersion);
		::operator delete(buffer);

		return ret;
	}
	else
	{
		ExitProcess(GetLastError());
	}
}
