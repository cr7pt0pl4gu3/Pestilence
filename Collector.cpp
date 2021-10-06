#include "Collector.h"
#include <Windows.h>
#include <sstream>

auto Collector::GetWindowsVersion() const->std::wstring
{
	// Stack wide strings
	constexpr wchar_t wsKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
	constexpr wchar_t wsVersion[] = { 'v', 'e', 'r', 's', 'i', 'o', 'n', '.', 'd', 'l', 'l', 0x0 };

	// Dynamically resolving LoadLibrary function from kernel32.dll
	typedef HMODULE(WINAPI* LoadLibrary_t)(LPCWSTR);

	constexpr unsigned char sLoadLibrary[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0x0 };

	const HMODULE hmKernel32 = GetModuleHandle(wsKernel32);

	LoadLibrary_t LoadLibrary_p;
	if (hmKernel32)
	{
		LoadLibrary_p = 
			reinterpret_cast<LoadLibrary_t>(GetProcAddress(hmKernel32, reinterpret_cast<LPCSTR>(sLoadLibrary)));
	}
	else
	{
		ExitProcess(GetLastError());
	}

	// Dynamically loading version.dll and resolving its functions
	LoadLibrary_p(wsVersion);

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

		// Cleanup (and dynamic resolution of FreeLibrary)
		constexpr unsigned char sFreeLibrary[] = { 'F', 'r', 'e', 'e', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 0x0 };

		typedef BOOL(WINAPI* FreeLibrary_t)(HMODULE);

		FreeLibrary_t FreeLibrary_p;
		if (hmKernel32)
		{
			FreeLibrary_p =
				reinterpret_cast<FreeLibrary_t>(GetProcAddress(hmKernel32, reinterpret_cast<LPCSTR>(sFreeLibrary)));
		}
		else
		{
			ExitProcess(GetLastError());
		}

		FreeLibrary_p(hmVersion);
		::operator delete(buffer);

		return ret;
	}
	else
	{
		ExitProcess(GetLastError());
	}
}

auto Collector::GetNetBIOSName() -> std::wstring
{
	// Setting up our buffers
	WCHAR buffer[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD len = _countof(buffer);

	// Dynamically resolving GetComputerName()
	constexpr wchar_t wsKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };

	const HMODULE hmKernel32 = GetModuleHandle(wsKernel32);

	typedef BOOL(WINAPI* GetComputerName_t)(LPWSTR, LPDWORD);

	constexpr unsigned char sGetComputerName[] = { 'G', 'e', 't', 'C', 'o', 'm', 'p', 'u', 't', 'e', 'r', 'N', 'a', 'm', 'e', 'W', 0x0 };

	if (hmKernel32)
	{
		const auto GetComputerName_p =
			reinterpret_cast<GetComputerName_t>(
				GetProcAddress(hmKernel32, reinterpret_cast<LPCSTR>(sGetComputerName)));

		GetComputerName_p(buffer, &len);
		return std::wstring(buffer);
	}
	else
	{
		ExitProcess(GetLastError());
	}
}

auto Collector::FingerPrintSystem() const -> std::vector<std::wstring>
{
	const std::wstring windowsVersion = GetWindowsVersion();
	const std::wstring netBiosName = GetNetBIOSName();

	std::vector<std::wstring> ret;
	ret.push_back(windowsVersion);
	ret.push_back(netBiosName);
	return ret;
}
