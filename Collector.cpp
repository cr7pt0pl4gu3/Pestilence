#include "Collector.h"
#include "Helper.h"
#include <Windows.h>
#include <sstream>

Collector::Collector(const Helper &helper)
{
	this->helper = helper;
}

auto Collector::GetWindowsVersion() ->std::wstring
{
	// Stack wide strings
	constexpr wchar_t wsKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
	constexpr wchar_t wsVersion[] = { 'v', 'e', 'r', 's', 'i', 'o', 'n', '.', 'd', 'l', 'l', 0x0 };

	// Dynamically resolving LoadLibrary function from kernel32.dll
	typedef HMODULE(WINAPI* LoadLibrary_t)(LPCWSTR);
	constexpr unsigned char sLoadLibrary[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0x0 };
	const ResolvedObject<LoadLibrary_t> loadLibrary =
		helper.ResolveFunction(sLoadLibrary, static_cast<LoadLibrary_t>(nullptr));

	// Dynamically loading version.dll and resolving its functions
	loadLibrary.call(wsVersion);

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

	const ResolvedObject<GetFileVersionInfoSize_t> getFileVersionInfoSize =
		helper.ResolveFunction(sGetFileVersionInfoSize, static_cast<GetFileVersionInfoSize_t>(nullptr), wsVersion);
	const ResolvedObject<GetFileVersionInfo_t> getFileVersionInfo =
		helper.ResolveFunction(sGetFileVersionInfo, static_cast<GetFileVersionInfo_t>(nullptr), wsVersion);
	const ResolvedObject<VerQueryValue_t> verQueryValue =
		helper.ResolveFunction(sVerQueryValue, static_cast<VerQueryValue_t>(nullptr), wsVersion);

	// Retrieving version-information resource
	const DWORD buffer_size = getFileVersionInfoSize.call(static_cast<LPCWSTR>(wsKernel32), nullptr);
	void* buffer = ::operator new(buffer_size);
	getFileVersionInfo.call(static_cast<LPCWSTR>(wsKernel32), 0, buffer_size, buffer);

	// Querying the resource for windows version & build number
	VS_FIXEDFILEINFO* version = nullptr;
	unsigned int version_len = 0;
	verQueryValue.call(buffer, L"\\", reinterpret_cast<LPVOID*>(&version), &version_len);

	// Return std::wstring representation of the windows version & build number
	std::wstringstream ss;
	ss << HIWORD(version->dwFileVersionMS)
	<< '.' << LOWORD(version->dwFileVersionMS)
	<< '.' << HIWORD(version->dwFileVersionLS)
	<< '.' << LOWORD(version->dwFileVersionLS);
	std::wstring ret = ss.str();

		
	// Cleanup
	::operator delete(buffer);

	return ret;
}

auto Collector::GetNetBIOSName() -> std::wstring
{
	// Setting up our buffers
	WCHAR buffer[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD len = _countof(buffer);

	// Dynamically resolving GetComputerName()
	constexpr unsigned char sGetComputerName[] = { 'G', 'e', 't', 'C', 'o', 'm', 'p', 'u', 't', 'e', 'r', 'N', 'a', 'm', 'e', 'W', 0x0 };
	typedef BOOL(WINAPI* GetComputerName_t)(LPWSTR, LPDWORD);
	const ResolvedObject<GetComputerName_t> getComputerName =
		helper.ResolveFunction(sGetComputerName, static_cast<GetComputerName_t>(nullptr));
	getComputerName.call(buffer, &len);

	return std::wstring(buffer);
}


auto Collector::FingerPrintSystem() -> std::vector<std::wstring>
{
	const std::wstring windowsVersion = GetWindowsVersion();
	const std::wstring netBiosName = GetNetBIOSName();

	// Dynamically resolving GetSystemInfo()
	SYSTEM_INFO si;

	typedef void(WINAPI* GetSystemInfo_t)(LPSYSTEM_INFO);
	constexpr unsigned char sGetSystemInfo[] = { 'G', 'e', 't', 'S', 'y', 's', 't', 'e', 'm', 'I', 'n', 'f', 'o', 0x0 };
	ResolvedObject<GetSystemInfo_t> getSystemInfo =
		helper.ResolveFunction(sGetSystemInfo, static_cast<GetSystemInfo_t>(nullptr));
	getSystemInfo.call(&si);

	// Getting processor architecture
	std::wstring arch;
	switch (si.wProcessorArchitecture)
	{
	case PROCESSOR_ARCHITECTURE_AMD64:
		arch = { 'x', '6', '4', ' ', '(', 'A', 'M', 'D', ' ', 'o', 'r', ' ', 'I', 'n', 't', 'e', 'l', ')', 0x0 };
		break;
	case PROCESSOR_ARCHITECTURE_ARM:
		arch = { 'A', 'R', 'M', 0x0 };
		break;
	case PROCESSOR_ARCHITECTURE_ARM64:
		arch = { 'A', 'R', 'M', '6', '4', 0x0 };
		break;
	case PROCESSOR_ARCHITECTURE_IA64:
		arch = { 'I', 'n', 't', 'e', 'l', ' ', 'I', 't', 'a', 'n', 'i', 'u', 'm', '-', 'b', 'a', 's', 'e', 'd', 0x0 };
		break;
	case PROCESSOR_ARCHITECTURE_INTEL:
		arch = { 'x', '8', '6', 0x0 };
		break;
	default:
		arch = { 'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'a', 'r', 'c', 'h', 'i', 't', 'e', 'c', 't', 'u', 'r', 'e', 0x0 };
		break;
	}

	// Page size
	std::wstringstream ss;
	ss << si.dwPageSize;
	std::wstring pageSize = ss.str();

	// Number of processors
	ss.str(std::wstring());
	ss << si.dwNumberOfProcessors;
	std::wstring numberOfProcessors = ss.str();

	std::vector<std::wstring> ret;
	ret.push_back(windowsVersion);
	ret.push_back(netBiosName);
	ret.push_back(arch);
	ret.push_back(pageSize);
	ret.push_back(numberOfProcessors);
	return ret;
}
