#pragma once
#include <iostream>
#include <random>
#include "ResolvedObject.h"

class Helper
{
private:
	bool isPrivateNameSpaceOpen = false;
public:
	Helper() = default;

	PSID pSid = nullptr;
	HANDLE pNameSpace = nullptr;
	std::wstring pNameSpaceName;

	[[nodiscard]] bool IsPrivateNameSpaceOpen() const;
	void CreateNewPrivateNameSpace();

	static auto GenerateRandomWideString(int mLength = 8) -> std::wstring;

	template<typename T>
	ResolvedObject<T> ResolveFunction(const unsigned char* function, T functionType, const wchar_t* dll = nullptr);
};

// Checking if we already opened private namespace
inline bool Helper::IsPrivateNameSpaceOpen() const
{
	return isPrivateNameSpaceOpen;
}

// Creating new private namespace for security reasons
inline void Helper::CreateNewPrivateNameSpace()
{
	// Creating new boundary descriptor (with random name ofc)
	constexpr unsigned char sCreateBoundaryDescriptor[] = { 'C', 'r', 'e', 'a', 't', 'e', 'B', 'o', 'u', 'n', 'd', 'a', 'r', 'y', 'D', 'e', 's', 'c', 'r', 'i', 'p', 't', 'o', 'r', 'W', 0x0 };
	typedef HANDLE(WINAPI* CreateBoundaryDescriptor_t)(LPCWSTR, ULONG);
	const ResolvedObject<CreateBoundaryDescriptor_t> createBoundaryDescriptor =
		ResolveFunction(sCreateBoundaryDescriptor, static_cast<CreateBoundaryDescriptor_t>(nullptr));

	HANDLE bDescriptor = createBoundaryDescriptor.call(GenerateRandomWideString().c_str(), 0);

	// Allocating and initializing SID, adding integrity label to our boundary descriptor
	SID_IDENTIFIER_AUTHORITY sidAuth{ SECURITY_CREATOR_SID_AUTHORITY };

	constexpr wchar_t wsAdvapi32[] = { 'A', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l', 0x0 };
	constexpr unsigned char sAllocateAndInitializeSid[] = { 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'A', 'n', 'd', 'I', 'n', 'i', 't', 'i', 'a', 'l', 'i', 'z', 'e', 'S', 'i', 'd', 0x0 };
	typedef BOOL(WINAPI* AllocateAndInitializeSid_t)(PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PSID);
	const ResolvedObject<AllocateAndInitializeSid_t> allocateAndInitializeSid =
		ResolveFunction(sAllocateAndInitializeSid, static_cast<AllocateAndInitializeSid_t>(nullptr), wsAdvapi32);

	allocateAndInitializeSid.call(&sidAuth, 1, SECURITY_MANDATORY_PROTECTED_PROCESS_RID, 0, 0, 0, 0, 0, 0, 0, &pSid);

	constexpr unsigned char sAddIntegrityLabelToBoundaryDescriptor[] = { 'A', 'd', 'd', 'I', 'n', 't', 'e', 'g', 'r', 'i', 't', 'y', 'L', 'a', 'b', 'e', 'l', 'T', 'o', 'B', 'o', 'u', 'n', 'd', 'a', 'r', 'y', 'D', 'e', 's', 'c', 'r', 'i', 'p', 't', 'o', 'r', 0x0 };
	typedef BOOL(WINAPI* AddIntegrityLabelToBoundaryDescriptor_t)(HANDLE*, PSID);
	const ResolvedObject<AddIntegrityLabelToBoundaryDescriptor_t> addIntegrityLabelToBoundaryDescriptor =
		ResolveFunction(sAddIntegrityLabelToBoundaryDescriptor, static_cast<AddIntegrityLabelToBoundaryDescriptor_t>(nullptr));

	addIntegrityLabelToBoundaryDescriptor.call(&bDescriptor, &pSid);

	// Creating private namespace from our boundary descriptor (with random name ofc)
	pNameSpaceName = GenerateRandomWideString();

	constexpr unsigned char sCreatePrivateNamespace[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'i', 'v', 'a', 't', 'e', 'N', 'a', 'm', 'e', 's', 'p', 'a', 'c', 'e', 'W', 0x0 };
	typedef HANDLE(WINAPI* CreatePrivateNamespace_t)(LPSECURITY_ATTRIBUTES, LPVOID, LPCWSTR);
	const ResolvedObject<CreatePrivateNamespace_t> createPrivateNamespace =
		ResolveFunction(sCreatePrivateNamespace, static_cast<CreatePrivateNamespace_t>(nullptr));

	pNameSpace = createPrivateNamespace.call(nullptr, bDescriptor, pNameSpaceName.c_str());

	isPrivateNameSpaceOpen = true;
}

// Function to generate random unicode string using length as a parameter
inline auto Helper::GenerateRandomWideString(int mLength) -> std::wstring
{
	const std::wstring possible_characters = { L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" };
	std::random_device rd;
	std::mt19937 engine(rd());

	const std::uniform_int_distribution<unsigned long long> dist(0, possible_characters.size() - 1);

	std::wstring strReturn;

	for (int i = 0; i < mLength; ++i)
	{
		const unsigned long long random_index = dist(engine);
		strReturn += possible_characters[random_index];
	}

	return strReturn;
}


// Wrapper of Dynamic Function Resolve functionality
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
