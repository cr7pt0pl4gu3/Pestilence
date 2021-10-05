#include <iostream>
#include "Collector.h"
#include "Windows.h"

auto main() -> int
{
	try
	{
		const auto* collector = new Collector();
		std::wcout << collector->GetWindowsVersion();
	}
	catch (...)
	{
		ExitProcess(GetLastError());
	}
}