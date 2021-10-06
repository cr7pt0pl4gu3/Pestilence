#include <iostream>
#include "Collector.h"
#include "Windows.h"

auto main() -> int
{
	try
	{
		const auto* collector = new Collector();
		const std::vector<std::wstring> info = collector->FingerPrintSystem();
		for (auto &i : info)
		{
			std::wcout << i << '\n';
		}
	}
	catch (...)
	{
		ExitProcess(GetLastError());
	}
}