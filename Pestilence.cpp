#include <iostream>
#include "Collector.h"
#include "Helper.h"
#include "Windows.h"

auto main() -> int
{
	try
	{
		const auto* helper = new Helper();
		auto* collector = new Collector(*helper);
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