#pragma once
#include <string>
#include <vector>
#include "Helper.h"

class Collector
{
private:
	Helper helper;
public:
	Collector(const Helper &helper);
	[[nodiscard]] auto GetWindowsVersion() ->std::wstring;
	auto GetNetBIOSName() ->std::wstring;
	auto FingerPrintSystem() ->std::vector<std::wstring>;
};

