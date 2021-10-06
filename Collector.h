#pragma once
#include <string>
#include <vector>

class Collector
{
public:
	Collector() = default;
	auto GetWindowsVersion() const ->std::wstring;
	static auto GetNetBIOSName() ->std::wstring;
	auto FingerPrintSystem() const ->std::vector<std::wstring>;
};

