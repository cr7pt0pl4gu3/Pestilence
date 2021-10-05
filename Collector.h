#pragma once
#include <string>

class Collector
{
public:
	Collector() = default;
	auto GetWindowsVersion() const ->std::wstring;
};

