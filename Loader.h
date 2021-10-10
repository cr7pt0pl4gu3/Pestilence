#pragma once
#include "Helper.h"

class Loader
{
private:
	Helper helper;
public:
	Loader(const Helper& helper);
	void FileMappingLoadShellcode(unsigned char *rawShellcode, int rawShellcodeLength);
};

