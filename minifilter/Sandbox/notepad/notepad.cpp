// notepad.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <tchar.h>

int main(int argc, char* argv[])
{

	DeleteFile(_T("c:\\hi123.txt"));
	//DeleteFile(argv[1]);
	return 0;
}
