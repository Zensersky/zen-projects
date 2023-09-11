// Anti-DBGTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

#include "AntiDBG.h"


int testthread()
{
	while (1 == 1)
	{
		if (GetAsyncKeyState(VK_SHIFT))
			MessageBoxA(NULL, "msg", "msg", MB_OK);
		Sleep(1000);
	}
	return 1;

}


int main()
{
	if (!AntiDebug::Initialize(nullptr))
	{
		printf("Security failed to initialize!\n");
		system("pause");
		return false;
	}

	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)testthread, NULL, NULL, NULL);

	AntiDebug::AddProtectedThread(GetCurrentThreadId());

	while (!GetAsyncKeyState(VK_END))
	{
		printf("Anti-DBG working!\n");

		AntiDebug::SecurityCheck1();
		AntiDebug::SecurityThreadCheck1();

		Sleep(3000);
	}
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
