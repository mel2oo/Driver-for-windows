// KeyBoardHook.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>

HHOOK g_hook;

LRESULT HookProc(ULONG nCode,LPARAM wParam,LPARAM lParam)
{
	KBDLLHOOKSTRUCT *kbdhks = (KBDLLHOOKSTRUCT *)lParam;
	BOOL bControlPress = 0;

	if(kbdhks->vkCode == HC_ACTION)
	{
		bControlPress = GetAsyncKeyState(VK_CONTROL) >> ((sizeof(short) * 8) - 1);	
	}
	if(kbdhks->vkCode == VK_ESCAPE & bControlPress)
	{
		return 1;
	}
	if(wParam == WM_KEYUP)
		printf("%c",kbdhks->vkCode);

	return CallNextHookEx(g_hook,nCode,wParam,lParam);
}

int main()
{
	MSG msg;
	g_hook = SetWindowsHookEx(WH_KEYBOARD_LL,(HOOKPROC)HookProc,GetModuleHandleW(0),0);

	//»√œ˚œ¢—≠ª∑
	while(GetMessageW(&msg,0,0,0))
		DispatchMessageW(&msg);

	return 0;
}

