#include "hide.h"

PDRIVER_OBJECT g_pDriverObject = NULL;
MiProcessLoaderEntry g_pfnMiProcessLoaderEntry = NULL;

PVOID GetProcAddress(WCHAR *FuncName)
{
	UNICODE_STRING u_FuncName;
	RtlInitUnicodeString(&u_FuncName, FuncName);
	return MmGetSystemRoutineAddress(&u_FuncName);
}

//在Windows 7的系统下去搜索MiProcessLoaderEntry函数
MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_7()
{
	//这个Search_Code就是MiProcessLoaderEntry函数的最前面的操作码
	//WIN7的搜索很有趣，MiProcessLoaderEntry这个函数就在EtwWriteString函数的前面几个函数
	//所以直接搜索EtwWriteString函数然后向前搜索即可
	CHAR Search_Code[] = "\x48\x89\x5C\x24\x08"			//mov     [rsp+arg_0], rbx
		"\x48\x89\x6C\x24\x18"			//mov     [rsp+arg_10], rbp
		"\x48\x89\x74\x24\x20"			//mov     [rsp+arg_18], rsi
		"\x57"							//push    rdi
		"\x41\x54"						//push    r12
		"\x41\x55"						//push    r13
		"\x41\x56"						//push    r14
		"\x41\x57";					//push    r15
	ULONG_PTR EtwWriteStringAddress = 0;
	ULONG_PTR StartAddress = 0;

	EtwWriteStringAddress = (ULONG_PTR)GetProcAddress(L"EtwWriteString");
	StartAddress = EtwWriteStringAddress - 0x1000;
	if (EtwWriteStringAddress == 0)
		return NULL;

	while (StartAddress < EtwWriteStringAddress)
	{
		if (memcmp((CHAR*)StartAddress, Search_Code, strlen(Search_Code)) == 0)
			return (MiProcessLoaderEntry)StartAddress;
		++StartAddress;
	}

	return NULL;
}

//在Windows 8的系统下去搜索MiProcessLoaderEntry函数
MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_8()
{
	CHAR Search_Code[] = "\x48\x89\x5C\x24\x08"			//mov     [rsp+arg_0], rbx
		"\x48\x89\x6C\x24\x10"			//mov     [rsp+arg_10], rbp
		"\x48\x89\x74\x24\x18"			//mov     [rsp+arg_18], rsi
		"\x57"							//push    rdi
		"\x48\x83\xEC\x20"				//sub	  rsp, 20h
		"\x48\x8B\xD9";				//mov     rbx, rcx
	ULONG_PTR IoInvalidateDeviceRelationsAddress = 0;
	ULONG_PTR StartAddress = 0;

	IoInvalidateDeviceRelationsAddress = (ULONG_PTR)GetProcAddress(L"IoInvalidateDeviceRelations");
	StartAddress = IoInvalidateDeviceRelationsAddress - 0x1000;
	if (IoInvalidateDeviceRelationsAddress == 0)
		return NULL;

	while (StartAddress < IoInvalidateDeviceRelationsAddress)
	{
		if (memcmp((CHAR*)StartAddress, Search_Code, strlen(Search_Code)) == 0)
			return (MiProcessLoaderEntry)StartAddress;
		++StartAddress;
	}

	return NULL;
}

//在Windows 8.1的系统下去搜索MiProcessLoaderEntry函数
MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_8_1()
{
	//IoLoadCrashDumpDriver -> MmLoadSystemImage -> MiProcessLoaderEntry
	//MmUnloadSystemImage -> MiUnloadSystemImage -> MiProcessLoaderEntry
	//在WIN10中MmUnloadSystemImage是导出的，WIN8.1中未导出，所以只能走另一条路子，还好IoLoadCrashDumpDriver是导出的

	//在IoLoadCrashDumpDriver函数中用来搜索的Code
	CHAR IoLoadCrashDumpDriver_Code[] = "\x48\x8B\xD0"				//mov     rdx, rax
		"\xE8";						//call	  *******
//在MmLoadSystemImage函数中用来搜索的Code
	CHAR MmLoadSystemImage_Code[] = "\x41\x8B\xD6"					//mov     edx, r14d	
		"\x48\x8B\xCE"					//mov	  rcx, rsi
		"\x41\x83\xCC\x04"				//or	  r12d, 4
		"\xE8";							//call    *******	
	ULONG_PTR IoLoadCrashDumpDriverAddress = 0;
	ULONG_PTR MmLoadSystemImageAddress = 0;
	ULONG_PTR StartAddress = 0;

	IoLoadCrashDumpDriverAddress = (ULONG_PTR)GetProcAddress(L"IoLoadCrashDumpDriver");
	StartAddress = IoLoadCrashDumpDriverAddress;
	if (IoLoadCrashDumpDriverAddress == 0)
		return NULL;

	while (StartAddress < IoLoadCrashDumpDriverAddress + 0x500)
	{
		if (memcmp((VOID*)StartAddress, IoLoadCrashDumpDriver_Code, strlen(IoLoadCrashDumpDriver_Code)) == 0)
		{
			StartAddress += strlen(IoLoadCrashDumpDriver_Code);								//跳过一直到call的code
			MmLoadSystemImageAddress = *(LONG*)StartAddress + StartAddress + 4;
			break;
		}
		++StartAddress;
	}

	StartAddress = MmLoadSystemImageAddress;
	if (MmLoadSystemImageAddress == 0)
		return NULL;

	while (StartAddress < MmLoadSystemImageAddress + 0x500)
	{
		if (memcmp((VOID*)StartAddress, MmLoadSystemImage_Code, strlen(MmLoadSystemImage_Code)) == 0)
		{
			StartAddress += strlen(MmLoadSystemImage_Code);								 //跳过一直到call的code
			return (MiProcessLoaderEntry)(*(LONG*)StartAddress + StartAddress + 4);
		}
		++StartAddress;
	}

	return NULL;
}

//在Windows 10的系统下去搜索MiProcessLoaderEntry函数
MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_10()
{
	//MmUnloadSystemImage -> MiUnloadSystemImage -> MiProcessLoaderEntry

	//在MmUnloadSystemImage函数中搜索的Code
	CHAR MmUnloadSystemImage_Code[] = "\x83\xCA\xFF"				//or      edx, 0FFFFFFFFh
		"\x48\x8B\xCF"				//mov     rcx, rdi
		"\x48\x8B\xD8"				//mov     rbx, rax
		"\xE8";						//call    *******
/*
//在MiUnloadSystemImage函数中搜索的Code
CHAR MiUnloadSystemImage_Code[] = "\x45\x33\xFF"				//xor     r15d, r15d
								  "\x4C\x39\x3F"				//cmp     [rdi], r15
								  "\x74\x18"					//jz      short
								  "\x33\xD2"					//xor     edx, edx
								  "\x48\x8B\xCF"				//mov     rcx, rdi
								  "\xE8";						//call	  *******
*/
	ULONG_PTR MmUnloadSystemImageAddress = 0;
	ULONG_PTR MiUnloadSystemImageAddress = 0;
	ULONG_PTR StartAddress = 0;

	MmUnloadSystemImageAddress = (ULONG_PTR)GetProcAddress(L"MmUnloadSystemImage");
	StartAddress = MmUnloadSystemImageAddress;
	if (MmUnloadSystemImageAddress == 0)
		return NULL;

	while (StartAddress < MmUnloadSystemImageAddress + 0x500)
	{
		if (memcmp((VOID*)StartAddress, MmUnloadSystemImage_Code, strlen(MmUnloadSystemImage_Code)) == 0)
		{
			StartAddress += strlen(MmUnloadSystemImage_Code);								//跳过一直到call的code
			MiUnloadSystemImageAddress = *(LONG*)StartAddress + StartAddress + 4;
			break;
		}
		++StartAddress;
	}

	StartAddress = MiUnloadSystemImageAddress;
	if (MiUnloadSystemImageAddress == 0)
		return NULL;

	while (StartAddress < MiUnloadSystemImageAddress + 0x500)
	{
		//分析ntoskrnl可以看出来，在不同版本的win10，call MiProcessLoaderEntry前面的操作不同
		//但是每次call MiProcessLoaderEntry之后都会mov eax, dword ptr cs:PerfGlobalGroupMask
		//所以这里根据0xEB(call) , 0x8B 0x05(mov eax)作为特征码

		/*if (memcmp((VOID*)StartAddress, MiUnloadSystemImage_Code, strlen(MiUnloadSystemImage_Code)) == 0)
		{
			StartAddress += strlen(MiUnloadSystemImage_Code);								 //跳过一直到call的code
			return (MiProcessLoaderEntry)(*(LONG*)StartAddress + StartAddress + 4);
		}*/
		if (*(UCHAR*)StartAddress == 0xE8 &&												//call
			*(UCHAR *)(StartAddress + 5) == 0x8B && *(UCHAR *)(StartAddress + 6) == 0x05)	//mov eax,
		{
			StartAddress++;																	//跳过call的0xE8
			return (MiProcessLoaderEntry)(*(LONG*)StartAddress + StartAddress + 4);
		}
		++StartAddress;
	}

	return NULL;
}

MiProcessLoaderEntry g_MiProcessLoaderEntry()
{
	NTSTATUS status;
	MiProcessLoaderEntry m_MiProcessLoaderEntry = NULL;
	RTL_OSVERSIONINFOEXW OsVersion = { 0 };

	OsVersion.dwOSVersionInfoSize = sizeof(OsVersion);
	status = RtlGetVersion(&OsVersion);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("获取系统版本失败！\n"));
		return NULL;
	}

	if (OsVersion.dwMajorVersion == 10)								//如果是Windows 10
	{
		m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_10();
		KdPrint(("当前系统版本是Windows 10 %d\n", OsVersion.dwBuildNumber));
		if (m_MiProcessLoaderEntry == NULL)
			KdPrint(("获取不到MiProcessLoaderEntry！\n"));
		else
			KdPrint(("MiProcessLoaderEntry地址是：%llx\n", (ULONG_PTR)m_MiProcessLoaderEntry));

		return m_MiProcessLoaderEntry;
	}
	else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 3)
	{
		m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_8_1();
		KdPrint(("当前系统版本是Windows 8.1\n"));
		if (m_MiProcessLoaderEntry == NULL)
			KdPrint(("获取不到MiProcessLoaderEntry！\n"));
		else
			KdPrint(("MiProcessLoaderEntry地址是：%llx\n", (ULONG_PTR)m_MiProcessLoaderEntry));

		return m_MiProcessLoaderEntry;
	}
	else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 2 && OsVersion.wProductType == VER_NT_WORKSTATION)		//这个是为了区分Windows 8和Windows Server 2012
	{
		m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_8();
		KdPrint(("当前系统版本是Windows 8\n"));
		if (m_MiProcessLoaderEntry == NULL)
			KdPrint(("获取不到MiProcessLoaderEntry！\n"));
		else
			KdPrint(("MiProcessLoaderEntry地址是：%llx\n", (ULONG_PTR)m_MiProcessLoaderEntry));

		return m_MiProcessLoaderEntry;
	}
	else if (OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1 && OsVersion.wProductType == VER_NT_WORKSTATION)		//这个是为了区分Windows 7和Windows Server 2008 R2	
	{
		m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_7();
		KdPrint(("当前系统版本是Windows 7\n"));
		if (m_MiProcessLoaderEntry == NULL)
			KdPrint(("获取不到MiProcessLoaderEntry！\n"));
		else
			KdPrint(("MiProcessLoaderEntry地址是：%llx\n", (ULONG_PTR)m_MiProcessLoaderEntry));

		return m_MiProcessLoaderEntry;
	}

	KdPrint(("当前系统不支持！\n"));
	return NULL;
}

PVOID GetCallPoint(PVOID pCallPoint)
{
	ULONG dwOffset = 0;
	ULONG_PTR returnAddress = 0;
	LARGE_INTEGER returnAddressTemp = { 0 };
	PUCHAR pFunAddress = NULL;

	if (pCallPoint == NULL || !MmIsAddressValid(pCallPoint))
		return NULL;

	pFunAddress = pCallPoint;
	// 函数偏移  
	RtlCopyMemory(&dwOffset, (PVOID)(pFunAddress + 1), sizeof(ULONG));

	// JMP向上跳转  
	if ((dwOffset & 0x10000000) == 0x10000000)
	{
		dwOffset = dwOffset + 5 + pFunAddress;
		returnAddressTemp.QuadPart = (ULONG_PTR)pFunAddress & 0xFFFFFFFF00000000;
		returnAddressTemp.LowPart = dwOffset;
		returnAddress = returnAddressTemp.QuadPart;
		return (PVOID)returnAddress;
	}

	returnAddress = (ULONG_PTR)dwOffset + 5 + pFunAddress;
	return (PVOID)returnAddress;

}

PVOID GetUndocumentFunctionAddress(IN PUNICODE_STRING pFunName, IN PUCHAR pStartAddress, IN UCHAR* pFeatureCode, IN ULONG FeatureCodeNum, ULONG SerSize, UCHAR SegCode, ULONG AddNum, BOOLEAN ByName)
{
	ULONG dwIndex = 0;
	PUCHAR pFunAddress = NULL;
	ULONG dwCodeNum = 0;

	if (pFeatureCode == NULL)
		return NULL;

	if (FeatureCodeNum >= 15)
		return NULL;

	if (SerSize > 0x1024)
		return NULL;

	if (ByName)
	{
		if (pFunName == NULL || !MmIsAddressValid(pFunName->Buffer))
			return NULL;

		pFunAddress = (PUCHAR)MmGetSystemRoutineAddress(pFunName);
		if (pFunAddress == NULL)
			return NULL;
	}
	else
	{
		if (pStartAddress == NULL || !MmIsAddressValid(pStartAddress))
			return NULL;

		pFunAddress = pStartAddress;
	}

	for (dwIndex = 0; dwIndex < SerSize; dwIndex++)
	{
		__try
		{
			if (pFunAddress[dwIndex] == pFeatureCode[dwCodeNum] || pFeatureCode[dwCodeNum] == SegCode)
			{
				dwCodeNum++;

				if (dwCodeNum == FeatureCodeNum)
					return pFunAddress + dwIndex - dwCodeNum + 1 + (int)AddNum;

				continue;
			}

			dwCodeNum = 0;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return 0;
		}
	}

	return 0;
}

// Test On 14393
NTSTATUS HideDriverWin10(PDRIVER_OBJECT pTargetDriverObject)
{
	UNICODE_STRING usRoutie = { 0 };
	PUCHAR pAddress = NULL;
	PUCHAR pMiUnloadSystemImage = NULL;

	UCHAR code[3] =
		"\xD8\xE8";

	UCHAR code2[10] =
		"\x48\x8B\xD8\xE8\x60\x60\x60\x60\x8B";

	UCHAR code3[3] =
		"\xA8\x04";

	/*
	PAGE:000000014052ABE4 48 8B D8                                      mov     rbx, rax
	PAGE:000000014052ABE7 E8 48 17 F7 FF                                call    MiUnloadSystemImage
	*/
	DbgBreakPoint();
	if (pTargetDriverObject == NULL)
		return STATUS_INVALID_PARAMETER;

	RtlInitUnicodeString(&usRoutie, L"MmUnloadSystemImage");

	pAddress = GetUndocumentFunctionAddress(&usRoutie, NULL, code, 2, 0x30, 0x90, 1, TRUE);

	if (pAddress == NULL)
	{
		KdPrint(("MiUnloadSystemImage 1 faild!\n"));
		return STATUS_UNSUCCESSFUL;
	}

	pAddress = GetCallPoint(pAddress);

	if (pAddress == NULL)
	{
		KdPrint(("MiUnloadSystemImage 2 faild!\n"));
		return STATUS_UNSUCCESSFUL;
	}
	pMiUnloadSystemImage = pAddress;
	/*
	PAGE:000000014049C5CF 48 8B CB                                      mov     rcx, rbx
	PAGE:000000014049C5D2 E8 31 29 C2 FF                                call    MiProcessLoaderEntry
	PAGE:000000014049C5D7 8B 05 A3 BC F0 FF                             mov     eax, cs:PerfGlobalGroupMask
	PAGE:000000014049C5DD A8 04                                         test    al, 4
	*/

	pAddress = GetUndocumentFunctionAddress(NULL, pAddress, code2, 9, 0x300, 0x60, 3, FALSE);

	if (pAddress == NULL)
	{
		KdPrint(("MiProcessLoaderEntry 1 faild!\n"));
		pAddress = GetUndocumentFunctionAddress(NULL, pMiUnloadSystemImage, code3, 2, 0x300, 0x60, -11, FALSE);
		DbgBreakPoint();
		if (pAddress == NULL)
			return STATUS_UNSUCCESSFUL;
	}

	g_pfnMiProcessLoaderEntry = (MiProcessLoaderEntry)GetCallPoint(pAddress);

	if (g_pfnMiProcessLoaderEntry == NULL)
	{
		KdPrint(("MiProcessLoaderEntry 2 faild!\n"));
		return STATUS_UNSUCCESSFUL;
	}

	KdPrint(("0x%p\n", g_pfnMiProcessLoaderEntry));

	/*////////////////////////////////隐藏驱动/////////////////////////////////*/
	SupportSEH(pTargetDriverObject);
	g_pfnMiProcessLoaderEntry(pTargetDriverObject->DriverSection, 0);

	pTargetDriverObject->DriverSection = NULL;
	/*/////////////////////////////////////////////////////////////////////////*/

	// 破坏驱动对象特征
	pTargetDriverObject->DriverStart = NULL;
	pTargetDriverObject->DriverSize = NULL;
	pTargetDriverObject->DriverUnload = NULL;
	pTargetDriverObject->DriverInit = NULL;
	pTargetDriverObject->DeviceObject = NULL;

	return STATUS_SUCCESS;
}

BOOLEAN HideDriverWin7(PDRIVER_OBJECT pTargetDriverObject)
{
	UNICODE_STRING usFuncName = { 0 };
	PUCHAR pMiProcessLoaderEntry = NULL;
	size_t i = 0;

	RtlInitUnicodeString(&usFuncName, L"EtwWriteString");

	pMiProcessLoaderEntry = (PUCHAR)MmGetSystemRoutineAddress(&usFuncName);

	pMiProcessLoaderEntry = pMiProcessLoaderEntry - 0x600;

	__try {
		for (i = 0; i < 0x600; i++)
		{

			if (*pMiProcessLoaderEntry == 0xbb && *(pMiProcessLoaderEntry + 1) == 0x01 && *(pMiProcessLoaderEntry + 2) == 0x0 &&
				*(pMiProcessLoaderEntry + 5) == 0x48 && *(pMiProcessLoaderEntry + 0xc) == 0x8a && *(pMiProcessLoaderEntry + 0xd) == 0xd3
				&& *(pMiProcessLoaderEntry + 0xe) == 0xe8)
			{
				pMiProcessLoaderEntry = pMiProcessLoaderEntry - 0x40;
				for (i = 0; i < 0x30; i++)
				{
					if (*pMiProcessLoaderEntry == 0x90 && *(pMiProcessLoaderEntry + 1) == 0x48)
					{
						pMiProcessLoaderEntry++;
						goto MiProcessSuccess;
					}
					pMiProcessLoaderEntry++;
				}
				return FALSE;
			}
			pMiProcessLoaderEntry++;
		}
	}
	__except (1)
	{
		return FALSE;
	}

	return FALSE;
MiProcessSuccess:

	g_pfnMiProcessLoaderEntry = pMiProcessLoaderEntry;

	KdPrint(("0x%p\n", g_pfnMiProcessLoaderEntry));

	/*////////////////////////////////隐藏驱动/////////////////////////////////*/
	SupportSEH(pTargetDriverObject);
	g_pfnMiProcessLoaderEntry(pTargetDriverObject->DriverSection, 0);

	pTargetDriverObject->DriverSection = NULL;
	/*/////////////////////////////////////////////////////////////////////////*/

	// 破坏驱动对象特征
	pTargetDriverObject->DriverStart = NULL;
	pTargetDriverObject->DriverSize = NULL;
	pTargetDriverObject->DriverUnload = NULL;
	pTargetDriverObject->DriverInit = NULL;
	pTargetDriverObject->DeviceObject = NULL;

	return TRUE;
}

NTSTATUS GetDriverObject(PDRIVER_OBJECT *lpObj, WCHAR* DriverDirName)
{
	NTSTATUS status = STATUS_SUCCESS;
	PDRIVER_OBJECT pBeepObj = NULL;
	UNICODE_STRING DevName = { 0 };

	if (!MmIsAddressValid(lpObj))
		return STATUS_INVALID_ADDRESS;

	RtlInitUnicodeString(&DevName, DriverDirName);

	status = ObReferenceObjectByName(&DevName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, &pBeepObj);

	if (NT_SUCCESS(status))
		*lpObj = pBeepObj;
	else
	{
		KdPrint(("Get Obj faild...error:0x%x\n", status));
	}

	return status;
}

BOOLEAN SupportSEH(PDRIVER_OBJECT pDriverObject)
{
	PDRIVER_OBJECT pTempDrvObj = NULL;
	PLDR_DATA_TABLE_ENTRY ldr = pDriverObject->DriverSection;
	if (NT_SUCCESS(GetDriverObject(&pTempDrvObj, L"\\Driver\\beep")))
	{
		ldr->DllBase = pTempDrvObj->DriverStart;

		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

VOID KernelSleep(LONG msec)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 0, &my_interval);
}

VOID DelObject(IN PVOID StartContext)
{
	PULONG_PTR pZero = NULL;
	KernelSleep(5000);
	ObMakeTemporaryObject(g_pDriverObject);
	KdPrint(("test seh.\n"));
	__try {
		*pZero = 0x100;
	}
	__except (1)
	{
		KdPrint(("seh success.\n"));
	}
}

VOID Reinitialize(PDRIVER_OBJECT DriverObject, PVOID Context, ULONG Count)
{

	HANDLE hThread = NULL;

	if (*NtBuildNumber < 8000)
	{
		HideDriverWin7(DriverObject);
	}
	else
	{
		HideDriverWin10(DriverObject);
	}

	PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, DelObject, NULL);

}