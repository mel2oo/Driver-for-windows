#include <ntddk.h>

VOID FindFunc1(PVOID);
VOID FindFunc2(PVOID);
VOID FindFunc3(PVOID);
VOID FindFunc4(PVOID);

#define SwapContext_Code1 0x8b55ff8b
#define SwapContext_Code2 0xa16456ec
#define SwapContext_Code3 0x00000124
#define SwapContext_Code4 0x3b08758b

typedef NTSTATUS (*NtQuerySystemInformation)(__in ULONG SystemInformationClass,
										  __out PVOID SystemInformation,
										  __in ULONG Length,
										  __out ULONG ReturnLength);
NtQuerySystemInformation NtQuerySystemInfo = NULL;

typedef NTSTATUS (*SwapContext)(PEPROCESS pEprocess,NTSTATUS ExitStatus);
SwapContext MySwapContext = NULL;

ULONG g_PsTerminateProcess = 0x00;
ERESOURCE g_ProcessLock = {0x00};

typedef struct _SYSTEM_MUDULE_INFO
{
	ULONG Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknow;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
}SYSTEM_MODULE_INFO,*PSYSTEM_MODULE_INFO;

typedef unsigned long DWORD;


PSYSTEM_MODULE_INFO g_pSystemModuleInfo = NULL;

VOID Lock(ERESOURCE *pLock)
{
	KeEnterCriticalRegion();

	ExAcquireResourceExclusiveLite(pLock, TRUE);
}

VOID Unlock(ERESOURCE *pLock)
{
	ExReleaseResource(pLock);

	KeLeaveCriticalRegion();
}

ULONG MultiThreadSearchFunAddr(WCHAR *szFuncName)
{
	
	UNICODE_STRING uFuncName = {0x00};
	UNICODE_STRING uNtQuerySystemInfoFuncName = {0x00};
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PVOID pOutputBuffer = NULL;
	ULONG OutputBufferSize;
	PVOID waitObects[2] = {NULL};
	HANDLE thread1,thread2,thread3,thread4;
	thread1 = thread2 = thread3 = thread4 = NULL;

	RtlInitUnicodeString(&uFuncName,szFuncName);
	RtlInitUnicodeString(&uNtQuerySystemInfoFuncName,L"NtQuerySystemInformation");
	NtQuerySystemInfo = (NtQuerySystemInformation)MmGetSystemRoutineAddress(&uNtQuerySystemInfoFuncName);
	if(!NtQuerySystemInfo)
	{
		DbgPrint("Get NtQuerySystemInformation faild\n");
		return (ULONG)0;
	}
	
	ExInitializeResourceLite(&g_ProcessLock);

	ntStatus = NtQuerySystemInfo(11,pOutputBuffer,0,&OutputBufferSize);
	
	pOutputBuffer = ExAllocatePoolWithTag(PagedPool,OutputBufferSize,'PTUO');
	if(!pOutputBuffer)
	{
		DbgPrint("alloc memory faild\n");
		return 0;
	}

	ntStatus = NtQuerySystemInfo(11,pOutputBuffer,OutputBufferSize,&OutputBufferSize);
	if(!NT_SUCCESS(ntStatus))
	{
		DbgPrint("NtQuerySystemInfo2 faild:%x\n",ntStatus);
		ExFreePool(pOutputBuffer);
		return 0;
	}

	g_pSystemModuleInfo = (PSYSTEM_MODULE_INFO)((ULONG *)pOutputBuffer + 1);
	
	if(KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		KfRaiseIrql(PASSIVE_LEVEL);
	}
	if(KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		DbgPrint("KeRaiseIrql faild:%x\n",ntStatus);
		return 0;
	}


	ntStatus = PsCreateSystemThread(&thread1,
		0,
		NULL,
		(HANDLE)0,
		NULL,
		FindFunc1,
		NULL);
	if(!NT_SUCCESS(ntStatus))
	{
		DbgPrint("PsCreateSystemThread1 faild:%x\n",ntStatus);
		ExFreePool(pOutputBuffer);
		return 0;
	}

	ntStatus = PsCreateSystemThread(&thread2,
		0,
		NULL,
		(HANDLE)0,
		NULL,
		FindFunc2,
		NULL);
	if(!NT_SUCCESS(ntStatus))
	{
		DbgPrint("PsCreateSystemThread2 faild:%x\n",ntStatus);
		ExFreePool(pOutputBuffer);
		return 0;
	}

	ntStatus = ObReferenceObjectByHandle(thread1,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		&waitObects[0],
		NULL);
	
	ntStatus = ObReferenceObjectByHandle(thread2,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		&waitObects[1],
		NULL);


	KeWaitForMultipleObjects(2,waitObects,WaitAll,Executive,KernelMode,FALSE,NULL,NULL);
	//KeWaitForSingleObject(waitObects,Executive,KernelMode,FALSE,NULL);
	ObDereferenceObject(waitObects[0]);
	ObDereferenceObject(waitObects[1]);
	ExDeleteResourceLite(&g_ProcessLock);
	return g_PsTerminateProcess;

}

VOID FindFunc1(PVOID pContext)
{
	ULONG ModuleBase;
	ULONG ModuleEndOffset;
	ULONG ModuleSize;
	ULONG index;

	ModuleBase = (ULONG)g_pSystemModuleInfo->Base;
	ModuleSize = g_pSystemModuleInfo->Size / 2;
	ModuleEndOffset = (ULONG)g_pSystemModuleInfo->Base + ModuleSize;
	//ModuleEndOffset = (ULONG)g_pSystemModuleInfo->Base + g_pSystemModuleInfo->Size;

	for(index = ModuleBase; index < ModuleEndOffset; index++)
	{
		Lock(&g_ProcessLock);
		if (g_PsTerminateProcess)
		{
			Unlock(&g_ProcessLock);
			break;
		}
		if (*(DWORD *)(index + 0x00) == SwapContext_Code1)
		{
			if (*(DWORD *)(index + 0x04) == SwapContext_Code2)
			{
				if (*(DWORD *)(index + 0x08) == SwapContext_Code3)
				{
					if (*(DWORD *)(index + 0x0c) == SwapContext_Code4)
					{
						DbgPrint("thread1 Search SwapContext func Address successful:%8x\n!", index);
						g_PsTerminateProcess = index;
						Unlock(&g_ProcessLock);
						break;
					}
				}
			}
		}
		
		Unlock(&g_ProcessLock);
	}
	
	PsTerminateSystemThread(STATUS_SUCCESS);
	
}

VOID FindFunc2(PVOID pContext)
{
	ULONG ModuleBase;
	ULONG ModuleEnd;
	ULONG index;
	ModuleBase = (ULONG)g_pSystemModuleInfo->Base + (g_pSystemModuleInfo->Size / 2);
	ModuleEnd = (ULONG)g_pSystemModuleInfo->Base + g_pSystemModuleInfo->Size;

	__try
	{
		for(index = ModuleBase; index < ModuleEnd; index++)
		{
			Lock(&g_ProcessLock);
			if (g_PsTerminateProcess)
			{
				__leave;
			}
			if (!MmIsAddressValid((DWORD *)index))
			{
				DbgPrint("Memory Address is Invalid!\n");
				__leave;
			}

			DbgPrint("index is 0x%x,ModuleEnd is 0x%x,Memory Check Bypass!\n",index,ModuleEnd);
			if(*(DWORD *)(index + 0x00) == SwapContext_Code1)
			{
				if(*(DWORD *)(index + 0x04) == SwapContext_Code2)
				{
					if(*(ULONG *)(index + 0x08) == SwapContext_Code3)
					{
						if(*(ULONG *)(index + 0x0c) == SwapContext_Code4)
						{
							DbgPrint("thread2 Search SwapContext func Address successful:%x\n",index);
							g_PsTerminateProcess = index;
							__leave;
						}
					}
				}
			}
			Unlock(&g_ProcessLock);
		}
	}
	
	__finally
	{
		DbgPrint("__finally!\n");
		Unlock(&g_ProcessLock);
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID FindFunc3(PVOID pContext)
{
	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID FindFunc4(PVOID pContext)
{
	PsTerminateSystemThread(STATUS_SUCCESS);
}