#include <ntddk.h>
#include "MultiThreadSearch.h"

#define DeviceName L"\\Device\\InlineHook"
#define SymbolicLinkName L"\\dosdevices\\InlineHook"
typedef unsigned char BYTE;
typedef unsigned long DWORD;
typedef unsigned short WORD;

unsigned char *g_lpCopyOpCode = NULL;

typedef NTSTATUS (*PSPTERMINATEPROCESS)(PEPROCESS process,NTSTATUS ExitStatus);
PSPTERMINATEPROCESS PspTerminateProcess;

NTSTATUS WriteKernelMemory(BYTE *pDestination, BYTE *pSource, SIZE_T length);

NTSTATUS __stdcall New_PspTerminateProcess(PEPROCESS process,NTSTATUS ExitStatus)
{
	DbgPrint("enter New_PspTerminateProcess!\n");
	return 1;
}

_declspec (naked)T_New_PspTerminateProcess(PEPROCESS process, NTSTATUS ExitStatus)
{
	NTSTATUS ioStatus;
	__asm
	{
		pushad
		pushfd

		push[ebp + 0x10]
		push[ebp + 0x0c]
		call New_PspTerminateProcess
		mov ioStatus,eax
		cmp eax, 0x01
		jz end
		jmp g_lpCopyOpCode
		end:
		popfd
		popad
		mov eax,ioStatus
		retn 4
	}
}


VOID DriverUnload(PDRIVER_OBJECT pDriObj)
{
	UNICODE_STRING uSymbolicName = {0x00};
	ULONG i = 0;
	RtlInitUnicodeString(&uSymbolicName,SymbolicLinkName);
	IoDeleteSymbolicLink(&uSymbolicName);

	IoDeleteDevice(pDriObj->DeviceObject);

	__asm 
	{
		pushad
		mov eax,CR0
		and eax,0xfffeffff
		mov CR0,eax
		popad
	}
	while (i < 10)
	{
		DbgPrint("code%d is 0x%x", i, *(g_lpCopyOpCode + i));
		++i;
		if (i == 4)
			DbgPrint(",");
	}

	DbgPrint("\n");

	WriteKernelMemory(PspTerminateProcess, g_lpCopyOpCode, 5);

	__asm
	{
		pushad
		mov eax,CR0
		or eax,not 0xfffeffff
		mov CR0,eax
		popad
	}

	DbgPrint("goodbye InLinkHook!\n");
}

PMDL GetMdlForNonPagedMemory(PVOID pVirtualAddress, SIZE_T length)
{
	PMDL pMdl;

	if (length >= (PAGE_SIZE * (65535 - sizeof(MDL)) / sizeof(ULONG_PTR)))
	{
		DbgPrint("Size parameter passed to IoAllocateMdl is too big!\n");
		return NULL;
	}

	pMdl = IoAllocateMdl((PVOID)pVirtualAddress, length, FALSE, FALSE, NULL);
	if (NULL == pMdl)
	{
		DbgPrint("IoAllocateMdl returned NULL!\n");
		return NULL;
	}

	MmBuildMdlForNonPagedPool(pMdl);

	return pMdl;
}

NTSTATUS WriteKernelMemory(BYTE *pDestination, BYTE *pSource, SIZE_T length)
{
	KSPIN_LOCK spinLock;
	KLOCK_QUEUE_HANDLE lockHandle;
	PMDL pMdl;
	PVOID pAddress;

	pMdl = GetMdlForNonPagedMemory(pDestination, length);
	if (NULL == pMdl)
	{
		DbgPrint("GetMdlForSafeKernelMemoryArea returned NULL!\n");
		return STATUS_UNSUCCESSFUL;
	}

	pAddress = MmGetSystemAddressForMdlSafe(pMdl, HighPagePriority);

	if (pAddress == NULL)
	{
		IoFreeMdl(pMdl);
		DbgPrint("MmGetSystemAddressForMdlSafe returned NULL!\n");
		return STATUS_UNSUCCESSFUL;
	}

	KeInitializeSpinLock(&spinLock);
	// Only supported on XP and later. For Windows 2000 compatibility you can
	// use the older, less efficient and less reliable KeAcquireSpinLock function.
	KeAcquireInStackQueuedSpinLock(&spinLock, &lockHandle);
	// We have the spinlock, so we can safely overwrite the kernel memory.
	RtlCopyMemory(pAddress, pSource, length);
	KeReleaseInStackQueuedSpinLock(&lockHandle);

	IoFreeMdl(pMdl);

	return STATUS_SUCCESS;
}

VOID InlineHookPspTerminateProcess()
{
	unsigned char *lpBuffer = NULL;
	ULONG uJmpOldOffset = 0;
	ULONG uTotalLen = 5;
	ULONG uJmpOpCodeLen = 5;
	ULONG uJmpOffset = 0;
	NTSTATUS ioStatus = STATUS_SUCCESS;

	__asm
	{
		pushad
		mov eax,CR0
		and eax,0xfffeffff
		mov CR0,eax
		popad
	}

	g_lpCopyOpCode = (unsigned char *)ExAllocatePoolWithTag(NonPagedPool,uTotalLen + uJmpOpCodeLen,"KHLI");
	if (!g_lpCopyOpCode)
	{
		DbgPrint("ExAllocatePoolWithTag faild!\n");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	if (!PspTerminateProcess)
	{
		return STATUS_SUCCESS;
	}

	DbgPrint("PspTerminateProcess address is 0x%x\n",PspTerminateProcess);
	
	//copy
	RtlCopyMemory(g_lpCopyOpCode,PspTerminateProcess,uTotalLen);
	uJmpOffset = (ULONG)(((ULONG)PspTerminateProcess + uTotalLen)) - (ULONG)((ULONG)g_lpCopyOpCode + uTotalLen + uJmpOpCodeLen);
	*(g_lpCopyOpCode + uTotalLen) = 0xE9;
	RtlCopyMemory(g_lpCopyOpCode + uTotalLen + 1,&uJmpOffset,4);

	//inlinehook
	lpBuffer = (unsigned char *)ExAllocatePoolWithTag(NonPagedPool,uTotalLen,L"pmj");
	RtlFillMemory(lpBuffer,uTotalLen,0x90);

	*lpBuffer = 0xE9; 
	
	uJmpOffset = (ULONG)T_New_PspTerminateProcess - ((ULONG)PspTerminateProcess + uTotalLen);
	RtlCopyMemory(lpBuffer + 1,&uJmpOffset,4);

	ioStatus = WriteKernelMemory(PspTerminateProcess, lpBuffer, uTotalLen);
	DbgPrint("T_NewPspTerminateProcess address is 0x%x\n", (ULONG)T_New_PspTerminateProcess);
	
	DbgPrint("uJmpOffset is 0x%x\n", uJmpOffset);


	__asm
	{
		pushad
		mov eax,CR0
		or eax,not 0xfffeffff
		mov CR0,eax
		popad
	}
	

}

NTSTATUS DriverEntry(__in PDRIVER_OBJECT pDriObj,__in PUNICODE_STRING pDriPath)
{
	NTSTATUS ioStatus = STATUS_SUCCESS;
	UNICODE_STRING uDeviceName = {0x00};
	UNICODE_STRING uSymbolicLinkName = {0x00};
	DEVICE_OBJECT lpDeviceObject = {0x00};
	
	RtlInitUnicodeString(&uDeviceName,DeviceName);
	ioStatus = IoCreateDevice(pDriObj
		,NULL
		,&uDeviceName
		,FILE_DEVICE_UNKNOWN
		,0
		,TRUE
		,&lpDeviceObject);
	if(!NT_SUCCESS(ioStatus))
	{
		DbgPrint("IoCreateDevice faild:%d\n",ioStatus);
		return ioStatus;
	}

	ioStatus = IoCreateSymbolicLink(&uSymbolicLinkName,&uDeviceName);
	if(!NT_SUCCESS(ioStatus))
	{
		DbgPrint("IoCreateSymbolicLink faild:%d\n",ioStatus);
		return ioStatus;
	}


	
	pDriObj->DriverUnload = DriverUnload;

	PspTerminateProcess = (PSPTERMINATEPROCESS)MultiThreadSearchFunAddr(L"PspTerminateProcess");

	InlineHookPspTerminateProcess();

	
	

	return ioStatus;
}