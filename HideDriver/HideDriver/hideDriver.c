#include <ntifs.h>

PETHREAD pThreadObj = NULL;

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY64 InLoadOrderLinks;
	ULONG64 __Undefined1;
	ULONG64 __Undefined2;
	ULONG64 __Undefined3;
	ULONG64 NonPageDebugInfo;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Undefined5;
	ULONG64 __Undefined6;
	ULONG CheckSum;
	ULONG __padding1;
	ULONG TimeDataStamp;
	ULONG __padding2;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

NTSTATUS
ObReferenceObjectByName(
	__in PUNICODE_STRING ObjectName,
	__in ULONG Attributes,
	__in_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PVOID ParseContext,
	__out PVOID *Object
);

extern POBJECT_TYPE *IoDriverObjectType;

PDRIVER_OBJECT g_PDrv = NULL;

VOID NewHide()
{
	LARGE_INTEGER Sleep = { 0 };

	PDRIVER_OBJECT ghostofdeath = NULL;

	UNICODE_STRING ghostname = { 0 };

	RtlInitUnicodeString(&ghostname, L"\\Driver\\Beep");

	ObReferenceObjectByName(&ghostname, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, &ghostofdeath);

	if (g_PDrv && ghostofdeath)
	{
		ObDereferenceObject(ghostofdeath);

		PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)g_PDrv->DriverSection;

		PKLDR_DATA_TABLE_ENTRY tempentry = (PKLDR_DATA_TABLE_ENTRY)ghostofdeath->DriverSection;

		entry->DllBase = tempentry->DllBase;

		PLIST_ENTRY pList = &(entry->InLoadOrderLinks);

		RemoveEntryList(pList);

		pList->Flink = NULL;
		pList->Blink = NULL;

		g_PDrv->DriverSection = NULL;

		g_PDrv->DriverStart = NULL;
		g_PDrv->DriverSize = NULL;
		g_PDrv->DriverUnload = NULL;
		g_PDrv->DriverInit = NULL;
		g_PDrv->DeviceObject = NULL;

		Sleep.QuadPart = -1000000;

		KeDelayExecutionThread(KernelMode, FALSE, &Sleep);

		ObMakeTemporaryObject(g_PDrv);

		INT a = 12, b = 0, c = 0;

		__try{
			c = a / b;
		}
			__except (1)
		{
			DbgPrint("Boom!");
		}
	}

	DbgPrint("Finish!");
}

VOID MyThread()
{
	LARGE_INTEGER SleepTime;
	SleepTime.QuadPart = -20000000;

	KdPrint(("Entry thread!"));

	while (1)
	{
		KdPrint(("-------while-------"));

		KeDelayExecutionThread(KernelMode, FALSE, &SleepTime);
	}

	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path)
{
	g_PDrv = driver;

	OBJECT_ATTRIBUTES ObjAttr = { 0 };
	HANDLE hThread;

	InitializeObjectAttributes(&ObjAttr, NULL, OBJ_KERNEL_HANDLE, 0, NULL);

	NTSTATUS status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &ObjAttr, NULL, NULL, MyThread, NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Create Thread Fail!"));
		return STATUS_NOT_SUPPORTED;
	}

	status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &pThreadObj, NULL);

	ZwClose(hThread);

	IoRegisterDriverReinitialization(driver, NewHide, NULL);

	return 0;
}