#ifndef HIDE_H
#define HIDE_H

#include <ntifs.h>

#pragma warning(disable : 4047)  

extern POBJECT_TYPE *IoDriverObjectType;
extern PDRIVER_OBJECT g_pDriverObject;
extern PSHORT NtBuildNumber;

#define DELAY_ONE_MICROSECOND 	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND*1000)

typedef NTSTATUS(__fastcall *MiProcessLoaderEntry)(PVOID pDriverSection, BOOLEAN bLoad);

extern MiProcessLoaderEntry g_pfnMiProcessLoaderEntry;

NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
	__in PUNICODE_STRING ObjectName,
	__in ULONG Attributes,
	__in_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PVOID ParseContext,
	__out PVOID* Object
);

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID      DllBase;
	PVOID      EntryPoint;
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

VOID KernelSleep(LONG msec);

VOID DelObject(IN PVOID StartContext);

PVOID GetProcAddress(WCHAR *FuncName);

MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_7();

MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_8();

MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_8_1();

MiProcessLoaderEntry Get_MiProcessLoaderEntry_WIN_10();

MiProcessLoaderEntry g_MiProcessLoaderEntry();

NTSTATUS GetDriverObject(PDRIVER_OBJECT *lpObj, WCHAR* DriverDirName);

BOOLEAN SupportSEH(PDRIVER_OBJECT pDriverObject);

VOID Reinitialize(PDRIVER_OBJECT DriverObject, PVOID Context, ULONG Count);

#endif