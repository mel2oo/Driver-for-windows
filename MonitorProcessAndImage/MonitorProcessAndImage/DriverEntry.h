#pragma once
#include <ntddk.h>

NTSTATUS
PsLookupProcessByProcessId(
	__in HANDLE ProcessId,   //进程ID
	__deref_out PEPROCESS *Process //返回的EPROCESS
);

VOID CreateProcessRoutineEx(IN HANDLE  ParentId, IN HANDLE  ProcessId, IN BOOLEAN  Create);

VOID LoadImageNotifyRoutine(__in_opt PUNICODE_STRING FullImageName, __in HANDLE ProcessId, __in PIMAGE_INFO ImageInfo);

VOID DrivrUnload(PDRIVER_OBJECT pDriverObject);

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegpath);
