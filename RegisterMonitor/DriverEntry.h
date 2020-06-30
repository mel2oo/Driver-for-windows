#pragma once
#include <ntddk.h>

NTSTATUS ObQueryNameString(
	_In_ PVOID Object,
	_Out_writes_bytes_opt_(Length) POBJECT_NAME_INFORMATION ObjectNameInfo,
	_In_ ULONG Length,
	_Out_ PULONG ReturnLength
);

PUCHAR PsGetProcessImageFileName(PEPROCESS pEProcess);

BOOLEAN GetRegisterObjectCompletePath(PUNICODE_STRING pRegistryPath, PVOID pRegistryObject);

BOOLEAN IsProtectReg(UNICODE_STRING ustrRegPath);

NTSTATUS RegisterMonCallback(_In_ PVOID CallbackContext, _In_opt_ PVOID Argument1, _In_opt_ PVOID Argument2);

VOID DrivrUnload(PDRIVER_OBJECT pDriverObject);

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegpath);
