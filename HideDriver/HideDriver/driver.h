#ifndef DRIVER_H
#define DRIVER_H

#include <ntifs.h>

#define		HIDE_DEVICE_NAME	L"\\Device\\HideDriver"
#define		HIDE_LINK_NAME		L"\\DosDevices\\HideDriver"

NTSTATUS ControlDispatchRoutine(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
NTSTATUS DispatchRoutine(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);

VOID Unload(PDRIVER_OBJECT pDriverObject);

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegisterPath);

#endif
