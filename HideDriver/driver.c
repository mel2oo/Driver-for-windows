#include "driver.h"
#include "hide.h"

NTSTATUS ControlDispatchRoutine(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	KdPrint(("Enter ControlDispatchRoutine\n"));
	NTSTATUS status = STATUS_SUCCESS;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;	
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	KdPrint(("Leave ControlDispatchRoutine\n"));
	return status;
}

NTSTATUS DispatchRoutine(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	KdPrint(("Enter DispatchRoutine\n"));
	NTSTATUS status = STATUS_SUCCESS;
	// Íê³ÉIRP
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;	
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	KdPrint(("Leave DispatchRoutine\n"));
	return status;
}

VOID Unload(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING strLink;

	RtlInitUnicodeString(&strLink, HIDE_LINK_NAME);

	IoDeleteSymbolicLink(&strLink);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegisterPath)
{
	NTSTATUS status;
	UNICODE_STRING DevName, SymLink;
	PDEVICE_OBJECT pDevObj;

	KdBreakPoint();

	RtlInitUnicodeString(&DevName, HIDE_DEVICE_NAME);

	status = IoCreateDevice(pDriverObject, 0, &DevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	RtlInitUnicodeString(&SymLink, HIDE_LINK_NAME);

	status = IoCreateSymbolicLink(&SymLink, &DevName);

	pDevObj->Flags |= DO_BUFFERED_IO;

	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		return status;
	}

	for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriverObject->MajorFunction[i] = DispatchRoutine;
	}

	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ControlDispatchRoutine;
	pDriverObject->DriverUnload = Unload;

	g_pDriverObject = pDriverObject;

	IoRegisterDriverReinitialization(pDriverObject, Reinitialize, NULL);

	return status;
}