#include <ntddk.h>

//自己的设备名和符号链接
#define DeviceName L"\\device\\IrpHook"
#define SymbolicName L"\\dosDevices\\PIrpHook"

//要拦截的目标设备名
#define TargetDeviceName L"\\device\\SsdtHook"

#define IOCTL_BASE 0x8000
#define CTL(i) CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef NTSTATUS (*OLDDISPATCHIOCTL)(PDEVICE_OBJECT pDevObj, PIRP pIrp);
OLDDISPATCHIOCTL OldDispatchIoCtl;

VOID DriverUnload(PDRIVER_OBJECT pDriObj)
{
	UNICODE_STRING uSymbolicName = {0x00};
	NTSTATUS ntStatus = STATUS_SUCCESS;
	RtlInitUnicodeString(&uSymbolicName,SymbolicName);
	ntStatus = IoDeleteSymbolicLink(&uSymbolicName);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("IoDeleteSymbolicLink faild:0x%x!\n",ntStatus);
	}

	IoDeleteDevice(pDriObj->DeviceObject);

	return ntStatus;

}

NTSTATUS DispatchIoCommon(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp,IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DispatchIoCtl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = 0;

	DbgPrint("SsdtHook's is hooking!\n");

	IoCompleteRequest(pIrp,IO_NO_INCREMENT);

	return ntStatus;
}

VOID StartHook(PDRIVER_OBJECT pDriObj)
{
	UNICODE_STRING uDeviceName = {0x00};
	NTSTATUS ntStatus = STATUS_SUCCESS;
	DEVICE_OBJECT *pDeviceObject = NULL;
	FILE_OBJECT *pFileObject = NULL;
	PDRIVER_OBJECT pDriverObject = NULL;

	DbgPrint("Start Irp hook!\n");
	RtlInitUnicodeString(&uDeviceName, TargetDeviceName);
	
	ntStatus = IoGetDeviceObjectPointer(&uDeviceName
		, FILE_READ_DATA
		, &pFileObject
		, &pDeviceObject);
	if (!NT_SUCCESS(ntStatus) || (PDEVICE_OBJECT)&pDeviceObject == NULL)
	{
		DbgPrint("IoGetDeviceObjectPointer faild:0x%x!\n",ntStatus);
		return;
	}

	pDriverObject = pDeviceObject->DriverObject;
	OldDispatchIoCtl = pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	
	InterlockedExchange(&pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],(ULONG)DispatchIoCtl);

	DbgPrint("finish Irp hook!\n");
	return;

}

NTSTATUS DriverEntry(__in PDRIVER_OBJECT pDriObj, __in PUNICODE_STRING pDriPath)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UNICODE_STRING uDeviceName = {0x00};
	UNICODE_STRING uSymbolicName = {0x00};
	DEVICE_OBJECT DeviceObject = {0x00};
	ULONG majorIndex;
	RtlInitUnicodeString(&uDeviceName,DeviceName);
	ntStatus = IoCreateDevice(pDriObj
	,0
	,&uDeviceName
	,FILE_DEVICE_UNKNOWN
	,0
	,FALSE
	,&DeviceObject);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("IoCreateDevice faild:0x%x!\n",ntStatus);
		goto ret;
	}

	DeviceObject.Flags |= DO_BUFFERED_IO;

	RtlInitUnicodeString(&uSymbolicName,SymbolicName);
	ntStatus = IoCreateSymbolicLink(&uSymbolicName,&uDeviceName);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("IoCreateSymbolicSymbolic faild:0x%x!\n",ntStatus);
		goto ret;
	}

	for (majorIndex = 0; majorIndex < IRP_MJ_MAXIMUM_FUNCTION; ++majorIndex)
	{
		pDriObj->MajorFunction[majorIndex] = DispatchIoCommon;
	}

	pDriObj->DriverUnload = DriverUnload;

	StartHook(pDriObj);

	ret:
	return ntStatus;

}