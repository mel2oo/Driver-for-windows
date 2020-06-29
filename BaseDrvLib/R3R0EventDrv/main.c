#include <ntddk.h>


#define DEVICENAME				L"\\Device\\R3R0EventDrv"
#define SYMBOLICLINKNAME		L"\\DosDevices\\R3R0EventDrv"
#define EVENTNAME				L"\\BaseNamedObjects\\R3R0EventDrv"

#define CTRLCODE_BASE 0x8000
#define MYCTRL_CODE(code) \
	CTL_CODE(FILE_DEVICE_UNKNOWN,code+CTRLCODE_BASE,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTRL_PROCWATCH MYCTRL_CODE(0)

//每当系统检测到一个进程被创建而执行该驱动的回调时，我们就用该数据类型来接收
typedef struct _DEVICE_EXTENSION
{
	HANDLE hProcessHandle;	//用来保存event的handle
	PKEVENT ProcessEvent;
	HANDLE hParentId;
	HANDLE hProcessId;
	BOOLEAN bCreate;

}DEVICE_EXTENSION, *PDEVICE_EXTENSION;

//定义从R3 do buffer io中接收过来的数据结构，和R3的保持一致，方便解析与访问
typedef struct _ProcMonData
{
	HANDLE hParentId;
	HANDLE hProcessId;
	BOOLEAN BCreate;
}ProcMonData, *PProMonData;

VOID HaveProcessCreateRoutine(__in HANDLE, __in HANDLE, __in BOOLEAN);

NTSTATUS DeviceIoControl(PDEVICE_OBJECT, PIRP);

PDEVICE_OBJECT g_pDeviceObject = NULL;

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING uSymbolicLinkName = { 0x00 };
	DbgPrint("R3R0EventClient:goodbye!\n");
	RtlInitUnicodeString(&uSymbolicLinkName, SYMBOLICLINKNAME);
	IoDeleteSymbolicLink(&uSymbolicLinkName);
	IoDeleteDevice(pDriverObject->DeviceObject);
	PsSetCreateProcessNotifyRoutine(HaveProcessCreateRoutine, TRUE);
	return;
}

NTSTATUS DeviceCommon(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	pIrp->IoStatus.Information = 0L;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, 0);
	return pIrp->IoStatus.Status;

}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pDriverPath)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UNICODE_STRING uDeviceName = { 0x00 };
	UNICODE_STRING uSymbolicLinkName = { 0x00 };
	UNICODE_STRING uEventName = { 0x00 };
	PDEVICE_OBJECT pDeviceObject = NULL;
	PDEVICE_EXTENSION pDeviceExtension = NULL;
	ULONG index;

	//DbgPrint("R3R0EventClient:hello\n");

	RtlInitUnicodeString(&uDeviceName, DEVICENAME);
	RtlInitUnicodeString(&uSymbolicLinkName, SYMBOLICLINKNAME);

	ntStatus = IoCreateDevice(pDriverObject,
		sizeof(DEVICE_EXTENSION),
		&uDeviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&pDeviceObject);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("IoCreateDevice faild:%x\n", ntStatus);
		return ntStatus;
	}

	ntStatus = IoCreateSymbolicLink(&uSymbolicLinkName, &uDeviceName);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("IoCreateSymbolicLink faild:%x\n", ntStatus);
		IoDeleteDevice(pDeviceObject);
		return ntStatus;
	}

	pDeviceObject->Flags |= DO_BUFFERED_IO;

	g_pDeviceObject = pDeviceObject;

	pDeviceExtension = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;

	RtlInitUnicodeString(&uEventName, EVENTNAME);
	//创建和R3的通讯event
	pDeviceExtension->ProcessEvent = IoCreateNotificationEvent(&uEventName, &pDeviceExtension->hProcessHandle);
	//设置非信任状态
	KeClearEvent(pDeviceExtension->ProcessEvent);

	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("IoCreateNotificationEvent faild:%x\n", ntStatus);
		IoDeleteDevice(pDeviceObject);
		IoDeleteSymbolicLink(&uSymbolicLinkName);
		return ntStatus;
	}

	ntStatus = PsSetCreateProcessNotifyRoutine(HaveProcessCreateRoutine, FALSE);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("PsSetCreateProcessNotifiyRoutine faild:%x\n", ntStatus);
		IoDeleteDevice(pDeviceObject);
		IoDeleteSymbolicLink(&uSymbolicLinkName);
		return ntStatus;
	}

	for (index = 0; index < IRP_MJ_MAXIMUM_FUNCTION; index++)
	{
		pDriverObject->MajorFunction[index] = DeviceCommon;
	}
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControl;
	pDriverObject->DriverUnload = DriverUnload;

	return ntStatus;

}

VOID HaveProcessCreateRoutine(__in HANDLE ParentId, __in HANDLE ProcessId, __in BOOLEAN create)
{
	PDEVICE_EXTENSION pDeviceExtension = (PDEVICE_EXTENSION)g_pDeviceObject->DeviceExtension;
	pDeviceExtension->hParentId = ParentId;
	pDeviceExtension->hProcessId = ProcessId;
	pDeviceExtension->bCreate = create;

	KeSetEvent(pDeviceExtension->ProcessEvent, 0, FALSE);
	KeClearEvent(pDeviceExtension->ProcessEvent);
}

NTSTATUS DeviceIoControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIrpStack = NULL;
	PProMonData pProcMonData = NULL;
	ULONG uIrpInputBufferSize = 0;
	ULONG uIrpOutputBufferSize = 0;
	ULONG uIoCtrlCode;
	PDEVICE_EXTENSION pDeviceExtension;

	pProcMonData = (PProMonData)pIrp->AssociatedIrp.SystemBuffer;
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

	uIrpInputBufferSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	uIrpOutputBufferSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	uIoCtrlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;

	switch (uIoCtrlCode)
	{
	case IOCTRL_PROCWATCH:
	{
		pDeviceExtension = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
		pProcMonData->BCreate = pDeviceExtension->bCreate;
		pProcMonData->hParentId = pDeviceExtension->hParentId;
		pProcMonData->hProcessId = pDeviceExtension->hProcessId;
	}
	break;
	default:
	{
		ntStatus = STATUS_INVALID_PARAMETER;
		uIrpOutputBufferSize = 0;
	}
	break;
	}

	pIrp->IoStatus.Information = uIrpOutputBufferSize;
	pIrp->IoStatus.Status = ntStatus;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return ntStatus;
}