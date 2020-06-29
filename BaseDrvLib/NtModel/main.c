#include <ntddk.h>

//定义设备对象名称和符号链接,注意，这里的字符串要用宽字节字符串，即字符串前加L
//注意，设备对象名称和符号链接名称要一致
#define DEVICE_NAME L"\\device\\NtModel"
#define LINK_NAME L"\\dosdevices\\NtModel"

//定义DispatchIocontrol函数接收r3发来的通讯方式控制码
#define IOCTRL_BASE 0x800

//这里(i)和宏定义的名称中间不能有空格，自己挖的坑。。。
#define MYIOCTRL_CODE(i) \
	CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE+i, METHOD_BUFFERED,FILE_ANY_ACCESS)

#define CTL_HELLO MYIOCTRL_CODE(0)
#define CTL_PRINT MYIOCTRL_CODE(1)
#define CTL_BYE MYIOCTRL_CODE(2)

//定义r3发来IRP时的分发处理函数
//r3发来的IRP被驱动拦截，驱动在内核中创建了一个设备对象（这里是在驱动的入口函数中被创建的），
//这个设备对象就是第一个参数
//r3就是将IRP发送给这个设备对象的

NTSTATUS DispatchCommon(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	//设置pIrp，给R3返回处理状态
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	//给r3返回额外信息，比如处理r3的read分发函数时，这个地方表示实际读取了多少个字节给r3
	pIrp->IoStatus.Information = 0;

	//这里别忘了执行表示处理此次IRP请求结束的函数
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	//返回给IO管理器的状态码
	return STATUS_SUCCESS;
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchRead(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	//由于是基于buffer的io，所以获取buffer的地址在IRP头部，而buffer的长度要在当前设备在IRP栈中获取对应的层
	//中获取
	PVOID pReadBuffer			= NULL;
	ULONG uReadLength			= 0;
	//获取当前设备在IRP栈中所在的位置，暂且说是当前设备在IRP栈中的栈帧
	PIO_STACK_LOCATION pStack	= NULL;

	//定义写入长度，这个长度不是根据buffer的长度或驱动要写入的长度为基准，而是取这两者较小值
	ULONG uMin					= 0;
	pReadBuffer = pIrp->AssociatedIrp.SystemBuffer;

	//获取栈帧
	pStack = IoGetCurrentIrpStackLocation(pIrp);

	//这样获取buffer的长度
	uReadLength = pStack->Parameters.Read.Length;

	uMin = (wcslen(L"Hello world") + 1) * sizeof(WCHAR) > uReadLength ? uReadLength :
		(wcslen(L"Hello world") + 1) * sizeof(WCHAR);

	//向buffer中写入r3要读取的数据
	RtlCopyMemory(pReadBuffer, L"Hello world", uMin);

	//写完之后，同样的，设置返回给r3的处理结果
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = uMin;

	//同样要执行结束函数
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DispatchWrite(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	//还是要定义buffer、长度、栈
	PVOID pWriteBuffer			= NULL;
	ULONG uWriteLength			= 0;
	PIO_STACK_LOCATION pStack	= NULL;

	//定义一块内核堆来存放r3发来要写入的数据
	PVOID pBuffer				= NULL;

	pWriteBuffer = pIrp->AssociatedIrp.SystemBuffer;
	pStack = IoGetCurrentIrpStackLocation(pIrp);
	uWriteLength = pStack->Parameters.Write.Length;

	//使用函数ExallocatePoolWithTag来分配一块内核堆
	//第一个参数，是指定分配的内核堆是分页内存，在r0中，只有处于PASSIVE级别的函数可以使用分页内存，
	//在IRP的分发函数中，所有分发函数级别都处于PASSIVE级别
	//另外一种是NonPagePool，非分页内存，这种内存使用速度快而且安全，出问题的几率很低，
	//但是长度有限，使用时，尽量避免使用非分页内存
	pBuffer = ExAllocatePoolWithTag(PagedPool, uWriteLength, 'TSET');

	if (pBuffer == NULL)
	{
		pIrp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		pIrp->IoStatus.Information = 0;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		DbgPrint("ExAllocatePoolWithTag failed\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	memset(pBuffer, 0x00, uWriteLength);

	RtlCopyMemory(pBuffer, pWriteBuffer, uWriteLength);

	//释放从内核堆申请的内存
	ExFreePool(pBuffer);
	pBuffer = NULL;//这里别忘了。。。
	//向r3返回状态
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = uWriteLength;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	//返回给IO管理器
	return STATUS_SUCCESS;
}

NTSTATUS DispatchClean(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = 0;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchIocontrol(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	PVOID inputBuffer			= NULL;
	PVOID outputBuffer			= NULL;
	ULONG inputLength			= 0;
	ULONG outputLength			= 0;
	PIO_STACK_LOCATION pStack	= NULL;
	ULONG uIocontrolCode		= 0;

	inputBuffer = outputBuffer = pIrp->AssociatedIrp.SystemBuffer;
	pStack = IoGetCurrentIrpStackLocation(pIrp);
	inputLength = pStack->Parameters.DeviceIoControl.InputBufferLength;
	outputLength = pStack->Parameters.DeviceIoControl.OutputBufferLength;
	uIocontrolCode = pStack->Parameters.DeviceIoControl.IoControlCode;

	switch (uIocontrolCode)
	{
	case CTL_HELLO:
		DbgPrint("hello iocontrol\n");
		break;
	case CTL_PRINT:
		DbgPrint("%ws\n", inputBuffer);
		break;
	case CTL_BYE:
		DbgPrint("GoodBye iocontrol\n");
		break;
	default:
		DbgPrint("unknow iocontrol\n");
		break;
	}


	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//驱动卸载函数
VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	//在驱动卸载函数里要清理符号链接、设备对象
	UNICODE_STRING uLinkName = { 0 };
	RtlInitUnicodeString(&uLinkName, LINK_NAME);
	IoDeleteSymbolicLink(&uLinkName);

	IoDeleteDevice(pDriverObject->DeviceObject);

	DbgPrint("Driver unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	//.c文件定义变量要在函数的最前面，否则编译会出错
//将设备对象名称、符号链接名称的宽字节字符串转换成unicode编码的字符串
	UNICODE_STRING uDeviceName		= { 0 };
	UNICODE_STRING uLinkName		= { 0 };
	//定义各个分发函数调用后的返回值,32位整数，0为成功
	NTSTATUS ntStatus				= 0;
	ULONG i							= 0;

	//定义设备对象指针,用来接收下面的iocreate创建的设备对象
	PDEVICE_OBJECT pDeviceObject	= NULL;

	DbgPrint("Load driver begin\n");

	//初始化设备对象名和符号链接
	RtlInitUnicodeString(&uDeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&uLinkName, LINK_NAME);

	//创建设备对象
	ntStatus = IoCreateDevice(pDriverObject, 0, &uDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);

	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("IoCreateDevice faild:%x\n", ntStatus);
		return ntStatus;
	}

	//指定r3和r0的通讯方式
	pDeviceObject->Flags |= DO_BUFFERED_IO;

	//创建符号链接
	ntStatus = IoCreateSymbolicLink(&uLinkName, &uDeviceName);
	if (!NT_SUCCESS(ntStatus))
	{
		//注意，这里如果出错，不能向上面那样直接退出，因为上面的设备对象已经被创建
		//要在这里对设备对象进行清理
		IoDeleteDevice(pDeviceObject);
		DbgPrint("IoCreateSymbolicLink failed: %x\n", ntStatus);
		return ntStatus;
	}

	//初始化所有分发函数为DispatchCommon
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
	{
		pDriverObject->MajorFunction[i] = DispatchCommon;
	}

	//拦截create、read、write、clean、close、iocontrol的分发函数
	pDriverObject->MajorFunction[IRP_MJ_CREATE]			= DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_READ]			= DispatchRead;
	pDriverObject->MajorFunction[IRP_MJ_CLEANUP]		= DispatchClean;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE]			= DispatchClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIocontrol;

	//别忘了驱动卸载函数
	pDriverObject->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;
}