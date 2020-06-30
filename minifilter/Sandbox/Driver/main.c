//author tomzhou
//email:soundfuture@sohu.com

#include "precom.h"
#include "Ioctlcmd.h"
#include "main.h"


#define		DEVICE_NAME		L"\\device\\sandbox"
#define		LINK_NAME		L"\\dosDevices\\sandbox"

LIST_ENTRY g_PROCESS_LIST_ENTRYList;
FAST_MUTEX	g_PROCESS_LIST_ENTRYListLock;



//处理应用层的create()函数
NTSTATUS DispatchCreate (
	IN PDEVICE_OBJECT	pDevObj,
	IN PIRP	pIrp) 
{
	//设置IO状态信息
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	//完成IRP操作，不向下层驱动发送
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	return STATUS_SUCCESS;
}
//处理应用层的write()函数
NTSTATUS DispatchWrite (
    IN PDEVICE_OBJECT	pDevObj,
    IN PIRP	pIrp) 
{
	NTSTATUS 		status = STATUS_SUCCESS;
	PVOID 		userBuffer;
	PVOID 		drvBuffer;
	ULONG 		xferSize;
	//获得IRP堆栈的当前位置
	PIO_STACK_LOCATION pIrpStack =
		IoGetCurrentIrpStackLocation( pIrp );
	//获得当前写的长度和缓冲
	xferSize = pIrpStack->Parameters.Write.Length;
	userBuffer = pIrp->AssociatedIrp.SystemBuffer;
	drvBuffer = ExAllocatePoolWithTag(PagedPool, xferSize, 'tseT');
	if (drvBuffer == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		xferSize = 0;
	}
	//将当前缓冲中的数据写入
	RtlCopyMemory( drvBuffer, userBuffer, xferSize );
	//完成IO，填写完成状态和传输的数据长度
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = xferSize;
	//完成IRP，不向下层传递
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	return status;
}
//处理应用层的read()函数
NTSTATUS DispatchRead (
    IN PDEVICE_OBJECT	pDevObj,
    IN PIRP	pIrp) 
{
	NTSTATUS 		status = STATUS_SUCCESS;
	PVOID 		userBuffer;
	ULONG 		xferSize;
	//获取IRP堆栈的当前位置
	PIO_STACK_LOCATION pIrpStack =
		IoGetCurrentIrpStackLocation( pIrp );
	//获取传输的字节数和缓冲
	xferSize = pIrpStack->Parameters.Read.Length;
	userBuffer = pIrp->AssociatedIrp.SystemBuffer;	
	//从驱动中读数据
	RtlCopyMemory( userBuffer, L"Hello, world",
	    xferSize );
	//填写IRP中的完成状态，结束IRP操作，不向下层发送
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = xferSize;
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	return status;
}
//处理应用层的DeviceIoControl()
NTSTATUS DispatchControl(
    IN PDEVICE_OBJECT DeviceObject, 
    IN PIRP Irp 
    )
{
    	PIO_STACK_LOCATION      	irpStack;
    	PVOID                   	inputBuffer;
    	PVOID                   	outputBuffer;
    	//PVOID		    			userBuffer;
    	ULONG                   	inputBufferLength;
    	ULONG                   	outputBufferLength;
    	ULONG                   	ioControlCode;
    	NTSTATUS		     		ntstatus;
	
    	ntstatus = Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		//获取当前IRP堆栈位置
		irpStack = IoGetCurrentIrpStackLocation (Irp);
		//获得输入缓冲和长度
		inputBuffer = Irp->AssociatedIrp.SystemBuffer;
		inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
		//获得输出缓冲和长度
		outputBuffer = Irp->AssociatedIrp.SystemBuffer;
		outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
		//获取控制码
		ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
		switch (irpStack->MajorFunction)
		{
		    case IRP_MJ_CREATE:
		        break;
		    case IRP_MJ_SHUTDOWN:
		        break;
			//设备控制扩展
		    case IRP_MJ_DEVICE_CONTROL:
		 		if(IOCTL_TRANSFER_TYPE(ioControlCode) == METHOD_NEITHER) 
				{
		           	outputBuffer = Irp->UserBuffer;
		        }
				//针对不同的控制码，进行不同的操作
				switch (ioControlCode ) 
				{
					case IOCTL_XXX_YYY:
						DbgPrint("%d\n", *(ULONG *)inputBuffer);
						*(ULONG *)outputBuffer = *(ULONG *)inputBuffer + 1;
						Irp->IoStatus.Information = sizeof(ULONG);
						break;
					default:
						break;
				}
				break;
		    default:
				break;
		}
		IoCompleteRequest( Irp, IO_NO_INCREMENT );
		return ntstatus;  
}
//处理应用层的close()函数
NTSTATUS DispatchClose (
    IN PDEVICE_OBJECT	pDevObj,
    IN PIRP	pIrp) 
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	return STATUS_SUCCESS;
}

static VOID CleanPROCESS_LIST_ENTRYList()
{
	PPROCESS_LIST_ENTRY PROCESS_LIST_ENTRYEntry = NULL;
	PLIST_ENTRY tmpEntry = NULL;

	while(IsListEmpty(&g_PROCESS_LIST_ENTRYList))
	{
		tmpEntry = RemoveHeadList(&g_PROCESS_LIST_ENTRYList); 
		PROCESS_LIST_ENTRYEntry = CONTAINING_RECORD(tmpEntry, PROCESS_LIST_ENTRY, Entry);
		RemoveEntryList(tmpEntry);
		ExFreePool(PROCESS_LIST_ENTRYEntry);
	}
}
//驱动Unload（）函数
VOID DriverUnload (
    IN PDRIVER_OBJECT	pDriverObject) 
{
	UNICODE_STRING         deviceLink;
	PDEVICE_OBJECT	   	p_NextObj;

	freeIPC(); //ipc
	UnloadMiniMonitor(pDriverObject);

	p_NextObj = pDriverObject->DeviceObject;
	if (p_NextObj != NULL)
	{
		RtlInitUnicodeString( &deviceLink, LINK_NAME);
		IoDeleteSymbolicLink( &deviceLink);
		IoDeleteDevice( pDriverObject->DeviceObject );
	}
	CleanPROCESS_LIST_ENTRYList();
	return;
}

//驱动程序入口，完成各种初始化工作，创建设备对象
NTSTATUS DriverEntry (
    IN PDRIVER_OBJECT pDriverObject,
    IN PUNICODE_STRING pRegistryPath) 
{
	NTSTATUS 		ntStatus;
	PDEVICE_OBJECT 	pDevObj;
	UNICODE_STRING 	uDevName;
	UNICODE_STRING 	uLinkName;
	PROCESS_LIST_ENTRY *pPROCESS_LIST_ENTRYEntry;
	DbgPrint("Driver Load begin!\n");

	ExInitializeFastMutex( &g_PROCESS_LIST_ENTRYListLock );
	InitializeListHead(&g_PROCESS_LIST_ENTRYList);

	pPROCESS_LIST_ENTRYEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_LIST_ENTRY), 'XBBS');
	if (pPROCESS_LIST_ENTRYEntry == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(pPROCESS_LIST_ENTRYEntry, sizeof(PROCESS_LIST_ENTRY));

	wcscpy(pPROCESS_LIST_ENTRYEntry->NameBuffer, L"notepad.exe");
	InsertHeadList(&g_PROCESS_LIST_ENTRYList, &pPROCESS_LIST_ENTRYEntry->Entry);


	pPROCESS_LIST_ENTRYEntry = ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_LIST_ENTRY), 'XBBS');
	if (pPROCESS_LIST_ENTRYEntry == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(pPROCESS_LIST_ENTRYEntry, sizeof(PROCESS_LIST_ENTRY));
	
	wcscpy(pPROCESS_LIST_ENTRYEntry->NameBuffer, L"iexplore.exe");
	InsertHeadList(&g_PROCESS_LIST_ENTRYList, &pPROCESS_LIST_ENTRYEntry->Entry);


	ntStatus = initFileMonitor(pDriverObject);
	
	if(! NT_SUCCESS(ntStatus))
		return ntStatus;
	
	ntStatus = initIPC( );
	
	if(! NT_SUCCESS(ntStatus))
	{
		stopMiniMonitor( );
		return ntStatus;
	}

	//Sandbox还需要初始化？
	InitSb();

	ntStatus = startMiniMonitor( );
	
	if(! NT_SUCCESS(ntStatus))
	{
		stopMiniMonitor( );
		closeIPC( );
		return STATUS_SUCCESS;
	}

	//初始化各个例程
	pDriverObject->MajorFunction[IRP_MJ_CREATE] =
				DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] =
				DispatchClose;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] =
				DispatchWrite;
	pDriverObject->MajorFunction[IRP_MJ_READ] =
				DispatchRead;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = 
				DispatchControl;
	pDriverObject->DriverUnload	= 
				DriverUnload;

	RtlInitUnicodeString(&uDevName, DEVICE_NAME);
	//创建驱动设备
	ntStatus = IoCreateDevice( pDriverObject,
			0,//sizeof(DEVICE_EXTENSION)
			&uDevName,
			FILE_DEVICE_SANDBOX,
			0, TRUE,
			&pDevObj );
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("IoCreateDevice Failed:%x\n", ntStatus);
		return ntStatus;
	}

	pDevObj->Flags |= DO_BUFFERED_IO;
	RtlInitUnicodeString(&uLinkName, LINK_NAME);
	//创建符号链接
	ntStatus = IoCreateSymbolicLink( &uLinkName,
		    &uDevName );
	if (!NT_SUCCESS(ntStatus)) 
	{
		//STATUS_INSUFFICIENT_RESOURCES 	资源不足
		//STATUS_OBJECT_NAME_EXISTS 		指定对象名存在
		//STATUS_OBJECT_NAME_COLLISION 	对象名有冲突
		DbgPrint("IoCreateSymbolicLink Failed:%x\n", ntStatus);
		IoDeleteDevice( pDevObj );
		return ntStatus;
	}
	DbgPrint("Driver Load success!\n");
	return ntStatus;
}

