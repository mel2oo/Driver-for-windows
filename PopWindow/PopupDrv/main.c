//author tomzhou
//email:soundfuture@sohu.com

#include <ntddk.h>
#include <ntstrsafe.h>
#include "Ioctlcmd.h"
#include "main.h"

#define		DEVICE_NAME		L"\\device\\PopupDrv"
#define		LINK_NAME		L"\\dosDevices\\PopupDrv"


LIST_ENTRY g_OperList;
ERESOURCE  g_OperListLock;

LIST_ENTRY g_WaitList;
ERESOURCE  g_WaitListLock;

LIST_ENTRY g_PendingIrpList;
ERESOURCE  g_PendingIrpListLock;

ULONG g_ulCurrentWaitID = 0;

VOID __stdcall LockWrite(ERESOURCE *lpLock)
{
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(lpLock, TRUE);
}


VOID __stdcall UnLockWrite(ERESOURCE *lpLock)
{
    ExReleaseResourceLite(lpLock);
    KeLeaveCriticalRegion();
}


VOID __stdcall LockRead(ERESOURCE *lpLock)
{
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(lpLock, TRUE);
}


VOID __stdcall LockReadStarveWriter(ERESOURCE *lpLock)
{
    KeEnterCriticalRegion();
    ExAcquireSharedStarveExclusive(lpLock, TRUE);
}


VOID __stdcall UnLockRead(ERESOURCE *lpLock)
{
    ExReleaseResourceLite(lpLock);
    KeLeaveCriticalRegion();
}


VOID __stdcall InitLock(ERESOURCE *lpLock)
{
    ExInitializeResourceLite(lpLock);
}

VOID __stdcall DeleteLock(ERESOURCE *lpLock)
{
    ExDeleteResourceLite(lpLock);
}

VOID __stdcall InitList(LIST_ENTRY *list)
{
    InitializeListHead(list);
}

VOID
CommonIrpCancel(
				IN PDEVICE_OBJECT DeviceObject,
				IN PIRP Irp
				)
{
	KIRQL				CancelOldIrql	= Irp->CancelIrql;
	
	IoReleaseCancelSpinLock(DISPATCH_LEVEL);
	KeLowerIrql(CancelOldIrql);

	LockWrite(&g_PendingIrpListLock);
	RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
	UnLockWrite(&g_PendingIrpListLock);
	
	Irp->IoStatus.Status = STATUS_CANCELLED;
	Irp->IoStatus.Information = 0;
	
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

VOID
PendingIrpToList(PIRP pIrp, PLIST_ENTRY pIrpList, PDRIVER_CANCEL pfnCancelRoutine)
{
	InsertTailList(pIrpList, &pIrp->Tail.Overlay.ListEntry);
	IoMarkIrpPending(pIrp);
	IoSetCancelRoutine(pIrp, pfnCancelRoutine);//R3:CancelIo(handle),//CancelIo from r3  or IoCancelIrp to call  
}

//处理应用层的read()函数
NTSTATUS DispatchRead (
    IN PDEVICE_OBJECT	pDevObj,
    IN PIRP	lpIrp) 
{
	NTSTATUS			ntStatus		= STATUS_SUCCESS;
	ULONG				ulLength		= 0;
	PIO_STACK_LOCATION	lpIrpStack		= IoGetCurrentIrpStackLocation(lpIrp);
	OP_INFO				*lpOpInfoEntry	= NULL;
	LIST_ENTRY			*lpOpInfoList	= NULL;
	
	if (lpIrpStack->Parameters.Read.Length < sizeof(RING3_OP_INFO))
	{
		ntStatus = STATUS_INVALID_PARAMETER;
		ulLength = 0;
		goto Completed;
	}
	
	LockWrite(&g_OperListLock);
	
	if (IsListEmpty(&g_OperList) == TRUE)
	{
		UnLockWrite(&g_OperListLock);
		
		LockWrite(&g_PendingIrpListLock);
		PendingIrpToList(lpIrp, &g_PendingIrpList, CommonIrpCancel);
		UnLockWrite(&g_PendingIrpListLock);
	
		goto Pended;
	}
	
	lpOpInfoList = g_OperList.Flink;
	lpOpInfoEntry = CONTAINING_RECORD(lpOpInfoList, OP_INFO, m_List);
	RemoveEntryList(lpOpInfoList);
	UnLockWrite(&g_OperListLock);
	
	RtlCopyMemory(lpIrp->AssociatedIrp.SystemBuffer, lpOpInfoEntry, sizeof(RING3_OP_INFO));
	ntStatus = STATUS_SUCCESS;
	ulLength = sizeof(RING3_OP_INFO);
	
	ExFreePool(lpOpInfoEntry);
	
Completed:
	
	lpIrp->IoStatus.Status = ntStatus;
	lpIrp->IoStatus.Information = ulLength;
	IoCompleteRequest(lpIrp, IO_NO_INCREMENT);
	return ntStatus;
	
Pended:
	return STATUS_PENDING;
}



NTSTATUS  GetProcessFullNameByPid(HANDLE nPid, PUNICODE_STRING  FullPath)
{

	HANDLE               hFile = NULL;
	ULONG                nNeedSize = 0;
	NTSTATUS             nStatus = STATUS_SUCCESS;
	NTSTATUS             nDeviceStatus = STATUS_DEVICE_DOES_NOT_EXIST;
	PEPROCESS            Process = NULL;
	KAPC_STATE           ApcState = { 0 };
	PVOID                lpBuffer = NULL;
	OBJECT_ATTRIBUTES	 ObjectAttributes = { 0 };
	IO_STATUS_BLOCK      IoStatus = { 0 };
	PFILE_OBJECT         FileObject = NULL;
	PFILE_NAME_INFORMATION FileName = NULL;
	WCHAR                FileBuffer[MAX_PATH] = { 0 };
	DECLARE_UNICODE_STRING_SIZE(ProcessPath, MAX_PATH);
	DECLARE_UNICODE_STRING_SIZE(DosDeviceName, MAX_PATH);

	PAGED_CODE();

	nStatus = PsLookupProcessByProcessId(nPid, &Process);
	if (NT_ERROR(nStatus))
	{
		KdPrint(("%s error PsLookupProcessByProcessId.\n", __FUNCTION__));
		return nStatus;
	}



	__try
	{

		KeStackAttachProcess(Process, &ApcState);

		nStatus = ZwQueryInformationProcess(
			NtCurrentProcess(),
			ProcessImageFileName,
			NULL,
			NULL,
			&nNeedSize
			);

		if (STATUS_INFO_LENGTH_MISMATCH != nStatus)
		{
			KdPrint(("%s NtQueryInformationProcess error.\n", __FUNCTION__));
			nStatus = STATUS_MEMORY_NOT_ALLOCATED;
			__leave;

		}

		lpBuffer = ExAllocatePoolWithTag(NonPagedPool, nNeedSize, 'GetP');
		if (lpBuffer == NULL)
		{
			KdPrint(("%s ExAllocatePoolWithTag error.\n", __FUNCTION__));
			nStatus = STATUS_MEMORY_NOT_ALLOCATED;
			__leave;
		}

		nStatus = ZwQueryInformationProcess(
			NtCurrentProcess(),
			ProcessImageFileName,
			lpBuffer,
			nNeedSize,
			&nNeedSize
			);

		if (NT_ERROR(nStatus))
		{
			KdPrint(("%s NtQueryInformationProcess error2.\n", __FUNCTION__));
			__leave;
		}

		RtlCopyUnicodeString(&ProcessPath, (PUNICODE_STRING)lpBuffer);
		InitializeObjectAttributes(
			&ObjectAttributes,
			&ProcessPath,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL
			);

		nStatus = ZwCreateFile(
			&hFile,
			FILE_READ_ATTRIBUTES,
			&ObjectAttributes,
			&IoStatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			0,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
			NULL,
			0
			);

		if (NT_ERROR(nStatus))
		{
			hFile = NULL;
			__leave;
		}

		nStatus = ObReferenceObjectByHandle(
			hFile,
			NULL,
			*IoFileObjectType,
			KernelMode,
			(PVOID*)&FileObject,
			NULL
			);

		if (NT_ERROR(nStatus))
		{
			FileObject = NULL;
			__leave;
		}

		FileName = (PFILE_NAME_INFORMATION)FileBuffer;

		nStatus = ZwQueryInformationFile(
			hFile,
			&IoStatus,
			FileName,
			sizeof(WCHAR)*MAX_PATH,
			FileNameInformation
			);

		if (NT_ERROR(nStatus))
		{
			__leave;
		}

		if (FileObject->DeviceObject == NULL)
		{
			nDeviceStatus = STATUS_DEVICE_DOES_NOT_EXIST;
			__leave;
		}

		nDeviceStatus = RtlVolumeDeviceToDosName(FileObject->DeviceObject, &DosDeviceName);

	}
	__finally
	{
		if (NULL != FileObject)
		{
			ObDereferenceObject(FileObject);
		}

		if (NULL != hFile)
		{
			ZwClose(hFile);
		}

		if (NULL != lpBuffer)
		{
			ExFreePool(lpBuffer);
		}

		KeUnstackDetachProcess(&ApcState);


	}

	if (NT_SUCCESS(nStatus))
	{
		RtlInitUnicodeString(&ProcessPath, FileName->FileName);
		if (NT_SUCCESS(nDeviceStatus))
		{
			RtlCopyUnicodeString(FullPath, &DosDeviceName);
			RtlUnicodeStringCat(FullPath, &ProcessPath);
		}
		else
		{
			RtlCopyUnicodeString(FullPath, &ProcessPath);
		}
	}


	return nStatus;
}

WAIT_LIST_ENTRY*
FindWaitEntryByID(PLIST_ENTRY pListHead, ULONG ulWaitID)
{
    PLIST_ENTRY			pList		= NULL;
    WAIT_LIST_ENTRY		*pEntry	= NULL;
	
    for (pList = pListHead->Flink; pList != pListHead; pList = pList->Flink)
    {
        pEntry = CONTAINING_RECORD(pList, WAIT_LIST_ENTRY, m_List);
        if (pEntry->m_ulWaitID == ulWaitID)
        {
            return pEntry;
        }
    }
    return NULL;
}

ULONG MakeWaitID()
{
    InterlockedIncrement(&g_ulCurrentWaitID);
    return g_ulCurrentWaitID;
}

BOOLEAN
CompletePendingIrp(LIST_ENTRY* pIrpListHead, OP_INFO* pOpInfo)
{
	LIST_ENTRY			*lpIrpList	= NULL;
	PIRP				lpIrp		= NULL;
	BOOLEAN				bFound		= FALSE;
	BOOLEAN				bReturn		= FALSE;
	
	if (IsListEmpty(pIrpListHead) == TRUE)
	{
		return bReturn;
	}
	
	for (lpIrpList = pIrpListHead->Flink; lpIrpList != pIrpListHead; lpIrpList = lpIrpList->Flink)
	{
		lpIrp = CONTAINING_RECORD(lpIrpList, IRP, Tail.Overlay.ListEntry);
		if (IoSetCancelRoutine(lpIrp, NULL))//returns the previous value of Irp->CancelRoutine. no Cancel routine, or cancellation in progress, returns NULL.
		{
			RemoveEntryList(lpIrpList);
			bFound = TRUE;
			break;
		}
	}
	
	if (bFound == FALSE)
	{
		return bReturn;
	}
	
	RtlCopyMemory(lpIrp->AssociatedIrp.SystemBuffer, pOpInfo, sizeof(RING3_OP_INFO));
	
	lpIrp->IoStatus.Information = sizeof(RING3_OP_INFO);
	lpIrp->IoStatus.Status = STATUS_SUCCESS;
	
	IoCompleteRequest(lpIrp, IO_NO_INCREMENT);
	bReturn = TRUE;
	
	return bReturn;
}

R3_RESULT __stdcall GetResultFromUser()
{
    R3_RESULT			NotifyResult	= R3Result_Pass;
    BOOLEAN				bSuccess		=  FALSE;
    NTSTATUS			Status			= STATUS_SUCCESS;
    LARGE_INTEGER		WaitTimeOut		= {0};
    OP_INFO				*lpNewOpInfo	= NULL;
    WAIT_LIST_ENTRY		*lpNewWaitEntry = NULL;
	UNICODE_STRING     m_processPath = {0};
    ULONG_PTR ulPtr = 0;
 
    lpNewOpInfo = (OP_INFO*)ExAllocatePool(PagedPool, sizeof(OP_INFO));

    if (lpNewOpInfo == NULL)
    {
        return NotifyResult;
    }

    //设置事件相关的数据，发送给R3，比如进程ID，名字，路径，以及具体操作（创建，修改，删除）等等
	//当然，这里，我们只是简单的捕捉了进程的ID或者名字等
    ulPtr = (ULONG_PTR)PsGetCurrentProcessId();
    lpNewOpInfo->m_ulProcessID = (ULONG_PTR)ulPtr;
	//DbgBreakPoint();
	
	m_processPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, 256 * sizeof(WCHAR), 'HTAP');
	m_processPath.MaximumLength = 256;
	m_processPath.Length = 0;

	GetProcessFullNameByPid(ulPtr, &m_processPath);
	RtlCopyMemory(lpNewOpInfo->m_ProcessName, m_processPath.Buffer, m_processPath.Length);
	RtlFreeUnicodeString(&m_processPath);

    lpNewOpInfo->m_ulWaitID = MakeWaitID();//区别不同事件的ID


    lpNewWaitEntry = (WAIT_LIST_ENTRY*)ExAllocatePool(NonPagedPool, sizeof(WAIT_LIST_ENTRY));
    if (lpNewWaitEntry == NULL)
    {
        goto End;
    }

    lpNewWaitEntry->m_ulWaitID = lpNewOpInfo->m_ulWaitID;
    KeInitializeEvent(&lpNewWaitEntry->m_ulWaitEvent, SynchronizationEvent, FALSE);
	
    // 插入等待队列，等待R3下发结果
    LockWrite(&g_WaitListLock);
	InsertTailList(&g_WaitList, &lpNewWaitEntry->m_List);
    UnLockWrite(&g_WaitListLock);



    LockWrite(&g_PendingIrpListLock);
    bSuccess = CompletePendingIrp(&g_PendingIrpList, lpNewOpInfo);//查看是否有未完成的pendingIRP，直接将该OperInfo传给R3
    UnLockWrite(&g_PendingIrpListLock);

	if (bSuccess == FALSE)	//完成pending irp失败，将lpNewOpInfo插入operlist
	{
        LockWrite(&g_OperListLock);
        InsertTailList(&g_OperList, &lpNewOpInfo->m_List); //插入OperList,等待R3来读取
        UnLockWrite(&g_OperListLock);
   
        lpNewOpInfo = NULL;
	}

	// 等40秒，环3是30秒超时
    WaitTimeOut.QuadPart = -40 * 10000000;
	Status = KeWaitForSingleObject(&lpNewWaitEntry->m_ulWaitEvent, 
		Executive, KernelMode, FALSE, &WaitTimeOut);//等待R3下发允许或阻止操作

    LockWrite(&g_WaitListLock);
    RemoveEntryList(&lpNewWaitEntry->m_List);
    UnLockWrite(&g_WaitListLock);

    if (Status != STATUS_TIMEOUT)
    {
        if (lpNewWaitEntry->m_bBlocked == TRUE)
        {
            NotifyResult = R3Result_Block;
        }
        else
        {
            NotifyResult = R3Result_Pass;
        }
    }
    else
    {
        NotifyResult =  R3Result_DefaultNon;
    }

End:
    if (lpNewWaitEntry != NULL)
    {
        ExFreePool(lpNewWaitEntry);
    }
    if (lpNewOpInfo != NULL)
    {
        ExFreePool(lpNewOpInfo);
    }
    return NotifyResult;
}


//处理应用层的DeviceIoControl()
NTSTATUS DispatchControl(
    IN PDEVICE_OBJECT DeviceObject, 
    IN PIRP Irp 
    )
{
    PIO_STACK_LOCATION      	lpIrpStack			= NULL;
    PVOID                   	inputBuffer			= NULL;
    PVOID                   	outputBuffer		= NULL;
    ULONG                   	inputBufferLength	= 0;
    ULONG                   	outputBufferLength	= 0;
    ULONG                   	ioControlCode		= 0;
    NTSTATUS		     		ntStatus			= STATUS_SUCCESS;
	
    ntStatus = Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	//获取当前IRP堆栈位置
	lpIrpStack = IoGetCurrentIrpStackLocation (Irp);
	//获得输入缓冲和长度
	inputBuffer = Irp->AssociatedIrp.SystemBuffer;
	inputBufferLength = lpIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	//获得输出缓冲和长度
	outputBuffer = Irp->AssociatedIrp.SystemBuffer;
	outputBufferLength = lpIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	//获取控制码
	ioControlCode = lpIrpStack->Parameters.DeviceIoControl.IoControlCode;
		
	switch (ioControlCode ) 
	{
		case IOCTL_SEND_RESULT_TO_R0://R3向内核传递弹窗结果，将对应的WaitID事件设置用户选择结果
		{
				RING3_REPLY			*lpReply		= NULL;
				WAIT_LIST_ENTRY		*lpWaitEntry	= NULL;
							
				if (lpIrpStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(RING3_REPLY))
				{
						Irp->IoStatus.Information = 0;
						Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
						break;
				}
				lpReply = (RING3_REPLY*)Irp->AssociatedIrp.SystemBuffer;
							
				LockWrite(&g_WaitListLock);
				lpWaitEntry = FindWaitEntryByID(&g_WaitList, lpReply->m_ulWaitID);//根据WaitID，找到对应的拦截事件
							
				if (lpWaitEntry != NULL)
				{
						lpWaitEntry->m_bBlocked = lpReply->m_ulBlocked;
						KeSetEvent(&lpWaitEntry->m_ulWaitEvent, 0, FALSE);//设置EVENT事件，唤醒GetResultFromUser()里的等待事件
				}
							
				UnLockWrite(&g_WaitListLock);
							
				Irp->IoStatus.Information = 0;
				ntStatus = Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		break;

		case IOCTL_XXX_ATTACK://攻击拦截模仿
		{
				R3_RESULT notifyResult = R3Result_DefaultNon; 

							
				notifyResult = GetResultFromUser();//从R3获得弹框结果，是阻止还是放过
				if (notifyResult == R3Result_Block)
				{
						DbgPrint("阻止\n");
						*(ULONG *)outputBuffer = 0;
						ntStatus = STATUS_SUCCESS;
				}
				else if (notifyResult == R3Result_Pass)
				{
						DbgPrint("允许\n");
						*(ULONG *)outputBuffer = 1;
						ntStatus = STATUS_SUCCESS;
				}
				else
				{
						DbgPrint("超时允许\n");
						*(ULONG *)outputBuffer = 1;
						ntStatus = STATUS_SUCCESS;
				}

		}
		Irp->IoStatus.Information = sizeof(ULONG);
		Irp->IoStatus.Status = ntStatus;
		break;

		default:
		break;
	}
		
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return ntStatus;  
}

//驱动Unload（）函数
VOID DriverUnload (
    IN PDRIVER_OBJECT	pDriverObject) 
{
	UNICODE_STRING         deviceLink = {0};

	RtlInitUnicodeString( &deviceLink, LINK_NAME);
	IoDeleteSymbolicLink( &deviceLink);
	IoDeleteDevice( pDriverObject->DeviceObject );

	return;
}

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

//驱动程序入口，完成各种初始化工作，创建设备对象
NTSTATUS DriverEntry (
    IN PDRIVER_OBJECT pDriverObject,
    IN PUNICODE_STRING pRegistryPath) 
{
	NTSTATUS 		status		= STATUS_SUCCESS;
	PDEVICE_OBJECT 	pDevObj		= NULL;
	UNICODE_STRING 	uDevName	= {0};
	UNICODE_STRING 	uLinkName	= {0};
	DbgPrint("Driver Load begin!\n");

	InitLock(&g_OperListLock);
	InitLock(&g_WaitListLock);
	InitLock(&g_PendingIrpListLock);
	
	InitList(&g_OperList);
	InitList(&g_WaitList);
	InitList(&g_PendingIrpList);


	//初始化各个例程

	pDriverObject->MajorFunction[IRP_MJ_CREATE] =
				DispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] =
				DispatchClose;
	pDriverObject->MajorFunction[IRP_MJ_READ] =
				DispatchRead;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = 
				DispatchControl;
	pDriverObject->DriverUnload	= 
				DriverUnload;

	RtlInitUnicodeString(&uDevName, DEVICE_NAME);
	//创建驱动设备
	status = IoCreateDevice( pDriverObject,
			0,//sizeof(DEVICE_EXTENSION)
			&uDevName,
			FILE_DEVICE_UNKNOWN,
			0, FALSE,
			&pDevObj );
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IoCreateDevice Failed:%x\n", status);
		return status;
	}

	pDevObj->Flags |= DO_BUFFERED_IO;
	RtlInitUnicodeString(&uLinkName, LINK_NAME);
	//创建符号链接
	status = IoCreateSymbolicLink( &uLinkName, &uDevName );
	if (!NT_SUCCESS(status)) 
	{
		//STATUS_INSUFFICIENT_RESOURCES 	资源不足
		//STATUS_OBJECT_NAME_EXISTS 		指定对象名存在
		//STATUS_OBJECT_NAME_COLLISION 	对象名有冲突
		DbgPrint("IoCreateSymbolicLink Failed:%x\n", status);
		IoDeleteDevice( pDevObj );
		return status;
	}
	DbgPrint("Driver Load success!\n");
	return status;
}

