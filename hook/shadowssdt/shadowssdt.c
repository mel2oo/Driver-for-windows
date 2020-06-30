#include <ntifs.h>
#include <ntddk.h>
#include <WinDef.h>
#include <ntstrsafe.h>

#define DeviceName L"\\device\\ShadowSSDT"
#define SymbolicName L"\\dosDevices\\ShadowSSDT"

#define SystemHandleInformation 16
#define ObjectNameInformation 1
 
#pragma pack(1)
typedef struct ServiceDescriptorTable
{
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
}ServiceDescriptorTableEntry_t,*PServiceDescriptorTableEntry_t;
#pragma pack()

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
}SYSTEM_HANDLE_INFORMATION,*PSYSTEM_HANDLE_INFORMATION;

//定义全局句柄表的结构
typedef struct _SYSTEM_HANDLE_INFORMATION_EX 
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_INFORMATION Information[1];
}SYSTEM_HANDLE_INFORMATION_EX,*PSYSTEM_HANDLE_INFORMATION_EX;


__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;
#define SYSTEMSERVICE(_function) KeServiceTableBase.ServiceTableBase[*(PULONG)((PUCHAR)_function + 1)]
#define SDT SYSTEMSERVICE
#define KSSDT KeServiceDescriptorTable

HANDLE GetCrsPid(VOID);

NTKERNELAPI NTSTATUS ZwQuerySystemInformation(IN ULONG SystemInformationClass
											  ,OUT PVOID SystemInformation
											  ,IN ULONG SystemInformationLength
											  ,OUT PULONG lpOutputLength OPTIONAL);

extern NTSTATUS ZwQueryInformationProcess(HANDLE ProcessHandle,
										  PROCESSINFOCLASS ProcessInfoClass,
										  PVOID ProcessInformation,
										  ULONG ProcessInformationLength,
										  PULONG ReturnLength);

//shadow ssdt表结构和ssdt表结构是一样的?
ServiceDescriptorTableEntry_t *g_lpKeServiceTableBaseShadow = NULL;

BOOL New_NtGdiBitBlt(IN HDC hdcDes
					   ,IN int xDes
					   ,IN int yDes
					   ,IN int cxDes
					   ,IN int cyDes
					   ,IN HDC hdcSrc
					   ,IN int xSrc
					   ,IN int ySrc
					   ,IN int cxSrc
					   ,IN int cySrc
					   ,IN DWORD dwRop
					   ,IN DWORD dwBackColor
					   ,IN ULONG fl);

BOOL New_NtGdiStretChBlt(IN HDC hdcDes
						 ,IN int xDes
						 ,IN int yDes
						 ,IN int cxDes
						 ,IN int cyDes
						 ,IN HDC hdcSrc
						 ,IN int xSrc
						 ,IN int ySrc
						 ,IN int cxSrc
						 ,IN int cySrc
						 ,IN DWORD dwRop
						 ,IN DWORD dwBackColor);

NTSTATUS New_NtUserHwndQueryRedirectoryInfo(ULONG param1, ULONG param2, ULONG param3, ULONG param4);



typedef BOOL (NTAPI*NTGDIBITBLT)(IN HDC hdcDes
						  ,IN int xDes
						  ,IN int yDes
						  ,IN int cxDes
						  ,IN int cyDes
						  ,IN HDC hdcSrc
						  ,IN int xSrc
						  ,IN int ySrc
						  ,IN int cxSrc
						  ,IN int cySrc
						  ,IN DWORD dwRop
						  ,IN DWORD dwBackColor
						  ,IN ULONG fl);

typedef BOOL (NTAPI *NTGDISTRETCHBLT)(IN HDC hdcDes
									 ,IN int xDes
									 ,IN int yDes
									 ,IN int cxDes
									 ,IN int cyDes
									 ,IN HDC hdcSrc
									 ,IN int xSrc
									 ,IN int ySrc
									 ,IN int cxSrc
									 ,IN int cySrc
									 ,IN DWORD dwRop
									 ,IN DWORD dwBackColor);

typedef NTSTATUS(*NTUSERHWNDQUERYREDIRECTORYINFO)(ULONG param1
	, ULONG param2
	, ULONG param3
	, ULONG param4);

NTGDIBITBLT OldNtGdiBitBlt;

NTGDISTRETCHBLT OldNtGdiStretChBlt;

NTUSERHWNDQUERYREDIRECTORYINFO OldNtUserHwndQueryRedirectoryInfo;

BOOLEAN IsPatternMatch(IN PUNICODE_STRING Expression,IN PUNICODE_STRING Name,IN BOOLEAN IgnoreCase)
{
	return FsRtlIsNameInExpression(Expression,Name,IgnoreCase,NULL);
}

NTSTATUS GetProcessNameByPid(__in ULONG_PTR uPid,__out UNICODE_STRING *fullPath)
{
	
	NTSTATUS ntStatus = STATUS_SUCCESS;
	NTSTATUS dosStatus = STATUS_SUCCESS;
	PEPROCESS pEprocessEprocess = NULL;
	HANDLE hProcessHandle = NULL;
	FILE_OBJECT *fProcessFileObject = NULL;
	//UNICODE_STRING uProcessName = {0x00};
	IO_STATUS_BLOCK ioBlock = {0x00};
	ULONG uProcessNameRealLen;
	VOID *uProcessNameBuffer = NULL;
	KAPC_STATE pRkapcState = {0x00};
	OBJECT_ATTRIBUTES oProcessObject = {0x00};
	UNICODE_STRING uProcessDosName = {0x00};
	DECLARE_UNICODE_STRING_SIZE(uProcessNameStr,MAX_PATH);
	WCHAR FileBuffer[MAX_PATH] = {0x00};
	FILE_NAME_INFORMATION *fileName = NULL;
	WCHAR fileBuffer[MAX_PATH] = {0x00};

	PAGED_CODE();

	//获取进程的Eprocess结构
	ntStatus = PsLookupProcessByProcessId(uPid,&pEprocessEprocess);
	if(!NT_SUCCESS(ntStatus))
	{
		//DbgPrint("PsLookupProcessByProcessId faild\n");
		return ntStatus;
	}

	__try
	{
		KeStackAttachProcess(pEprocessEprocess,&pRkapcState);

		//第一次获取进程名实际长度
		ntStatus = ZwQueryInformationProcess(NtCurrentProcess()
			,ProcessImageFileName
			,NULL
			,NULL
			,&uProcessNameRealLen);
		if(STATUS_INFO_LENGTH_MISMATCH != ntStatus)
		{
			DbgPrint("ZwQueryInformationProcess with name len faild\n");
			ntStatus = STATUS_MEMORY_NOT_ALLOCATED;
			__leave;
		}

		uProcessNameBuffer = ExAllocatePoolWithTag(NonPagedPool,uProcessNameRealLen,'PTEG');
		if(!uProcessNameBuffer)
		{
			DbgPrint("ExallocatePoolWithTag to uProcessNameBuffer faild\n");
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		//第二次获取进程名
		ntStatus = ZwQueryInformationProcess(NtCurrentProcess()
			,ProcessImageFileName
			,uProcessNameBuffer
			,uProcessNameRealLen
			,NULL);
		if(NT_ERROR(ntStatus))
		{
			DbgPrint("ZwQueryInformationProcess to name buffer faild\n");
			__leave;
		}

		RtlCopyUnicodeString(&uProcessNameStr,(UNICODE_STRING *)uProcessNameBuffer);
		InitializeObjectAttributes(&oProcessObject
			,&uProcessNameStr
			,OBJ_CASE_INSENSITIVE,
			NULL
			,NULL);
		//DbgPrint("uProcessName is %wZ\n",&uProcessNameStr);

		//接着，打开进程，获取进程句柄
		ntStatus = ZwCreateFile(&hProcessHandle
			,FILE_READ_ATTRIBUTES
			,&oProcessObject
			,&ioBlock
			,NULL
			,FILE_ATTRIBUTE_NORMAL
			,0
			,FILE_OPEN
			,FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
			,NULL
			,0);
		if(NT_ERROR(ntStatus))
		{
			DbgPrint("ZwCreateFile faild:0x%x\n",ntStatus);
			ExFreePool(uProcessNameBuffer);
			uProcessNameBuffer = NULL;
			__leave;
		}

		//获取成功，接着获取该文件的文件内核对象,该函数会对该文件内核对象的引用计数加1
		ntStatus = ObReferenceObjectByHandle(hProcessHandle
			,NULL
			,*IoFileObjectType
			,KernelMode
			,(PVOID)&fProcessFileObject
			,NULL);
		if(!NT_SUCCESS(ntStatus))
		{
			DbgPrint("ObReferenceObjectByHandle faild\n");
			__leave;
		}

		if(fProcessFileObject->DeviceObject == NULL)
		{
			DbgPrint("fileObject->DeviceObject is NULL\n");
			__leave;
		}

		fileName = (FILE_NAME_INFORMATION *)fileBuffer;
		ntStatus = ZwQueryInformationFile(hProcessHandle
			,&ioBlock
			,fileName
			,sizeof(WCHAR) * MAX_PATH
			,FileNameInformation);
		if(!NT_SUCCESS(ntStatus))
		{
			DbgPrint("ZwQueryInformationFile faild!:%d\n",ntStatus);
			__leave;
		}

		dosStatus = RtlVolumeDeviceToDosName(fProcessFileObject->DeviceObject,&uProcessDosName);
		if(!NT_SUCCESS(ntStatus))
		{
			DbgPrint("RtlVolumeDeviceToDosName faild\n");
			__leave;
		}

	}

	__finally
	{
		if(hProcessHandle)
		{
			ZwClose(hProcessHandle);
		}
		if(fProcessFileObject)
		{
			ObDereferenceObject(fProcessFileObject);
		}
	}

	if(!NT_SUCCESS(ntStatus))
		return ntStatus;

	RtlInitUnicodeString(&uProcessNameStr,fileName->FileName);
	if(NT_SUCCESS(dosStatus))
	{
		RtlCopyUnicodeString(fullPath,&uProcessDosName);
		RtlUnicodeStringCat(fullPath,&uProcessNameStr);
	}
	else
	{
		RtlCopyUnicodeString(fullPath,&uProcessNameStr);
	}

	return ntStatus;
}

NTSTATUS New_NtUserHwndQueryRedirectoryInfo(ULONG param1, ULONG param2, ULONG param3, ULONG param4)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	ntStatus = OldNtUserHwndQueryRedirectoryInfo(param1,param2,param3,param4);
}

BOOLEAN Sleep(ULONG TimeInterval)
{
	NTSTATUS tStatus = STATUS_SUCCESS;
	LARGE_INTEGER DelayTime;

	DelayTime.QuadPart = (-10 * 1000) * TimeInterval;
	tStatus = KeDelayExecutionThread(KernelMode,FALSE,&DelayTime);

	return (NT_SUCCESS(tStatus));
}


VOID DriverUnload(PDRIVER_OBJECT pDriObj)
{
	UNICODE_STRING uSymbolicName = {0x00};
	PDEVICE_OBJECT pDevice = pDriObj->DeviceObject;
	NTSTATUS ioStatus = STATUS_SUCCESS;
	PEPROCESS lpEprocess = NULL;

	RtlInitUnicodeString(&uSymbolicName,SymbolicName);

	IoDeleteDevice(pDevice);
	IoDeleteSymbolicLink(&uSymbolicName);


	if(OldNtGdiBitBlt && OldNtGdiStretChBlt && g_lpKeServiceTableBaseShadow)
	{
		ioStatus = PsLookupProcessByProcessId(GetCrsPid(),&lpEprocess);
		if(!NT_SUCCESS(ioStatus))
		{
			//DbgPrint("%s PsLookUpProcessByProcessId faild:%d!\n",__FUNCDNAME__,ioStatus);
			return;
		}

		KeAttachProcess(lpEprocess);
		__try
		{
			__asm
			{
				pushad
					mov eax,CR0
					and eax,0xfffeffff
					mov CR0,eax
					popad
			}

			InterlockedExchange((PULONG)&g_lpKeServiceTableBaseShadow->ServiceTableBase[13],(ULONG)OldNtGdiBitBlt);
			InterlockedExchange((PULONG)&g_lpKeServiceTableBaseShadow->ServiceTableBase[292],(ULONG)OldNtGdiStretChBlt);

			__asm
			{
				pushad
					mov eax,CR0
					or eax,NOT 0xfffeffff
					mov CR0,eax
					popad
			}
		}

		__finally
		{
			KeDetachProcess();
			Sleep(50);
		}
		
		
	}
	
	DbgPrint("ShadowSSDT : goodbye!\n");

	return;
}

BOOL New_NtGdiBitBlt(IN HDC hdcDes
						   ,IN int xDes
						   ,IN int yDes
						   ,IN int cxDes
						   ,IN int cyDes
						   ,IN HDC hdcSrc
						   ,IN int xSrc
						   ,IN int ySrc
						   ,IN int cxSrc
						   ,IN int cySrc
						   ,IN DWORD dwRop
						   ,IN DWORD dwBackColor
						   ,IN ULONG flwag)
{
	ULONG_PTR ulPid;
	UNICODE_STRING uEpression;
	DECLARE_UNICODE_STRING_SIZE(uProcessName,MAX_PATH);

	ulPid = (ULONG_PTR)PsGetCurrentProcessId();

	GetProcessNameByPid((HANDLE)ulPid,&uProcessName);
	RtlInitUnicodeString(&uEpression,L"*FSCAPTURE.EXE");

	if(IsPatternMatch(&uEpression,&uProcessName,TRUE))
	{
		DbgPrint("Current Process Name is %wZ\n",&uProcessName);
		return FALSE;
	}
	
	//DbgPrint("%s:xDes->%d,yDes->%d,wDes->%d,hDes->%d\n",__FUNCDNAME__,xDes,yDes,cxDes,cyDes);
	//DbgPrint("%s:xSrc->%d,ySrc->%d,wSrc->%d,hSrc->%d\n",__FUNCDNAME__,xSrc,ySrc,cxSrc,cySrc);
	return OldNtGdiBitBlt(hdcDes,xDes,yDes,cxDes,cyDes,hdcSrc,xSrc,ySrc,cxSrc,cySrc,dwRop,dwBackColor,flwag);
}

BOOL New_NtGdiStretChBlt(IN HDC hdcDes
						 ,IN int xDes
						 ,IN int yDes
						 ,IN int cxDes
						 ,IN int cyDes
						 ,IN HDC hdcSrc
						 ,IN int xSrc
						 ,IN int ySrc
						 ,IN int cxSrc
						 ,IN int cySrc
						 ,IN DWORD dwRop
						 ,IN DWORD dwBackColor)
{
	UNICODE_STRING uWhiteProcName = {0x00};
	DECLARE_UNICODE_STRING_SIZE(uProcessName,MAX_PATH);
	GetProcessNameByPid(NtCurrentProcess(),&uProcessName);
	RtlInitUnicodeString(&uWhiteProcName,L"*FSCAPTURE.EXE");

	if(IsPatternMatch(&uWhiteProcName,&uProcessName,TRUE))
	{
		DbgPrint("Current Process Name is %wz\n",&uProcessName);
		return FALSE;
		//DbgPrint("%s:xDes->%d,yDes->%d,wDes->%d,hDes->%d\n",xDes,yDes,cxDes,cyDes);
		//DbgPrint("%s:xSrc->%d,ySrc->%d,wSrc->%d,hSrc->%d\n",xSrc,ySrc,cxSrc,cySrc);
	}
	
	return OldNtGdiStretChBlt(hdcDes,xDes,yDes,cxDes,cyDes,hdcSrc,xSrc,ySrc,cxSrc,cySrc,dwRop,dwBackColor);
}


//获取全局句柄表，该句柄表不是导出的
PVOID GetTableInfo(ULONG TableType)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PVOID lpOutputBuffer = NULL;
	ULONG uBufferSize = 0x4000;

	do
	{
		lpOutputBuffer = ExAllocatePoolWithTag(PagedPool,uBufferSize,'GIT');
		if(!lpOutputBuffer)
		{
			DbgPrint("ExAllocatePoolWithTag faild!\n");
			return NULL;
		}

		ntStatus = ZwQuerySystemInformation(TableType,lpOutputBuffer,uBufferSize,NULL);
		if(ntStatus == STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePool(lpOutputBuffer);

			uBufferSize *= 2;
		}
	}while(ntStatus == STATUS_INFO_LENGTH_MISMATCH);

	if(NT_SUCCESS(ntStatus))
	{
		return lpOutputBuffer;
	}

	ExFreePoolWithTag(lpOutputBuffer,'GIT');

	return NULL;
}

HANDLE GetCrsPid(VOID)
{
	ULONG crsPid = 0;
	PSYSTEM_HANDLE_INFORMATION_EX handles = NULL;
	HANDLE csrId = (HANDLE)0;
	ULONG i;
	UCHAR Buffer[0x100];
	POBJECT_NAME_INFORMATION lpObj = (PVOID)&Buffer;
	OBJECT_ATTRIBUTES obj;
	CLIENT_ID CliId;
	HANDLE hTarHandle;
	HANDLE hCurrentProcessHandle;

	handles = (SYSTEM_HANDLE_INFORMATION_EX *)GetTableInfo(SystemHandleInformation);
	if(handles == NULL)
		return csrId;
	for(i = 0; i < handles->NumberOfHandles; i++)
	{
		if(handles->Information[i].ObjectTypeNumber == 21)
		{
			InitializeObjectAttributes(&obj
				,NULL
				,OBJ_KERNEL_HANDLE
				,NULL
				,NULL);
			CliId.UniqueProcess = handles->Information[i].ProcessId;
			CliId.UniqueThread = 0;
			//打开当前进程
			if(NT_SUCCESS(NtOpenProcess(&hCurrentProcessHandle,PROCESS_DUP_HANDLE,&obj,&CliId)))
			{
				//拷贝目标进程的目标资源句柄到当前进程的目标句柄中
				if(NT_SUCCESS(ZwDuplicateObject(hCurrentProcessHandle
					,handles->Information[i].Handle
					,NtCurrentProcess()
					,&hTarHandle
					,0
					,0
					,DUPLICATE_SAME_ACCESS)))
				{
					//查询拷贝到自己进程的资源objectName信息
					if(NT_SUCCESS(ZwQueryObject(hTarHandle,ObjectNameInformation,lpObj,0x100,NULL)))
					{
						if(lpObj->Name.Buffer && (wcsncmp(lpObj->Name.Buffer,L"\\Windows\\ApiPort",20) == 0))
						{
							DbgPrint("find target process!\n");
							csrId = (HANDLE)handles->Information[i].ProcessId;
						}
					}
					ZwClose(hTarHandle);
				}
				ZwClose(hCurrentProcessHandle);
			}

		}
	}	
	
	ExFreePool(handles);

	return csrId;
}

VOID Hook(VOID)
{
	NTSTATUS ioStatus = STATUS_SUCCESS;
	ULONG uCurKernelVersion = 0;
	ULONG MajorVersion = 0;
	ULONG MinVersion = 0;
	ULONG CsdVersion = 0;
	PEPROCESS crsProcess = NULL;

	PsGetVersion(&MajorVersion,&MinVersion,&uCurKernelVersion,NULL);

	DbgPrint("uCurKernelVersion is %d\n",uCurKernelVersion);

	if(uCurKernelVersion != 2600)
	{
		DbgPrint("not xp!\n");
		return;
	}

	g_lpKeServiceTableBaseShadow = (ServiceDescriptorTableEntry_t *)((ULONG)&KeServiceDescriptorTable - 0x40 + 0x10);
	DbgPrint("g_lpKeServiceTableBaseShadow address is 0x%x\n",(ULONG)g_lpKeServiceTableBaseShadow);

	if(!g_lpKeServiceTableBaseShadow)
	{
		return;
	}


	ioStatus = PsLookupProcessByProcessId(GetCrsPid(),&crsProcess);
	if(!NT_SUCCESS(ioStatus))
	{
		DbgPrint("PsLookupProcessByProcessId faild:%d\n",ioStatus);
		return;
	}
	
	__try
	{
		KeAttachProcess(crsProcess);
		//关闭内核写保护
		__asm
		{
			pushad
				mov eax,CR0
				and eax,0xfffeffff
				mov CR0,eax
				popad
		}

		OldNtGdiBitBlt = (NTGDIBITBLT)InterlockedExchange((PULONG)&g_lpKeServiceTableBaseShadow->ServiceTableBase[13],(ULONG)New_NtGdiBitBlt);
		OldNtGdiStretChBlt = (NTGDISTRETCHBLT)InterlockedExchange((PULONG)&g_lpKeServiceTableBaseShadow->ServiceTableBase[292]
		,(ULONG)New_NtGdiStretChBlt);

		__asm
		{
			pushad
				mov eax,CR0
				or eax,NOT 0xfffeffff
				mov CR0,eax
				popad
		}
	}

	__finally
	{
		KeDetachProcess();
		Sleep(50);
	}

}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriObj,PUNICODE_STRING pDriPath)
{
	NTSTATUS ioStatus = STATUS_SUCCESS;

	UNICODE_STRING uDeviceName = {0x00};
	UNICODE_STRING uSymbolicName = {0x00};
	DEVICE_OBJECT *pDevObj = NULL;

	RtlInitUnicodeString(&uDeviceName,DeviceName);
	ioStatus = IoCreateDevice(pDriObj
		,0
		,&uDeviceName
		,FILE_DEVICE_UNKNOWN
		,0
		,FALSE
		,&pDevObj
		);

	if(!NT_SUCCESS(ioStatus))
	{
		DbgPrint("IoCreateDevice faild:%d!\n",ioStatus);
		return ioStatus;
	}

	RtlInitUnicodeString(&uSymbolicName,SymbolicName);

	ioStatus = IoCreateSymbolicLink(&uSymbolicName,&uDeviceName);
	if(!NT_SUCCESS(ioStatus))
	{
		DbgPrint("IoCreateSymbolicLink faild:%d!\n",ioStatus);
		return ioStatus;
	}

	pDriObj->DriverUnload = DriverUnload;

	DbgPrint("start ShadowSSDT_Hook!\n");
	Hook();

	return ioStatus;
}