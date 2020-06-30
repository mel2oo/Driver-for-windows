
#include "precom.h"


extern UNICODE_STRING	g_ustrVolumeDeviceName;
extern PFLT_INSTANCE	g_SbVolInstance;

extern UNICODE_STRING	g_SandboxPath; 
extern UNICODE_STRING	g_SandboxDosPath; 
extern	PFLT_FILTER		gp_Filter;


#define	MAX_VOLUME_CHARS 26	

_inline PVOID MyAllocateMemory(
							   IN POOL_TYPE	PoolType,
							   IN SIZE_T		NumberOfBytes
							   )
{
	PVOID	pBuffer;
	
	pBuffer = ExAllocatePoolWithTag(PoolType, NumberOfBytes, 'FCLM');
	if(pBuffer != NULL)
		RtlZeroMemory(pBuffer, NumberOfBytes);
	
	return pBuffer;
}

VOID SbGetSandboxPath(
	IN	PWCHAR	szSandboxName,
	IN	BOOL	bRegistry, 
	OUT	PWCHAR	lpszSandboxPath
	)
{
	UNICODE_STRING uSandboxPath;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	if(!szSandboxName || !lpszSandboxPath)
		return;

	uSandboxPath.Length = 0;
	uSandboxPath.MaximumLength = (MAX_PATH -1)* sizeof(WCHAR);
	uSandboxPath.Buffer = lpszSandboxPath;

	RtlCopyUnicodeString(&uSandboxPath, &g_SandboxPath);

	ntStatus = RtlAppendUnicodeToString(&uSandboxPath, szSandboxName);
	if (!NT_SUCCESS(ntStatus))
		return;
	ntStatus = RtlAppendUnicodeToString(&uSandboxPath, L"\\");
	if (!NT_SUCCESS(ntStatus))
		return;
	uSandboxPath.Buffer[uSandboxPath.Length/sizeof(WCHAR)] = 0;
}


NTSTATUS 
SbVolDeviceToDosName(
    IN PUNICODE_STRING VolumeDeviceName,
    OUT PWCHAR pDriverLetterChar,
    OUT PUSHORT	pusVolumeDeviceVolumeNameLength
    )
{
    WCHAR Buffer[30];
    UNICODE_STRING DriveLetterName;
    UNICODE_STRING LinkTarget;
    WCHAR Char;
    NTSTATUS Status;
	LinkTarget.Buffer = MyNew(WCHAR, MAX_PATH);
	if (LinkTarget.Buffer == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;
	
	LinkTarget.Length = 0;
	LinkTarget.MaximumLength = MAX_PATH*sizeof(WCHAR);
    RtlStringCbCopyW(Buffer, MAX_PATH*sizeof(WCHAR), L"\\??\\C:");
	Buffer[6] = 0;
    RtlInitUnicodeString(&DriveLetterName, Buffer);

    for (Char = 'A'; Char <= 'Z'; Char++)
    {
        DriveLetterName.Buffer[4] = Char;
		LinkTarget.Length = 0;
        Status = TlQuerySymbolicLinkName(&DriveLetterName, &LinkTarget);
        if (!NT_SUCCESS(Status))
            continue;

        if (RtlPrefixUnicodeString(&LinkTarget, VolumeDeviceName, TRUE))
            break;
    }
	ExFreePool(LinkTarget.Buffer);
	
    if (Char <= 'Z')
    {
       	if (pDriverLetterChar)
			*pDriverLetterChar = Char;
		if (pusVolumeDeviceVolumeNameLength)
			*pusVolumeDeviceVolumeNameLength = LinkTarget.Length;
        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


// "C:\1.txt" -->"c:\sandbox\abc.exe\harddiskvolume1\1.txt"
NTSTATUS
SbConvertDosToSbName(
	IN PUNICODE_STRING			pSandboxPath,
	IN PUNICODE_STRING			puszSrcName,
	IN OUT PUNICODE_STRING		pDestName
	)
{
	PWCHAR szSrcNtName = NULL;
	DWORD dwSrcNtNameLen = 0;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	BOOL bSuccess = FALSE;

	if(!pSandboxPath || !puszSrcName || !pDestName)
		return STATUS_INVALID_PARAMETER;
	
	RtlCopyUnicodeString(pDestName, pSandboxPath);

	szSrcNtName = MyNew(WCHAR, MAX_PATH);

	if (!szSrcNtName)
		return STATUS_INSUFFICIENT_RESOURCES;
	
	bSuccess = GetNtDeviceName(puszSrcName->Buffer, szSrcNtName);

	if (!bSuccess)
	{
		MyDelete(szSrcNtName);
		return ntStatus;
	}

	if (_wcsnicmp(szSrcNtName, L"\\DEVICE\\", 8) != 0)
	{
		MyDelete(szSrcNtName);
		return STATUS_INVALID_PARAMETER;
	}
	dwSrcNtNameLen = wcslen(szSrcNtName);
	if (dwSrcNtNameLen * sizeof(WCHAR) + pDestName->Length > MAX_PATH * sizeof(WCHAR))
	{
		MyDelete(szSrcNtName);
		return STATUS_BUFFER_TOO_SMALL;
	}
	
	ntStatus = RtlAppendUnicodeToString( pDestName, szSrcNtName + 8);
	if (!NT_SUCCESS(ntStatus))
	{
		MyDelete(szSrcNtName);
		return ntStatus;
	}
	
	if (!TlIsFileExist(gp_Filter,g_SbVolInstance, pDestName))
	{
		RtlCopyUnicodeString( pDestName, puszSrcName);
	}
	else
	{
		if (pDestName->Length + g_SandboxDosPath.Length - g_SandboxPath.Length > (MAX_PATH -1)* sizeof(WCHAR))
		{
			MyDelete(szSrcNtName);
			return STATUS_UNSUCCESSFUL;
		}
		memmove( pDestName->Buffer + g_SandboxDosPath.Length/sizeof(WCHAR), pDestName->Buffer + g_SandboxPath.Length / sizeof(WCHAR), pDestName->Length - g_SandboxPath.Length);
		memcpy(pDestName->Buffer, g_SandboxDosPath.Buffer, g_SandboxDosPath.Length);
		pDestName->Length = pDestName->Length + g_SandboxDosPath.Length - g_SandboxPath.Length;
	}

	MyDelete(szSrcNtName);
	return STATUS_SUCCESS;
}

// \\Device\\hardvolume2\\1.txt -> \\Device\\hardvolume1\\sandbox\\hardvolume2\\1.txt


NTSTATUS
SbConvertToSbName(
	IN PUNICODE_STRING			pSandboxPath,
	IN PUNICODE_STRING			pSrcName,
	OUT PUNICODE_STRING			pDstName,
	OUT PUNICODE_STRING			pVolName
	)
{
	NTSTATUS		ntStatus	= STATUS_UNSUCCESSFUL;
	USHORT			usNameSize	= 0;
	PBYTE			pNameBuffer = NULL;
	UNICODE_STRING	ustrDevicePrefix = RTL_CONSTANT_STRING(L"\\Device\\");
	UNICODE_STRING	ustrHardVolumeName	= {0 , 0 , 0};
	USHORT			usIndex				= 0;
	
	__try
	{
		if(pSrcName == NULL ||  pDstName == NULL || NULL == pSandboxPath) 
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			__leave;
		}

		if(RtlPrefixUnicodeString(pSandboxPath,
								  pSrcName,
								  TRUE))
		{
			ntStatus = STATUS_SB_REPARSED;
			__leave;
		}
		
		usNameSize = pSandboxPath->Length + pSrcName->Length - ustrDevicePrefix.Length;
		
		pNameBuffer= MyAllocateMemory(PagedPool, usNameSize);
		if(pNameBuffer == NULL)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}	
	

		RtlCopyMemory(pNameBuffer, 
						pSandboxPath->Buffer, 
						pSandboxPath->Length
						);

		RtlCopyMemory(	pNameBuffer + pSandboxPath->Length, 
						pSrcName->Buffer + ustrDevicePrefix.Length / sizeof(WCHAR), 
						pSrcName->Length - ustrDevicePrefix.Length
						);


		pDstName->Buffer = (PWSTR)pNameBuffer; 
		pDstName->MaximumLength = pDstName->Length  = usNameSize; 
	
		ntStatus = STATUS_SUCCESS;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ntStatus = GetExceptionCode();
	}

	return ntStatus;
}

USHORT SbGetVolLength(PFLT_FILTER pFilter, PUNICODE_STRING pustrFullPath)
{
	UNICODE_STRING ustrHardVolumeName;
	if(!pustrFullPath)
		return 0;
	
	if (pustrFullPath->Length < 9*sizeof(WCHAR))// "\Device\"
		return 0;
	
	ustrHardVolumeName.Buffer = pustrFullPath->Buffer;
	ustrHardVolumeName.Length = 9*sizeof(WCHAR); // "\Device\"
	ustrHardVolumeName.MaximumLength = pustrFullPath->Length;
	do
	{

		while(*(ustrHardVolumeName.Buffer + ustrHardVolumeName.Length / sizeof(WCHAR)) != L'\\'
			 && *(ustrHardVolumeName.Buffer + ustrHardVolumeName.Length / sizeof(WCHAR)) != L':')
		{
			ustrHardVolumeName.Length += sizeof(WCHAR);
			if(ustrHardVolumeName.Length >= ustrHardVolumeName.MaximumLength)
				break;
		}
		
		if (SbGetVolumeInstance(pFilter, &ustrHardVolumeName) )
		{
			return ustrHardVolumeName.Length;
		}
		ustrHardVolumeName.Length += sizeof(WCHAR);
		
	}while(ustrHardVolumeName.Length <= ustrHardVolumeName.MaximumLength);
	return 0;
}

/*
\\Device\\hardvolume1\\sandbox\\hardvolume2\\1.txt
\\Device\\hardvolume2\\1.txt
*/

NTSTATUS
SbConvertInSbNameToOutName(
	IN  PFLT_FILTER					pFilter,
	IN	PUNICODE_STRING				pOutSideName,
	IN  PUNICODE_STRING				pSandboxPath,
	OUT	PUNICODE_STRING				pSrcName,
	IN OUT PUNICODE_STRING				pustrVolumeDeviceName
	)
{
	NTSTATUS		ntStatus			= STATUS_UNSUCCESSFUL;
	UNICODE_STRING	ustrHardVolumeName	= {0 , 0 , 0};
	USHORT			usIndex				= 0;
	USHORT			usNameSize			= 0;	
	UNICODE_STRING	ustrDevicePrefix	= RTL_CONSTANT_STRING(L"\\Device\\");
	PBYTE			pNameBuffer			= NULL;
	BOOLEAN			bVolume = FALSE;
	UNICODE_STRING  ustrVolumeFullName  = {0, 0, 0};
	USHORT			usVolumeNameLength = 0;
	__try
	{
		if(pOutSideName == NULL || pSrcName == NULL)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			__leave;
		}

		if(!RtlPrefixUnicodeString(pSandboxPath,
								  pOutSideName,
								  TRUE))
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			__leave;
		}

		ustrHardVolumeName.Buffer = pOutSideName->Buffer + pSandboxPath->Length / sizeof(WCHAR);
		do
		{

			while(*(ustrHardVolumeName.Buffer + usIndex / sizeof(WCHAR)) != L'\\'
				 && *(ustrHardVolumeName.Buffer + usIndex / sizeof(WCHAR)) != L':')
			{
				usIndex += sizeof(WCHAR);
				if(usIndex + pSandboxPath->Length == pOutSideName->Length)
					break;
			}
			
			ustrHardVolumeName.MaximumLength = ustrHardVolumeName.Length = usIndex;
			
			ustrVolumeFullName.Length = 0;
			ustrVolumeFullName.MaximumLength = ustrHardVolumeName.Length + ustrDevicePrefix.Length;
			ustrVolumeFullName.Buffer = MyNew(WCHAR, ustrVolumeFullName.MaximumLength / sizeof(WCHAR));
			
			if (ustrVolumeFullName.Buffer == NULL)
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				__leave;
			}
			
			ntStatus = RtlUnicodeStringCopy( &ustrVolumeFullName, &ustrDevicePrefix);
			if (!NT_SUCCESS(ntStatus))
				__leave;
			
			ntStatus = RtlUnicodeStringCat( &ustrVolumeFullName, &ustrHardVolumeName);
			if (!NT_SUCCESS(ntStatus))
				__leave;

			if (SbGetVolumeInstance(pFilter, &ustrVolumeFullName) )
			{
				ExFreePool( ustrVolumeFullName.Buffer );
				ustrVolumeFullName.Buffer = NULL;
				usVolumeNameLength = usIndex - sizeof(WCHAR);
				break;
			}
			
			ExFreePool(ustrVolumeFullName.Buffer );
			ustrVolumeFullName.Buffer = NULL;
			
			usIndex += sizeof(WCHAR);
			
		}while(usIndex + pSandboxPath->Length < pOutSideName->Length);

		
		if (usVolumeNameLength == 0)
		{
			ntStatus = STATUS_UNSUCCESSFUL;
			__leave;
		}
		
		if(NULL != pustrVolumeDeviceName)
		{
			RtlCopyMemory(pustrVolumeDeviceName->Buffer, ustrDevicePrefix.Buffer,	ustrDevicePrefix.Length);
			RtlCopyMemory(pustrVolumeDeviceName->Buffer + ustrDevicePrefix.Length / sizeof(WCHAR),  ustrHardVolumeName.Buffer, ustrHardVolumeName.Length);
			
			pustrVolumeDeviceName->Length =  ustrDevicePrefix.Length + ustrHardVolumeName.Length;
			pustrVolumeDeviceName->MaximumLength = pustrVolumeDeviceName->Length ;
		}
		
		usNameSize	= pOutSideName->Length -  pSandboxPath->Length + ustrDevicePrefix.Length;
		pNameBuffer	= (PBYTE)(pOutSideName->Buffer + ((pSandboxPath->Length + usVolumeNameLength)/ sizeof(WCHAR)));

		pNameBuffer = MyAllocateMemory(PagedPool, usNameSize);
		if(pNameBuffer  == NULL)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		RtlCopyMemory(pNameBuffer, ustrDevicePrefix.Buffer, ustrDevicePrefix.Length);
	
		RtlCopyMemory(pNameBuffer + ustrDevicePrefix.Length, 
					  pOutSideName->Buffer + pSandboxPath->Length / sizeof(WCHAR) , 
					  pOutSideName->Length - pSandboxPath->Length);

		if(bVolume)
		{
			*(WCHAR *)(pNameBuffer + usNameSize - sizeof(WCHAR)) = L'\\';
		}

		pSrcName->Buffer = (PWSTR)pNameBuffer;
		pSrcName->MaximumLength = pSrcName->Length  = usNameSize;
		ntStatus = STATUS_SUCCESS;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ntStatus = GetExceptionCode();
	}
	if (NULL != ustrVolumeFullName.Buffer)
		MyDelete(ustrVolumeFullName.Buffer);
	return ntStatus;
}


NTSTATUS
SbRedirectFile(
	IN	PFLT_CALLBACK_DATA 		Data,
	IN	PCFLT_RELATED_OBJECTS	FltObjects,
	IN	PUNICODE_STRING			pUstrDstFileName
	)
{
	PFILE_OBJECT		pFileObject;
	
	__try
	{
		pFileObject= Data->Iopb->TargetFileObject;
		if(pFileObject == NULL)
			return STATUS_INVALID_PARAMETER;


		if(pFileObject->FileName.Length > 0 && pFileObject->FileName.Buffer != NULL)
		{
			ExFreePool(pFileObject->FileName.Buffer);
			pFileObject->FileName.Buffer = NULL;
		}	

		pFileObject->FileName = *pUstrDstFileName;
		pFileObject->RelatedFileObject = NULL;

		Data->IoStatus.Status = STATUS_REPARSE; 
		Data->IoStatus.Information = IO_REPARSE;

		FltSetCallbackDataDirty(Data);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return STATUS_SUCCESS;
}

NTSTATUS
SbGetParentPath(
	IN PUNICODE_STRING pFileName,
	OUT PUNICODE_STRING pOutPath,
	IN BOOL bInsandbox)
{
		BOOL bLast = FALSE;
		WORD usIndex = 0;
		WORD count = 0;

		while(usIndex < pFileName->Length)
		{
			if (*(pFileName->Buffer + usIndex/sizeof(WCHAR)) 
				== L'\\')
				count++;
			usIndex += sizeof(WCHAR);
		}
		if (bInsandbox)
		{

			if (count <= 6)
				return STATUS_NO_PARENT_PATH;
				
		}
		else
		{
			if (count <= 3)
				return STATUS_NO_PARENT_PATH;

		}

		pOutPath->Buffer = pFileName->Buffer;
		usIndex = pFileName->Length - sizeof (WCHAR);
		while(usIndex > 0)
		{
			if (*(pFileName->Buffer + usIndex/sizeof(WCHAR)) 
				== L'\\')
			{
				bLast = TRUE;
				break;
			}
			usIndex -= sizeof(WCHAR);
		}
			
		if (bLast)
		{
			pOutPath->MaximumLength = pOutPath->Length = usIndex;
			return STATUS_SUCCESS;
		}
		return STATUS_UNSUCCESSFUL;
}

NTSTATUS
SbPrepareSandboxPath(
	IN PFLT_FILTER	pFilter,
	IN PFLT_INSTANCE	pInstance,
	IN PUNICODE_STRING  pSandboxPath,
	IN PUNICODE_STRING	pFileName,
	IN ACCESS_MASK		desiredAccess
	)
{
	NTSTATUS		ntStatus;
	UNICODE_STRING	ustrTmpName = {0, 0, 0};
	UNICODE_STRING	outsideTmpName = {0, 0, 0};
	USHORT			usIndex;
	OBJECT_ATTRIBUTES	objAttrib;
	HANDLE			hFile;
	IO_STATUS_BLOCK	ioStatus;
	BOOLEAN			bCreatingRootDir = TRUE;
	PFILE_OBJECT	outsideTmpFileObj = NULL;
	ACCESS_MASK		AccessMask = desiredAccess;

	__try
	{
		if(pFilter == NULL || pInstance == NULL || pFileName == NULL)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			__leave;
		}
		if (pSandboxPath == NULL)
			pSandboxPath = &g_SandboxPath;

		if(!RtlPrefixUnicodeString(pSandboxPath,
							  pFileName,
							  TRUE))
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			__leave;
		}

		ustrTmpName.Buffer = pFileName->Buffer;
		usIndex = g_ustrVolumeDeviceName.Length + 2 * sizeof(WCHAR);
		while(usIndex < pFileName->Length - sizeof(WCHAR))
		{
			
			while( *(pFileName->Buffer + usIndex/sizeof(WCHAR)) 
				!= L'\\')
			{
				usIndex += sizeof(WCHAR);
				if(usIndex >= pFileName->Length - sizeof(WCHAR))
				{
					ntStatus = STATUS_SUCCESS;
					__leave;
				}
			}
			ustrTmpName.MaximumLength = ustrTmpName.Length = usIndex;

			InitializeObjectAttributes(&objAttrib,
									   &ustrTmpName,
									   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
									   NULL,
									   NULL);

			ntStatus = FltCreateFile(pFilter,
										 pInstance,    
										 &hFile,
										 GENERIC_READ | GENERIC_WRITE,
										 &objAttrib,
										 &ioStatus,
										 0,
										 FILE_ATTRIBUTE_DIRECTORY,
										 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
										 FILE_OPEN_IF,
										 FILE_DIRECTORY_FILE,
										 NULL,0,0);
			if(NT_SUCCESS(ntStatus))
			{
				FltClose(hFile);

				usIndex += sizeof(WCHAR);
			}
			else 
			{
				if( ntStatus == STATUS_ACCESS_DENIED || ntStatus == STATUS_SHARING_VIOLATION )
					ntStatus = STATUS_SUCCESS;
				else
					break;
			}
			bCreatingRootDir = FALSE;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	if(outsideTmpName.Buffer)
	{
		MyDelete(outsideTmpName.Buffer);
		outsideTmpName.Buffer= NULL;
	}
	if(outsideTmpFileObj)
	{
		ObDereferenceObject(outsideTmpFileObj);
		outsideTmpFileObj = NULL;
	}

	return ntStatus;
}

NTSTATUS
SbCopyFile(
	IN PFLT_FILTER	pFilter,
	IN PFLT_INSTANCE	pSrcInstance,
	IN PFILE_OBJECT		pSrcFileObj,
	IN PUNICODE_STRING	pSrcFileName,
	IN PFLT_INSTANCE	pDstInstance,
	IN PUNICODE_STRING	pDstFileName,
	IN BOOLEAN			bDirectory
	)
{
	NTSTATUS		ntStatus = STATUS_UNSUCCESSFUL;
	PFILE_STREAM_INFORMATION	pStreamInfo = NULL;
	ULONG			uStreamInfoSize = PAGE_SIZE;
	PVOID			pStreamBuffer;
	UNICODE_STRING	ustrSrcFileName = {0, 0, 0};
	UNICODE_STRING	ustrDstFileName = {0, 0, 0};
	UNICODE_STRING	ustrTmpName = {0, 0, 0};
	HANDLE			hFile = NULL;
	PFILE_OBJECT	pSrcFileObject = NULL;
	static UNICODE_STRING	dataStreamName = UNICODE_STRING_CONST("::$DATA");
	IO_STATUS_BLOCK					iosb = {0};
	FILE_FS_ATTRIBUTE_INFORMATION*	fsAttribInfomation = NULL;
	ULONG							length = sizeof(FILE_FS_ATTRIBUTE_INFORMATION)+20;

	__try
	{
		if(pFilter == NULL || pSrcInstance == NULL || 
			pSrcFileName == NULL || pDstInstance == NULL || pDstFileName == NULL)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			__leave;
		}

		if(!pSrcFileObj && !pSrcFileName)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			__leave;
		}

		if(!pSrcFileObj)
		{
			OBJECT_ATTRIBUTES	objAttrib;
			IO_STATUS_BLOCK		ioStatus = {0, 0};
	
			InitializeObjectAttributes(&objAttrib,
				pSrcFileName,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				NULL,
				NULL);
			
			ntStatus = FltCreateFile(pFilter,
									 pSrcInstance,    
									 &hFile,
									 GENERIC_READ | SYNCHRONIZE,
									 &objAttrib,
									 &ioStatus,
									 0,
									 FILE_ATTRIBUTE_NORMAL,
									 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
									 FILE_OPEN,
									 FILE_SYNCHRONOUS_IO_NONALERT,
									 NULL,0,0);
			if(! NT_SUCCESS(ntStatus))
				__leave;
			
			ntStatus = ObReferenceObjectByHandle(hFile,
				FILE_ANY_ACCESS,
				NULL,
				KernelMode,
				&pSrcFileObject,
				NULL);
			if(! NT_SUCCESS(ntStatus))		
				__leave;
			
		}
		else
		{
			pSrcFileObject = pSrcFileObj;
		}
		
		do 
		{
			pStreamBuffer = MyAllocateMemory(PagedPool, uStreamInfoSize);
			if(pStreamBuffer == NULL)
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				__leave;
			}

			ntStatus = FltQueryInformationFileSyncronous(pSrcInstance,
											   pSrcFileObject,
											   pStreamBuffer,
											   uStreamInfoSize,
											   FileStreamInformation,
											   NULL);
			if(NT_SUCCESS(ntStatus))
				break;

			uStreamInfoSize += PAGE_SIZE;
			ExFreePool(pStreamBuffer);	
			pStreamBuffer = NULL;

		} while (ntStatus == STATUS_BUFFER_OVERFLOW || ntStatus == STATUS_BUFFER_TOO_SMALL);

		if( ntStatus == STATUS_INVALID_PARAMETER )
		{
			fsAttribInfomation = (FILE_FS_ATTRIBUTE_INFORMATION*)MyNew(BYTE, length);
			if(!fsAttribInfomation)
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				__leave;
			}

			ntStatus = FltQueryVolumeInformation(pSrcInstance, &iosb, fsAttribInfomation,
				length, FileFsAttributeInformation);
			if(!NT_SUCCESS(ntStatus))
				__leave;

			if(0 != _wcsnicmp(L"NTFS", 
				fsAttribInfomation->FileSystemName, 
				fsAttribInfomation->FileSystemNameLength/sizeof(WCHAR))
				)
			{
				ntStatus = SbDoCopyFile(pFilter,
					pSrcFileObject,
					pSrcInstance,
					pSrcFileName,
					pDstInstance,
					pDstFileName,
					bDirectory);
				 
				__leave;
			}
		}

		if(! NT_SUCCESS(ntStatus))
			__leave;

		pStreamInfo = (PFILE_STREAM_INFORMATION)pStreamBuffer;
		while(TRUE)
		{
			ustrTmpName.MaximumLength = ustrTmpName.Length = (USHORT)pStreamInfo->StreamNameLength;
			ustrTmpName.Buffer = pStreamInfo->StreamName;
			if( RtlEqualUnicodeString(&ustrTmpName, &dataStreamName, TRUE) )
			{
				ntStatus = SbDoCopyFile(pFilter,
										 pSrcFileObject,
										 pSrcInstance,
										 pSrcFileName,
										 pDstInstance,
										 pDstFileName,
										 bDirectory);
				
				if(! NT_SUCCESS(ntStatus) && STATUS_SB_DIR_CREATED != ntStatus)
					break;

				if(pStreamInfo->NextEntryOffset == 0)
					break;

				pStreamInfo = (PFILE_STREAM_INFORMATION)((ULONG_PTR)pStreamInfo + pStreamInfo->NextEntryOffset);
				continue;
			}

			ustrSrcFileName.MaximumLength = ustrSrcFileName.Length = pSrcFileName->Length + (USHORT)pStreamInfo->StreamNameLength;
			ustrSrcFileName.Buffer = MyAllocateMemory(PagedPool, ustrSrcFileName.Length);

			ustrDstFileName.MaximumLength = ustrDstFileName.Length = pDstFileName->Length + (USHORT)pStreamInfo->StreamNameLength;
			ustrDstFileName.Buffer = MyAllocateMemory(PagedPool, ustrDstFileName.Length);
			if(ustrSrcFileName.Buffer == NULL || ustrDstFileName.Buffer == NULL)
			{
				if(ustrSrcFileName.Buffer != NULL)
				{
					ExFreePool(ustrSrcFileName.Buffer);
					ustrSrcFileName.Buffer = NULL;	
				}
				if(ustrDstFileName.Buffer != NULL)
				{
					ExFreePool(ustrDstFileName.Buffer);
					ustrDstFileName.Buffer = NULL;
				}

				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				__leave;
			}

			RtlCopyMemory(ustrSrcFileName.Buffer, pSrcFileName->Buffer, pSrcFileName->Length);
			RtlCopyMemory(ustrSrcFileName.Buffer + pSrcFileName->Length / sizeof(WCHAR),
						  pStreamInfo->StreamName,
						  pStreamInfo->StreamNameLength);

			RtlCopyMemory(ustrDstFileName.Buffer, pDstFileName->Buffer, pDstFileName->Length);
			RtlCopyMemory(ustrDstFileName.Buffer + pDstFileName->Length / sizeof(WCHAR),
						  pStreamInfo->StreamName,
						  pStreamInfo->StreamNameLength);

			ntStatus = SbDoCopyFile(pFilter,
									 pSrcFileObject,
									 pSrcInstance,
									 &ustrSrcFileName,
									 pDstInstance,
									 &ustrDstFileName,
									 bDirectory);

			ExFreePool(ustrSrcFileName.Buffer);
			ustrSrcFileName.Buffer = NULL;

			ExFreePool(ustrDstFileName.Buffer);
			ustrDstFileName.Buffer = NULL;


			if(! NT_SUCCESS(ntStatus) && ntStatus != STATUS_SB_DIR_CREATED)
				break;


			if(pStreamInfo->NextEntryOffset == 0)
				break;

			pStreamInfo = (PFILE_STREAM_INFORMATION)((ULONG_PTR)pStreamInfo + pStreamInfo->NextEntryOffset);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	MyDelete(fsAttribInfomation);

	if(!pSrcFileObj && pSrcFileObject)
		ObDereferenceObject(pSrcFileObject);

	if(hFile)
		FltClose(hFile);

	if(pStreamBuffer)
	{
		ExFreePool(pStreamBuffer);
		pStreamBuffer = NULL;
	}
	return ntStatus;
}

NTSTATUS
SbDoCopyFile(
	IN PFLT_FILTER	pFilter,
	IN PFILE_OBJECT	pSrcObject,
	IN PFLT_INSTANCE	pSrcInstance,
	IN PUNICODE_STRING	pSrcFileName,
	IN PFLT_INSTANCE	pDstInstance,
	IN PUNICODE_STRING	pDstFileName,
	IN BOOLEAN 			bDirectory
	)
{
	NTSTATUS		ntStatus;
	OBJECT_ATTRIBUTES	objSrcAttrib;
	OBJECT_ATTRIBUTES	objDstAttrib;
	HANDLE			hSrcFile = NULL;
	HANDLE			hDstFile = NULL;
	PFILE_OBJECT	pSrcFileObject = NULL;
	PFILE_OBJECT	pDstFileObject = NULL;
	IO_STATUS_BLOCK	ioStatus;
	LARGE_INTEGER	liOffset;
	ULONG			uReadSize;
	ULONG			uWriteSize;
	PVOID			pBuffer = NULL;
	ULONG 			CreateOptions = FILE_SYNCHRONOUS_IO_NONALERT;
	
	__try
	{
		if(pFilter == NULL || 
			pSrcInstance == NULL || 
			pSrcFileName == NULL || 
			pDstInstance == NULL || 
			pDstFileName == NULL)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			__leave;
		}

		if(bDirectory)
			CreateOptions |= FILE_DIRECTORY_FILE;
			

		if(!bDirectory)
		{
			if(!pSrcObject)
			{
				InitializeObjectAttributes(&objSrcAttrib,
										   pSrcFileName,
										   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
										   NULL,
										   NULL);
				
				ntStatus = FltCreateFile(pFilter,
										 pSrcInstance,    
										 &hSrcFile,
										 FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
										 &objSrcAttrib,
										 &ioStatus,
										 0,
										 FILE_ATTRIBUTE_NORMAL,
										 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
										 FILE_OPEN,
										 CreateOptions,
										 NULL,0,0);
				if(! NT_SUCCESS(ntStatus))
					__leave;

				ntStatus = ObReferenceObjectByHandle(hSrcFile,
													 FILE_ANY_ACCESS,
													 NULL,
													 KernelMode,
													 &pSrcFileObject,
													 NULL);
				if(! NT_SUCCESS(ntStatus))
					__leave;
			}
			else
				pSrcFileObject = pSrcObject;
		}

		InitializeObjectAttributes(&objDstAttrib,
								   pDstFileName,
								   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
								   NULL,
								   NULL);

		ntStatus = FltCreateFile(pFilter,
								 pDstInstance,
								 &hDstFile,
								 GENERIC_WRITE | SYNCHRONIZE,
								 &objDstAttrib,
								 &ioStatus,
								 0,
								 FILE_ATTRIBUTE_NORMAL,
								 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
								 FILE_CREATE,
								 CreateOptions,
								 NULL,0,0);
		if(! NT_SUCCESS(ntStatus))
			__leave;

		ntStatus = ObReferenceObjectByHandle(hDstFile,
											 FILE_ANY_ACCESS,
											 NULL,
											 KernelMode,
											 &pDstFileObject,
											 NULL);

		if(! NT_SUCCESS(ntStatus))
			__leave;

		if(bDirectory)
		{
			ntStatus = STATUS_SB_DIR_CREATED;
			__leave;
		}

		pBuffer = MyAllocateMemory(PagedPool, PAGE_SIZE);
		if(pBuffer == NULL)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		liOffset.QuadPart = pSrcFileObject->CurrentByteOffset.QuadPart;

		while(NT_SUCCESS(ntStatus))
		{
			uReadSize = 0;	uWriteSize = 0;

			ntStatus = FltReadFile(pSrcInstance,
								   pSrcFileObject,
								   0,
								   PAGE_SIZE,
								   pBuffer,
								   FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
								   &uReadSize,
								   NULL,
								   NULL);
			if( (!NT_SUCCESS(ntStatus)) || (uReadSize == 0) )
				break;

			pSrcFileObject->CurrentByteOffset.QuadPart += uReadSize;

			ntStatus = FltWriteFile(pDstInstance,
									pDstFileObject,
									0,
									uReadSize,
									pBuffer,
									0,
									&uWriteSize,
									NULL,
									NULL);
			if(!NT_SUCCESS(ntStatus))
				break;

			if(uReadSize < PAGE_SIZE)
				break;
		}

		pSrcFileObject->CurrentByteOffset.QuadPart = liOffset.QuadPart;
		if(ntStatus == STATUS_END_OF_FILE)
		{
			ntStatus = STATUS_SUCCESS;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	if(pBuffer != NULL)
		ExFreePool(pBuffer);

	if(pDstFileObject != NULL)
		ObDereferenceObject(pDstFileObject);
	if(hDstFile != NULL)
		FltClose(hDstFile);
	if(pSrcFileObject != NULL && !pSrcObject)
		ObDereferenceObject(pSrcFileObject);
	if(hSrcFile != NULL)
		FltClose(hSrcFile);

	return ntStatus;
}


NTSTATUS
SbTraverseDirectory(
	IN PFLT_INSTANCE	pInstance,
	IN PFILE_OBJECT		pFileObject,
	IN PUNICODE_STRING	pQueryName,
	IN ULONG			uInformaton,
	IN PVOID			*pBuffer,
	IN PULONG			pSize
	)
{
	NTSTATUS		ntStatus = STATUS_UNSUCCESSFUL;
	PFLT_CALLBACK_DATA	pNewData = NULL;
	PVOID			pTmpBuffer = NULL;
	ULONG			uTmpSize = PAGE_SIZE * 2;
	PVOID			pNewBuffer = NULL;
	ULONG			uNewBufferSize = PAGE_SIZE * 2;
	ULONG			uIndex = 0;
	BOOLEAN			bRestartScan = TRUE;
	ULONG			uRetSize = 0;
	PFILE_DIRECTORY_INFORMATION		pNode;

	__try
	{
		if(pInstance == NULL || pFileObject == NULL || pBuffer == NULL || pSize == NULL)
		{
			ntStatus = STATUS_INVALID_PARAMETER;
			__leave;
		}
		
		pNewBuffer = MyAllocateMemory(PagedPool, uNewBufferSize);
		if(pNewBuffer == NULL)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		pTmpBuffer = MyAllocateMemory(PagedPool, uTmpSize);
		if(pTmpBuffer == NULL)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		while(TRUE)
		{
			ntStatus = FltAllocateCallbackData(pInstance, pFileObject, &pNewData);
			if(! NT_SUCCESS(ntStatus))
				__leave;

			pNewData->Iopb->MajorFunction = IRP_MJ_DIRECTORY_CONTROL;
			pNewData->Iopb->MinorFunction = IRP_MN_QUERY_DIRECTORY;
			pNewData->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = pTmpBuffer;
			pNewData->Iopb->Parameters.DirectoryControl.QueryDirectory.Length = uTmpSize;
			pNewData->Iopb->Parameters.DirectoryControl.QueryDirectory.FileName = pQueryName;
			pNewData->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass = uInformaton;
			pNewData->Iopb->Parameters.DirectoryControl.QueryDirectory.FileIndex = 0;
			pNewData->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress = 0;
			if(bRestartScan)
			{
				SetFlag(pNewData->Iopb->OperationFlags, SL_RESTART_SCAN);			
			}
			pNewData->Iopb->IrpFlags |= IRP_SYNCHRONOUS_API;
			
			FltPerformSynchronousIo(pNewData);

			if(! NT_SUCCESS(pNewData->IoStatus.Status))
				__leave;

			uRetSize = (ULONG) pNewData->IoStatus.Information;

			if(uIndex + uRetSize > uNewBufferSize)
			{
				PVOID	ppBuffer;
				uNewBufferSize += PAGE_SIZE * 2;
				ppBuffer = MyAllocateMemory(PagedPool, uIndex);
				if(ppBuffer == NULL)
				{
					ntStatus = STATUS_INSUFFICIENT_RESOURCES;
					__leave;
				}
				RtlCopyMemory(ppBuffer, pNewBuffer, uIndex);
				ExFreePool(pNewBuffer);
				pNewBuffer = MyAllocateMemory(PagedPool, uNewBufferSize);
				if(pNewBuffer == NULL)
				{
					ExFreePool(ppBuffer);
					ntStatus = STATUS_INSUFFICIENT_RESOURCES;
					__leave;
				}
				RtlCopyMemory(pNewBuffer, ppBuffer, uIndex);
				ExFreePool(ppBuffer);
			}

			RtlCopyMemory((PBYTE)pNewBuffer + uIndex, 
						  pTmpBuffer, 
						  uRetSize);

			if(!bRestartScan)  //if this is a first time to run here, NextEntryOffset needn't to be adjusted.
			{
				pNode = (PFILE_DIRECTORY_INFORMATION)pNewBuffer;
				while(pNode->NextEntryOffset != 0)
				{
					#ifdef DBG
					if(pNode->NextEntryOffset > 0x1000)
						DbgBreakPoint();
					#endif
					pNode = (PFILE_DIRECTORY_INFORMATION)((PBYTE)pNode + pNode->NextEntryOffset);
				}
				pNode->NextEntryOffset =(ULONG)( ((PBYTE)pNewBuffer + uIndex) - (PBYTE)pNode);
			}
			uIndex += uRetSize;

			FltFreeCallbackData(pNewData);
			pNewData = NULL;

			bRestartScan = FALSE;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ntStatus = GetExceptionCode();
	}

	if(uIndex > 0)
	{
		*pBuffer = pNewBuffer;
		*pSize = uIndex;

		ntStatus = STATUS_SUCCESS;
	}

	if(!NT_SUCCESS(ntStatus) && pNewBuffer)
	{
		ExFreePool(pNewBuffer);
	}

	if(pTmpBuffer != NULL)
		ExFreePool(pTmpBuffer);

	if(pNewData != NULL)
		FltFreeCallbackData(pNewData);

	return ntStatus;
}


BOOLEAN
SbFileExist(
	IN PFLT_FILTER	pFilter,
	IN PFLT_INSTANCE	pInstance,
	IN PUNICODE_STRING	pFileName
	)
{
	NTSTATUS				ntStatus;
	OBJECT_ATTRIBUTES		objAttrib;
	HANDLE					hFile;
	IO_STATUS_BLOCK			ioStatus;

	__try
	{
		if(pFilter == NULL || pInstance == NULL || pFileName == NULL)
			return FALSE;

		InitializeObjectAttributes(&objAttrib,
								   pFileName,
								   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
								   NULL,
								   NULL);

		ntStatus = FltCreateFile(pFilter,
								 pInstance,    
								 &hFile,
								 FILE_READ_ATTRIBUTES | SYNCHRONIZE,
								 &objAttrib,
								 &ioStatus,
								 0,
								 FILE_ATTRIBUTE_NORMAL,
								 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
								 FILE_OPEN,
								 FILE_SYNCHRONOUS_IO_NONALERT,
								 NULL,0,0);

		if(NT_SUCCESS(ntStatus))
		{
			FltClose(hFile);
			return TRUE;
		}

		if(ntStatus == STATUS_SHARING_VIOLATION )
			return TRUE;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return FALSE;
}


PFLT_INSTANCE 
SbGetVolumeInstance(
	IN PFLT_FILTER		pFilter,
	IN PUNICODE_STRING	pVolumeName
	)
{
	NTSTATUS		ntStatus;
	PFLT_INSTANCE	pInstance = NULL;
	PFLT_VOLUME		pVolumeList[MAX_VOLUME_CHARS];
	BOOL			bDone = FALSE;
	ULONG			uRet;
	UNICODE_STRING	uniName ={0};
	ULONG 			index = 0;
	CONST UNICODE_STRING	constInstance = UNICODE_STRING_CONST("GlobalAttach");

	WCHAR			wszNameBuffer[MAX_PATH] = {0};

	
	ntStatus = FltEnumerateVolumes(pFilter,
		NULL,
		0,
		&uRet);
	if(ntStatus != STATUS_BUFFER_TOO_SMALL)
	{
		return NULL;
	}
	
	ntStatus = FltEnumerateVolumes(pFilter,
		pVolumeList,
		uRet,
		&uRet);
	
	if(!NT_SUCCESS(ntStatus))
	{

		return NULL;
	}
	uniName.Buffer = wszNameBuffer;
	
	if (uniName.Buffer == NULL)
	{
		for (index = 0;index< uRet; index++)
			FltObjectDereference(pVolumeList[index]);
		
		return NULL;
	}
	
	uniName.MaximumLength = MAX_PATH*sizeof(WCHAR);
	
	for (index = 0; index < uRet; index++)
	{
		uniName.Length = 0;

		ntStatus = FltGetVolumeName( pVolumeList[index],
										&uniName,
										NULL);

		if(!NT_SUCCESS(ntStatus))
			continue;

		if(RtlCompareUnicodeString(&uniName,
									pVolumeName,
									TRUE) != 0)
			continue;
		
		ntStatus = FltGetVolumeInstanceFromName(pFilter,
												pVolumeList[index],
												NULL,
												&pInstance);

		if(NT_SUCCESS(ntStatus))
		{
			FltObjectDereference(pInstance);
			break;
		}
	}
	
	for (index = 0;index< uRet; index++)
		FltObjectDereference(pVolumeList[index]);

	return pInstance;
}


NTSTATUS 
SbIsDirectory(
	IN PFILE_OBJECT fileObject,
	IN PUNICODE_STRING dirName, 
	IN PFLT_FILTER filter, 
	IN PFLT_INSTANCE instance, 
	OUT BOOLEAN* directory
	)
{
	PFILE_OBJECT	pFileObject = NULL;
	HANDLE			hFile = NULL;
	FILE_STANDARD_INFORMATION 	stdInfo;
	NTSTATUS 		ntStatus = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES	objAttrib;
	IO_STATUS_BLOCK		ioStatus;

	*directory = FALSE;

	__try
	{
		if(fileObject == NULL)
		{
	
			InitializeObjectAttributes(&objAttrib,
				dirName,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				NULL,
				NULL);
			
			ntStatus = FltCreateFile(filter,
										instance,    
										&hFile,
										GENERIC_READ | SYNCHRONIZE,
										&objAttrib,
										&ioStatus,
										0,
										FILE_ATTRIBUTE_NORMAL,
										FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
										FILE_OPEN,
										FILE_SYNCHRONOUS_IO_NONALERT,
										NULL,0,0);
			if(! NT_SUCCESS(ntStatus))
				__leave;
			
			ntStatus = ObReferenceObjectByHandle(hFile,
										FILE_ANY_ACCESS,
										NULL,
										KernelMode,
										&pFileObject,
										NULL);
			if(! NT_SUCCESS(ntStatus))		
				__leave;		
		}
		else
		{
			pFileObject = fileObject;
		}
		
		ntStatus = FltQueryInformationFileSyncronous(instance,
									pFileObject,
									&stdInfo,
									sizeof(FILE_STANDARD_INFORMATION),
									FileStandardInformation,
									NULL);
		
		if(NT_SUCCESS(ntStatus))
			*directory = stdInfo.Directory;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	if(pFileObject && !fileObject)
	{
		ObDereferenceObject(pFileObject);
		pFileObject = NULL;
	}
	
	if(hFile)
	{
		FltClose(hFile);
		hFile = NULL;
	}
	
	return ntStatus;
}

PFILE_OBJECT
SbGetFileObject(IN PCFLT_RELATED_OBJECTS FltObjects,
									IN PFLT_CALLBACK_DATA Data,
									IN BOOLEAN FEInSandbox,
									IN PUNICODE_STRING	pSandboxPath,
									OUT PFLT_INSTANCE *ppFEInstance,
									OUT HANDLE* handle)
{
	UNICODE_STRING		ustrVolumeDeviceName;
	UNICODE_STRING		ustrSrcFileName = {0, 0, NULL};
	UNICODE_STRING		ustrDstFileName = {0, 0, NULL};
	WCHAR				volumeName[MAX_PATH] = L"";
	OBJECT_ATTRIBUTES	objAttrib;
	PFILE_OBJECT		pSrcFileObject = NULL;
	NTSTATUS			ntStatus = STATUS_UNSUCCESSFUL;
	PFLT_FILE_NAME_INFORMATION		pNameInfo = NULL;
	PUNICODE_STRING		pFileName = NULL;
	HANDLE				hSrcFile = NULL;
	IO_STATUS_BLOCK		ioStatus = {0,0};

	__try
	{
		ntStatus = FltGetFileNameInformation(Data,
											 FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
											 &pNameInfo);
		if(!NT_SUCCESS(ntStatus))
			__leave;
		
		ustrVolumeDeviceName.Buffer = MyNew(WCHAR, MAX_PATH);
		if(!ustrVolumeDeviceName.Buffer)
			__leave;

		ustrVolumeDeviceName.Length  = 0;
		ustrVolumeDeviceName.MaximumLength = MAX_PATH * sizeof(WCHAR);

		if(FEInSandbox)
			ntStatus = SbConvertInSbNameToOutName(FltObjects->Filter, &pNameInfo->Name, pSandboxPath, &ustrSrcFileName, 
												&ustrVolumeDeviceName);
		else
			ntStatus = SbConvertToSbName(pSandboxPath, &pNameInfo->Name, &ustrDstFileName, 
												&ustrVolumeDeviceName);
			
		if(!NT_SUCCESS(ntStatus))
			__leave;

		*ppFEInstance = SbGetVolumeInstance(gp_Filter, &ustrVolumeDeviceName);
		if(*ppFEInstance == NULL)
			__leave;
		
		pFileName = FEInSandbox ? &ustrSrcFileName : &ustrDstFileName;

		InitializeObjectAttributes(&objAttrib,
								   pFileName,
								   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
								   NULL,
								   NULL);
		
		ntStatus = FltCreateFile(gp_Filter,
								 *ppFEInstance,
								 &hSrcFile,
								 FILE_LIST_DIRECTORY,
								 &objAttrib,
								 &ioStatus,
								 NULL,
								 FILE_ATTRIBUTE_DIRECTORY,
								 FILE_SHARE_READ | FILE_SHARE_WRITE,
								 FILE_OPEN,
								 FILE_DIRECTORY_FILE,
								 NULL,0,0);
		
		if(!NT_SUCCESS(ntStatus))
			__leave;

		ntStatus = ObReferenceObjectByHandle(hSrcFile,
											FILE_ANY_ACCESS,
											NULL,
											KernelMode,
											&pSrcFileObject,
											NULL);
		if(!NT_SUCCESS(ntStatus))
			__leave;

	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

	}
	if(pNameInfo != NULL)
	{
		FltReleaseFileNameInformation(pNameInfo);
		pNameInfo = NULL;
	}
	
	if(NULL != ustrSrcFileName.Buffer)
	{
		MyDelete(ustrSrcFileName.Buffer);
		ustrSrcFileName.Buffer = NULL;
	}
	
	if(NULL != ustrDstFileName.Buffer)
	{
		MyDelete(ustrDstFileName.Buffer);
		ustrDstFileName.Buffer = NULL;
	}
	
	if(NULL != ustrVolumeDeviceName.Buffer)
	{
		MyDelete(ustrVolumeDeviceName.Buffer);
		ustrVolumeDeviceName.Buffer = NULL;
	}
	
	if(hSrcFile != NULL)
	{
		*handle = hSrcFile;
	}

	return pSrcFileObject;
}


BOOLEAN
SBDeleteOneFile(IN	PFLT_INSTANCE Instance,
					  IN	PFLT_FILTER  filter,
					  IN	PFILE_OBJECT pFile_obj,
					  IN 	PUNICODE_STRING FEName
					)
{
	NTSTATUS						ntStatus = STATUS_UNSUCCESSFUL;
	FILE_DISPOSITION_INFORMATION 	file_disposition_info = {1};
	OBJECT_ATTRIBUTES				objAttrib;
	HANDLE							hFileEntity = NULL;
	PFILE_OBJECT					pFEFileObject = NULL;
	IO_STATUS_BLOCK					ioStatus = {0, 0};

	if(!pFile_obj && !FEName)
		return FALSE;

	if(!pFile_obj)
	{
		InitializeObjectAttributes(&objAttrib,
								FEName,
								OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
								NULL,
								NULL);

		ntStatus = FltCreateFile(filter,
							Instance,
							&hFileEntity,
							GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
							&objAttrib,
							&ioStatus,
							NULL,
							FILE_ATTRIBUTE_DIRECTORY,
							FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
							FILE_OPEN,
							FILE_SYNCHRONOUS_IO_NONALERT,
							NULL,
							0,
							0	);

		if(!NT_SUCCESS(ntStatus) || hFileEntity == NULL)
			return FALSE;
		
		ntStatus = ObReferenceObjectByHandle(hFileEntity,
											FILE_ANY_ACCESS,
											NULL,
											KernelMode,
											&pFEFileObject,
											NULL);

		if(!NT_SUCCESS(ntStatus))
		{
			FltClose(hFileEntity);
			return FALSE;
		}
	}
	ntStatus = FltSetInformationFile(Instance,
										pFile_obj?pFile_obj:pFEFileObject,
										&file_disposition_info, 
										sizeof(FILE_DISPOSITION_INFORMATION), 
										FileDispositionInformation );

	if(pFEFileObject != pFile_obj && NULL != pFEFileObject)
	{
		ObDereferenceObject(pFEFileObject);
		pFEFileObject = NULL;
	}
	
	if(NULL != hFileEntity)
	{
		FltClose(hFileEntity);
		hFileEntity = NULL;
	}
	return NT_SUCCESS(ntStatus);
}

BOOLEAN
SbCreateOneFile(
	IN		PFLT_FILTER			filter,
	IN 		PFLT_INSTANCE		instance,
	OUT		PFILE_OBJECT*		fileObject,
	IN 		PUNICODE_STRING		fileName,
	IN 		BOOLEAN				bRtFileObj,
	IN      ACCESS_MASK			access_mask,
	IN 		ULONG				createDisposition,
	IN		BOOLEAN				bDirectory)
{
	NTSTATUS			ntStatus = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES	objAttrib;
	IO_STATUS_BLOCK		ioStatus = {0, 0};
	HANDLE				hFile = NULL;
	ULONG CreateOptions = FILE_SYNCHRONOUS_IO_NONALERT;
	PFILE_OBJECT		pFileObject = NULL;
	ACCESS_MASK			AccessMack = 0;
	ULONG CreateDisposition = 0;
	
	if((!fileObject && bRtFileObj) || !fileName)
		return FALSE;

	if(bDirectory)
		CreateOptions |= FILE_DIRECTORY_FILE;

	if(!access_mask)
		AccessMack = FILE_READ_ATTRIBUTES | SYNCHRONIZE;
	else
		AccessMack = access_mask;

	if(createDisposition)
		CreateDisposition = createDisposition;
	else
		CreateDisposition = FILE_OPEN_IF;

	
	
	InitializeObjectAttributes(&objAttrib,
								   fileName,
								   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
								   NULL,
								   NULL);

	ntStatus = FltCreateFile(filter,
							instance,    
							&hFile,
							AccessMack,
							&objAttrib,
							&ioStatus,
							0,
							FILE_ATTRIBUTE_NORMAL,
							FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
							CreateDisposition,
							CreateOptions,
							NULL,
							0,
							0  );
	if(!NT_SUCCESS(ntStatus) || hFile == NULL)
		return FALSE;

	if(bRtFileObj)
	{
		ntStatus = ObReferenceObjectByHandle(hFile,
									 FILE_ANY_ACCESS,
									 NULL,
									 KernelMode,
									 fileObject,
									 NULL);
	}
	
	FltClose(hFile);
	hFile = NULL;

	return  NT_SUCCESS(ntStatus);
}

BOOLEAN
SbGetDestinationFileNameInformation(PVOID 				pInfo,
										   PUNICODE_STRING		ustrRenamedName,
										   BOOLEAN*				allocateMem
										  )
{
	BOOLEAN						rtVal 				= FALSE;
	NTSTATUS 					ntStatus 			= STATUS_SUCCESS;
	UNICODE_STRING				fileLinkName 		= {0, 0, 0};
	PFILE_RENAME_INFORMATION	pFileNameInfomation	= (PFILE_RENAME_INFORMATION)pInfo;
	*allocateMem = FALSE;
	__try
	{
		if (pFileNameInfomation->FileNameLength > MAX_PATH * sizeof(WCHAR))
			return FALSE;
		if(!pFileNameInfomation->RootDirectory)
		{
			fileLinkName.Buffer = MyNew(WCHAR, MAX_PATH + 1);
			if (fileLinkName.Buffer == NULL)
				return FALSE;
			
			fileLinkName.Length = (USHORT)pFileNameInfomation->FileNameLength;
			fileLinkName.MaximumLength = MAX_PATH * sizeof(WCHAR);
			RtlCopyMemory(fileLinkName.Buffer, pFileNameInfomation->FileName, pFileNameInfomation->FileNameLength);
			fileLinkName.Buffer[fileLinkName.Length/sizeof(WCHAR)] = 0;

			ustrRenamedName->Buffer = MyNew(WCHAR, MAX_PATH);
			if (!ustrRenamedName->Buffer)
				return FALSE;

			*allocateMem = TRUE;
			ustrRenamedName->MaximumLength = MAX_PATH * sizeof(WCHAR);
			ustrRenamedName->Length = 0;
			
			if(GetNtDeviceName(fileLinkName.Buffer, ustrRenamedName->Buffer))
				ustrRenamedName->Length = (USHORT)wcslen(ustrRenamedName->Buffer) * sizeof(WCHAR);

			rtVal = TRUE;
		}
		else
		{
			if(TlQueryObjectName(pFileNameInfomation->RootDirectory, &fileLinkName,TRUE))
			{
				ustrRenamedName->Buffer = MyNew(WCHAR, MAX_PATH);
				if (!ustrRenamedName->Buffer)
					return FALSE;
				
				*allocateMem = TRUE;
				ustrRenamedName->Length = 0;
				ustrRenamedName->MaximumLength = MAX_PATH * sizeof(WCHAR);
				RtlCopyUnicodeString(ustrRenamedName, &fileLinkName);
				ntStatus = RtlAppendUnicodeToString(ustrRenamedName, pFileNameInfomation->FileName);
				
				rtVal = NT_SUCCESS(ntStatus);
			}
		}
	}
	__finally
	{
		if(fileLinkName.Buffer != NULL)
		{
			MyDelete(fileLinkName.Buffer);
			fileLinkName.Buffer = NULL;
		}
		
		if (!rtVal&&
			ustrRenamedName->Buffer != NULL)
		{
			MyDelete(ustrRenamedName->Buffer);
			ustrRenamedName->Buffer = NULL;
			ustrRenamedName->MaximumLength = ustrRenamedName->Length = 0;
		}
	}
	return rtVal;
}


BOOL SbIsFilenameWithSandboxPrefix(WCHAR *filename)
{
	UNICODE_STRING uName;

	RtlInitUnicodeString(&uName, filename);

	return RtlPrefixUnicodeString(&g_SandboxPath, &uName, TRUE);
}

NTSTATUS SbGetFileNameInformation(
		PFLT_VOLUME		pVolume,
		PFLT_INSTANCE	pInstance,
		PFILE_OBJECT 	pFileObject,
		BOOLEAN			bGetFromCache,
		PFLT_FILE_NAME_INFORMATION	*pNameInfo
		)
{
	
	NTSTATUS			ntStatus = STATUS_UNSUCCESSFUL;
	NTSTATUS			tmpStatus = STATUS_SUCCESS;
	PWCHAR				wszName = NULL;
	PWCHAR				tmpName = NULL;
	UNICODE_STRING		ustrVolumeName={0,0,NULL};
	UNICODE_STRING		ustrFileName={0,0,NULL};
	PWSTR				pFinalName = NULL;  
	PFILE_OBJECT 		pTmpFileObject = NULL;
	ULONG				uRet = 0;
	BOOLEAN 			bParentObjects = FALSE;
	PFLT_FILE_NAME_INFORMATION		pName = NULL;
	
	__try
	{
		if( pVolume == NULL ||
		    pFileObject == NULL ||
		    pNameInfo == NULL )
		    __leave;
		
		wszName = MyNew(WCHAR, MAX_PATH);
		if(!wszName)
			__leave;
		
		tmpName = MyNew(WCHAR, MAX_PATH);
		if(!tmpName)
			__leave;
		
		pName = (PFLT_FILE_NAME_INFORMATION)MyNew(BYTE, MAX_PATH * sizeof(WCHAR)+ sizeof(FLT_FILE_NAME_INFORMATION));
		if(pName == NULL)
			__leave;
		wszName[0] = 0;
		tmpName[0] = 0;
		ustrVolumeName.Buffer = MyNew(WCHAR, MAX_PATH);
		if(ustrVolumeName.Buffer == NULL)
		{
			MyDelete(pName);
			__leave;
		}
		ustrVolumeName.Length = 0;
		ustrVolumeName.MaximumLength = MAX_PATH * sizeof(WCHAR);
		
		tmpStatus = FltGetVolumeName(pVolume,
									 &ustrVolumeName,
									 &uRet);
		if(! NT_SUCCESS(tmpStatus))
		{
			MyDelete(pName);
			__leave;
		}
		
		if (bGetFromCache && pFileObject->RelatedFileObject)
		{
			PFILE_STREAMHANDLE_CONTEXT pStreamHandleContext = NULL;
			ntStatus = FltGetStreamHandleContext(pInstance,
												 pFileObject,
												 &pStreamHandleContext);
			if(!NT_SUCCESS( ntStatus))
			{
				MyDelete(pName);
				pName = NULL;
				__leave;
			}
			
			if (pStreamHandleContext->m_FileName[0]!=0)
			{
				RtlCopyMemory(tmpName, pStreamHandleContext->m_FileName, (MAX_PATH-1)*sizeof(WCHAR));
				tmpName[MAX_PATH -1] = 0;
				FltReleaseContext(pStreamHandleContext);
			}
			else
			{
				MyDelete(pName);
				pName = NULL;
				FltReleaseContext(pStreamHandleContext);
				ntStatus = STATUS_NOT_FOUND;
				__leave;
			}
		}
		else
		{
			pTmpFileObject = pFileObject;
			while(pTmpFileObject != NULL && pTmpFileObject->FileName.Length > 0
				&& pTmpFileObject->Type == IO_TYPE_FILE)
			{		
				RtlZeroMemory(tmpName, MAX_PATH * sizeof(WCHAR) );
				
				tmpStatus = RtlStringCbCopyNW(tmpName,
								   			  MAX_PATH*sizeof(WCHAR),
								   			  pTmpFileObject->FileName.Buffer,
								   			  pTmpFileObject->FileName.Length);
				if(! NT_SUCCESS(tmpStatus))
					break;
				if (bParentObjects )
				{
					if (pTmpFileObject->FileName.Length >= sizeof(WCHAR)&&
						pTmpFileObject->FileName.Buffer[pTmpFileObject->FileName.Length / sizeof(WCHAR) -1] != L'\\'&&
						wszName[0] != '\\')
					{
						RtlStringCchCatW(tmpName, MAX_PATH, L"\\");
					}
					
				}
				else
					bParentObjects = TRUE;
				tmpStatus = RtlStringCchCatW(tmpName,
								 			 MAX_PATH,
								 			 wszName);
				if(! NT_SUCCESS(tmpStatus))
					break;

				tmpName[MAX_PATH-1] = 0;
				RtlZeroMemory(wszName, MAX_PATH * sizeof(WCHAR) );
				
				tmpStatus = RtlStringCchCopyW(wszName,
								   			  MAX_PATH,
								   			  tmpName);
				if(! NT_SUCCESS(tmpStatus))
					break;

				wszName[MAX_PATH-1] = 0;
				pTmpFileObject = pTmpFileObject->RelatedFileObject;
			}
			
			if(! NT_SUCCESS(tmpStatus))
			{
				MyDelete(pName);
				__leave;
			}
			
			RtlZeroMemory(tmpName, MAX_PATH * sizeof(WCHAR) );
			
			tmpStatus = RtlStringCbCopyNW(tmpName,
								   		  MAX_PATH*sizeof(WCHAR),
								   		  ustrVolumeName.Buffer,
										  ustrVolumeName.Length);
			if(! NT_SUCCESS(tmpStatus))
			{
				MyDelete(pName);
				__leave;
			}
			
			tmpStatus = RtlStringCchCatW(tmpName,
										 MAX_PATH,
										 wszName);
			if(! NT_SUCCESS(tmpStatus))
			{
				MyDelete(pName);	
				__leave;
			}
		}
		pFinalName = tmpName;
		
		RtlInitUnicodeString(&ustrFileName, pFinalName);
		
		
		if(ustrFileName.Length < MAX_PATH*sizeof(WCHAR) )
		{
			pName->Size = sizeof(FLT_FILE_NAME_INFORMATION);
			pName->NamesParsed = 0; 
			pName->Format = FLT_FILE_NAME_NORMALIZED;
			
			pName->Name.Buffer = (PWSTR)( (PBYTE)pName+sizeof(FLT_FILE_NAME_INFORMATION)+sizeof(USHORT)*2 );
			pName->Name.Length = ustrFileName.Length;
			pName->Name.MaximumLength = pName->Name.Length;
			RtlCopyMemory(pName->Name.Buffer, ustrFileName.Buffer, ustrFileName.Length);
			
			pName->Volume.Buffer = pName->Name.Buffer;
			pName->Volume.Length = ustrVolumeName.Length;
			pName->Volume.MaximumLength  = pName->Volume.Length;
			
			*pNameInfo = pName;
								   		  
			ntStatus = STATUS_SUCCESS;
		}
		else
		{
			MyDelete(pName);
			pName = NULL;
			ntStatus = STATUS_UNSUCCESSFUL;
		}
	}
	
	
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		*pNameInfo = NULL;
		ntStatus = STATUS_UNSUCCESSFUL;
		
		if(pName != NULL)
		{
			MyDelete(pName);
			pName = NULL;
		}
		
	}

	if(ustrVolumeName.Buffer != NULL)
		MyDelete(ustrVolumeName.Buffer);

	if(NULL != wszName)
		MyDelete(wszName);

	if(NULL != tmpName)
		MyDelete(tmpName);
	
	return ntStatus;
}


VOID
SbCleanContextCallback(
					   IN PFLT_CONTEXT  Context,
					   IN FLT_CONTEXT_TYPE  ContextType
					   )
{
	PFILE_STREAMHANDLE_CONTEXT pStreamHandleContext = (PFILE_STREAMHANDLE_CONTEXT)Context;
	
	if(FLT_STREAMHANDLE_CONTEXT != ContextType)
		return;
	
	if(NULL != pStreamHandleContext->outSideSbFileObj)
	{
		ObDereferenceObject(pStreamHandleContext->outSideSbFileObj);
		pStreamHandleContext->outSideSbFileObj = NULL;
	}
}

BOOL SbOperWillModifyFile(ACCESS_MASK DesiredAccess)
{
	if(DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA))
		return TRUE;
	
	if(DesiredAccess & (DELETE | WRITE_OWNER | WRITE_DAC | GENERIC_WRITE))
		return TRUE;
	
	return FALSE;
}

