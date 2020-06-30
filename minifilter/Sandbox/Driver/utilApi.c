#include "precom.h"

//输入\\??\\c:-->\\device\\\harddiskvolume1
//LinkTarget.Buffer注意要释放

NTSTATUS QuerySymbolicLink(
			IN PUNICODE_STRING SymbolicLinkName,
			OUT PUNICODE_STRING LinkTarget
			)                                  
{
	OBJECT_ATTRIBUTES	oa		= {0};
	NTSTATUS			status	= 0;
	HANDLE				handle	= NULL;

	InitializeObjectAttributes(
							&oa, 
							SymbolicLinkName,
							OBJ_CASE_INSENSITIVE,
							0, 
							0);

	status = ZwOpenSymbolicLinkObject(&handle, GENERIC_READ, &oa);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	LinkTarget->MaximumLength = MAX_PATH*sizeof(WCHAR);
	LinkTarget->Length = 0;
	LinkTarget->Buffer = ExAllocatePoolWithTag(PagedPool, LinkTarget->MaximumLength,'SOD');
	if (!LinkTarget->Buffer)
	{
		ZwClose(handle);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(LinkTarget->Buffer, LinkTarget->MaximumLength);

	status = ZwQuerySymbolicLinkObject(handle, LinkTarget, NULL);
	ZwClose(handle);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(LinkTarget->Buffer);
	}

	return status;
}

//输入\\Device\\harddiskvolume1
//输出C:
//DosName.Buffer的内存记得释放

NTSTATUS
MyRtlVolumeDeviceToDosName(
						IN PUNICODE_STRING DeviceName,
						OUT PUNICODE_STRING DosName
						)

/*++

Routine Description:

This routine returns a valid DOS path for the given device object.
This caller of this routine must call ExFreePool on DosName->Buffer
when it is no longer needed.

Arguments:

VolumeDeviceObject - Supplies the volume device object.
DosName - Returns the DOS name for the volume
Return Value:

NTSTATUS

--*/

{
	NTSTATUS				status					= 0;
	UNICODE_STRING			driveLetterName			= {0};
	WCHAR					driveLetterNameBuf[128] = {0};
	WCHAR					c						= L'\0';
	WCHAR					DriLetter[3]			= {0};
	UNICODE_STRING			linkTarget				= {0};

	for (c = L'A'; c <= L'Z'; c++)
	{
		RtlInitEmptyUnicodeString(&driveLetterName,driveLetterNameBuf,sizeof(driveLetterNameBuf));
		RtlAppendUnicodeToString(&driveLetterName, L"\\??\\");
		DriLetter[0] = c;
		DriLetter[1] = L':';
		DriLetter[2] = 0;
		RtlAppendUnicodeToString(&driveLetterName,DriLetter);

		status = QuerySymbolicLink(&driveLetterName, &linkTarget);
		if (!NT_SUCCESS(status))
		{
			continue;
		}

		if (RtlEqualUnicodeString(&linkTarget, DeviceName, TRUE))
		{
			ExFreePool(linkTarget.Buffer);
			break;
		}

		ExFreePool(linkTarget.Buffer);
	}

	if (c <= L'Z')
	{
		DosName->Buffer = ExAllocatePoolWithTag(PagedPool, 3*sizeof(WCHAR), 'SOD');
		if (!DosName->Buffer)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		DosName->MaximumLength = 6;
		DosName->Length   = 4;
		*DosName->Buffer  = c;
		*(DosName->Buffer+ 1) = ':';
		*(DosName->Buffer+ 2) = 0;

		return STATUS_SUCCESS;
	}

	return status;
} 

//c:\\windows\\hi.txt<--\\device\\harddiskvolume1\\windows\\hi.txt
BOOL NTAPI GetNTLinkName(WCHAR *wszNTName, WCHAR *wszFileName)
{
	UNICODE_STRING		ustrFileName = {0};
	UNICODE_STRING		ustrDosName = {0};
	UNICODE_STRING		ustrDeviceName = {0};

	WCHAR				*pPath = NULL;
	ULONG				i = 0;
	ULONG				ulSepNum = 0;


	if (wszFileName == NULL ||
		wszNTName == NULL ||
		_wcsnicmp(wszNTName, L"\\device\\harddiskvolume", wcslen(L"\\device\\harddiskvolume"))!=0)
	{
		return FALSE;
	}

	ustrFileName.Buffer = wszFileName;
	ustrFileName.Length = 0;
	ustrFileName.MaximumLength = sizeof(WCHAR)*MAX_PATH;

	while(wszNTName[i]!=L'\0')
	{

		if (wszNTName[i] == L'\0')
		{
			break;
		}
		if (wszNTName[i] == L'\\')
		{
			ulSepNum++;
		}
		if (ulSepNum == 3)
		{
			wszNTName[i] = UNICODE_NULL;
			pPath = &wszNTName[i+1];
			break;
		}
		i++;
	}

	if (pPath == NULL)
	{
		return FALSE;
	}

	RtlInitUnicodeString(&ustrDeviceName, wszNTName);

	if (!NT_SUCCESS(MyRtlVolumeDeviceToDosName(&ustrDeviceName, &ustrDosName)))
	{
		return FALSE;
	}

	RtlCopyUnicodeString(&ustrFileName, &ustrDosName);
	RtlAppendUnicodeToString(&ustrFileName, L"\\");
	RtlAppendUnicodeToString(&ustrFileName, pPath);

	ExFreePool(ustrDosName.Buffer);

	return TRUE;
}

BOOL QueryVolumeName(WCHAR ch, WCHAR * name, USHORT size)
{
	WCHAR szVolume[7] = L"\\??\\C:";
	UNICODE_STRING LinkName;
	UNICODE_STRING VolName;
	UNICODE_STRING ustrTarget;
	NTSTATUS ntStatus = 0;
	
	RtlInitUnicodeString(&LinkName, szVolume);
	
	szVolume[4] = ch;

	ustrTarget.Buffer = name;
	ustrTarget.Length = 0;
	ustrTarget.MaximumLength = size;
	
	ntStatus = QuerySymbolicLink(&LinkName, &VolName);
	if (NT_SUCCESS(ntStatus))
	{
		RtlCopyUnicodeString(&ustrTarget, &VolName);
		ExFreePool(VolName.Buffer);
	}
	return NT_SUCCESS(ntStatus);
	
}

//\\??\\c:\\windows\\hi.txt-->\\device\\harddiskvolume1\\windows\\hi.txt

BOOL NTAPI GetNtDeviceName(WCHAR * filename, WCHAR * ntname)
{
	UNICODE_STRING uVolName = {0,0,0};
	WCHAR volName[MAX_PATH] = L"";
	WCHAR tmpName[MAX_PATH] = L"";
	WCHAR chVol = L'\0';
	WCHAR * pPath = NULL;
	int i = 0;
	

	RtlStringCbCopyW(tmpName, MAX_PATH * sizeof(WCHAR), filename);
	
	for(i = 1; i < MAX_PATH - 1; i++)
	{
		if(tmpName[i] == L':')
		{
			pPath = &tmpName[(i + 1) % MAX_PATH];
			chVol = tmpName[i - 1];
			break;
		}
	}
	
	if(pPath == NULL)
	{
		return FALSE;
	}
	
	if(chVol == L'?')
	{
		uVolName.Length = 0;
		uVolName.MaximumLength = MAX_PATH * sizeof(WCHAR);
		uVolName.Buffer = ntname;
		RtlAppendUnicodeToString(&uVolName, L"\\Device\\HarddiskVolume?");
		RtlAppendUnicodeToString(&uVolName, pPath);
		return TRUE;
	}
	else if(QueryVolumeName(chVol, volName, MAX_PATH * sizeof(WCHAR)))
	{
		uVolName.Length = 0;
		uVolName.MaximumLength = MAX_PATH * sizeof(WCHAR);
		uVolName.Buffer = ntname;
		RtlAppendUnicodeToString(&uVolName, volName);
		RtlAppendUnicodeToString(&uVolName, pPath);
		return TRUE;
	}
	
	return FALSE;
}

BOOL TlObQueryObjectName(PVOID pObject, PUNICODE_STRING objName, BOOL allocateName)
{
	PVOID buffer = NULL;
	DWORD reqSize = 0;
	NTSTATUS status = 0;
	__try
	{
		reqSize = sizeof(OBJECT_NAME_INFORMATION) + (MAX_PATH + 32)*sizeof(WCHAR);

		buffer = ExAllocatePoolWithTag(PagedPool, reqSize, 'rtpR');

		if(buffer == NULL)
			return FALSE;

		status = ObQueryNameString(pObject, 
								   buffer,
								   reqSize,
								   &reqSize);

		if((status == STATUS_INFO_LENGTH_MISMATCH) ||
		   (status == STATUS_BUFFER_OVERFLOW) ||
		   (status == STATUS_BUFFER_TOO_SMALL))
		{
			ExFreePool(buffer);
			buffer = NULL;

			buffer = ExAllocatePoolWithTag(PagedPool, reqSize, 'rtpR');

			if(buffer == NULL)
			{
				return FALSE;
			}
			
			status = ObQueryNameString(pObject, 
								   buffer,
								   reqSize,
								   &reqSize);

		}

		if(NT_SUCCESS(status))
		{ 
			OBJECT_NAME_INFORMATION * pNameInfo = (OBJECT_NAME_INFORMATION *)buffer;

			if(allocateName)
			{
				objName->Buffer = ExAllocatePoolWithTag(PagedPool, pNameInfo->Name.Length + sizeof(WCHAR), 'rtpR');
		
				if(objName->Buffer)
				{
					RtlZeroMemory(objName->Buffer, pNameInfo->Name.Length + sizeof(WCHAR));
					objName->Length = 0;
					objName->MaximumLength = pNameInfo->Name.Length;
					RtlCopyUnicodeString(objName, &pNameInfo->Name);
				}
				else
					status = STATUS_INSUFFICIENT_RESOURCES;
				
			}
			else
				RtlCopyUnicodeString(objName, &pNameInfo->Name);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
	}

	if(buffer)
	{
		ExFreePool(buffer);
		buffer = NULL;
	}

	return NT_SUCCESS(status);
}

BOOL TlQueryObjectName(HANDLE objHandle, PUNICODE_STRING objName, BOOL allocateName)
{
	PVOID buffer = NULL;
	DWORD reqSize = 0;
	NTSTATUS status = 0;
	__try
	{
		reqSize = sizeof(OBJECT_NAME_INFORMATION) + (MAX_PATH + 32)*sizeof(WCHAR);

		buffer = ExAllocatePoolWithTag(PagedPool, reqSize, 'rtpR');

		if(buffer == NULL)
			return FALSE;

		status = ZwQueryObject(objHandle, 
								ObjectNameInfo,
								buffer,
								reqSize,
								&reqSize);

		if((status == STATUS_INFO_LENGTH_MISMATCH) ||
		   (status == STATUS_BUFFER_OVERFLOW) ||
		   (status == STATUS_BUFFER_TOO_SMALL))
		{
			ExFreePool(buffer);
			buffer = NULL;

			buffer = ExAllocatePoolWithTag(PagedPool, reqSize, 'rtpR');

			if(buffer == NULL)
			{
				return FALSE;
			}
			
			status = ZwQueryObject(objHandle, 
									ObjectNameInfo,
									buffer,
									reqSize,
									&reqSize);
		}

		if(NT_SUCCESS(status))
		{ 
			OBJECT_NAME_INFORMATION * pNameInfo = (OBJECT_NAME_INFORMATION *)buffer;

			if(allocateName)
			{
				objName->Buffer = ExAllocatePoolWithTag(PagedPool, pNameInfo->Name.Length + sizeof(WCHAR), 'rtpR');
		
				if(objName->Buffer)
				{
					RtlZeroMemory(objName->Buffer, pNameInfo->Name.Length + sizeof(WCHAR));
					objName->Length = 0;
					objName->MaximumLength = pNameInfo->Name.Length;
					RtlCopyUnicodeString(objName, &pNameInfo->Name);
				}
				else
					status = STATUS_INSUFFICIENT_RESOURCES;
				
			}
			else
				RtlCopyUnicodeString(objName, &pNameInfo->Name);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
	}

	if(buffer)
	{
		ExFreePool(buffer);
		buffer = NULL;
	}

	return NT_SUCCESS(status);
}


static int __inline ToLower(int c)
{
    if ((c >= L'A') && (c <= L'Z'))
    {
        return(c + (L'a' - L'A'));
    }
    else
    {
        return(c);
    }
}


BOOL RtlPatternMatch(WCHAR * pat, WCHAR * str)
{
   register WCHAR * s;
   register WCHAR * p;
   BOOL star = FALSE;

loopStart:
   for (s = str, p = pat; *s; ++s, ++p) {
      switch (*p) {
         case L'?':
            if (*s == L'.') goto starCheck;
            break;
         case L'*':
            star = TRUE;
            str = s, pat = p;
            if (!*++pat) return TRUE;
            goto loopStart;
         default:
            if (ToLower(*s) != ToLower(*p))
               goto starCheck;
            break;
      } 
   } 
   if (*p == L'*') ++p;
   return (!*p);

starCheck:
   if (!star) return FALSE;
   str++;
   goto loopStart;
}

BOOL RtlPatternNMatch(WCHAR * pat, WCHAR * str, DWORD count)
{
   register WCHAR * s;
   register WCHAR * p;
   BOOL star = FALSE;
   DWORD dwCount = count;

loopStart:
   for (s = str, p = pat; dwCount>0; --dwCount, ++s, ++p) {
      switch (*p) {
         case L'?':
            if (*s == L'.') goto starCheck;
            break;
         case L'*':
            star = TRUE;
            str = s, pat = p;
            if (!*++pat) return TRUE;
            goto loopStart;
         default:
            if (ToLower(*s) != ToLower(*p))
               goto starCheck;
            break;
      } 
   } 
   if (*p == L'*') ++p;
   return (!*p);

starCheck:
   if (!star) return FALSE;
   str++;
   dwCount--;
   goto loopStart;
}

BOOL TlIsNtDeviceName(WCHAR * filename)
{
	DECLARE_CONST_UNICODE_STRING(dev, L"\\Device\\");
	UNICODE_STRING uName;

	RtlInitUnicodeString(&uName, filename);
	return RtlPrefixUnicodeString(&dev, &uName, TRUE);
}

BOOL TlIsDosName(WCHAR * filename)
{
	int i = 0;

	for(i = 0; i < MAX_PATH; i++)
	{
		if(filename[i] == L'\0')
			break;

		if((filename[i] == L':') && ((i == 1) || ( i == 5)))
		{
			return TRUE;
		}
	}

	return FALSE;
}

BOOL TlIsShortName(WCHAR * filename)
{
	int i = 0;

	for(i = 0; i < MAX_PATH; i++)
	{
		if(filename[i] == L'\0')
			break;

		if(filename[i] == L'~')
		{
			return TRUE;
		}
	}

	return FALSE;
}

NTSTATUS TlQuerySymbolicLinkName(PUNICODE_STRING SymbolicLinkName, 
								 PUNICODE_STRING LinkTarget)
{
	OBJECT_ATTRIBUTES oa; 
	NTSTATUS status = 0; 
	HANDLE LinkHandle = 0; 

	InitializeObjectAttributes(&oa, 
							   SymbolicLinkName, 
							   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
							   0, 
							   0); 

	status = ZwOpenSymbolicLinkObject(&LinkHandle, GENERIC_READ, &oa); 

	if (!NT_SUCCESS(status)) 
	{ 
		return status; 
	} 


	status = ZwQuerySymbolicLinkObject(LinkHandle, LinkTarget, NULL); 
	ZwClose(LinkHandle); 
	return status; 
}

BOOL TlQueryVolumeName(WCHAR ch, WCHAR * name, USHORT size)
{
	WCHAR szVolume[7] = L"\\??\\C:";
	UNICODE_STRING LinkName;
	UNICODE_STRING VolName;

	RtlInitUnicodeString(&LinkName, szVolume);

	VolName.Buffer = name;
	VolName.Length = 0;
	VolName.MaximumLength = size;

	szVolume[4] = ch;

	return NT_SUCCESS(TlQuerySymbolicLinkName(&LinkName, &VolName));
}

NTSTATUS
  FltIsDirectorySafe(
    IN PFILE_OBJECT  FileObject,
    IN PFLT_INSTANCE  Instance,
    OUT PBOOLEAN  IsDirectory
    )
{
	PFSRTL_ADVANCED_FCB_HEADER FsRtlHeaderPtr = (PFSRTL_ADVANCED_FCB_HEADER)FileObject->FsContext;

	if(FsRtlHeaderPtr)
	{
		__try
		{
			if(MmIsAddressValid(FsRtlHeaderPtr))
			{
				if(FsRtlHeaderPtr->NodeTypeCode == 0x1029)
				{
					return STATUS_INVALID_DEVICE_REQUEST;
				}
			}
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{

		}
	}

	return FltIsDirectory(FileObject, Instance, IsDirectory);
}

BOOL TlIsFileExist(IN PFLT_FILTER		Filter,
					 IN PFLT_INSTANCE  	Instance,
					 IN PUNICODE_STRING	pustrFileName)
{
	BOOL					bResult = FALSE;
	NTSTATUS				ntStatus = 0;
	IO_STATUS_BLOCK			ioStatus = {0, 0};
	HANDLE					hFile = 0;
	OBJECT_ATTRIBUTES		objAttr;
	
	__try
	{
		InitializeObjectAttributes(
			&objAttr,
			pustrFileName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			NULL
			);
		
		ntStatus = FltCreateFile(
			Filter,
			Instance,    
			&hFile,
			GENERIC_READ,
			&objAttr,
			&ioStatus,
			0,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0,
			0);

		if(!NT_SUCCESS(ntStatus))
		{
			if(ntStatus == STATUS_SHARING_VIOLATION)
				bResult = TRUE;
				
			__leave;
		}

		FltClose(hFile);
			
		if(ioStatus.Information == FILE_OPENED)
			bResult = TRUE;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ntStatus = STATUS_UNSUCCESSFUL;
	}
	
	return bResult;
}


BOOL TlCanAccessChangeFile(ACCESS_MASK DesiredAccess)
{
	if(DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA))
		return TRUE;

	if(DesiredAccess & (DELETE | WRITE_OWNER | WRITE_DAC | GENERIC_WRITE))
		return TRUE;

	return FALSE;
}



extern LIST_ENTRY g_PROCESS_LIST_ENTRYList;
extern FAST_MUTEX g_PROCESS_LIST_ENTRYListLock;

BOOL SbShouldBeSandBoxed(HANDLE pid)
{
	WCHAR szProcessName[MAX_PATH] = {0};
	UNICODE_STRING ustrProcessName = {0};
	WCHAR *pBeginCompare = NULL;

	PLIST_ENTRY plistHead;
	PLIST_ENTRY pList = NULL;
	PPROCESS_LIST_ENTRY tmpEntry = NULL;

	ustrProcessName.Buffer = szProcessName;
	ustrProcessName.Length = 0;
	ustrProcessName.MaximumLength = sizeof(szProcessName);

	if (NT_SUCCESS(GetProcessFullNameByPid(pid, &ustrProcessName)))
	{
		//ExAcquireFastMutex(&g_PROCESS_LIST_ENTRYListLock);


		plistHead = &g_PROCESS_LIST_ENTRYList;
		for(pList = plistHead ->Flink; pList != plistHead; pList = pList->Flink)
		{
			tmpEntry = CONTAINING_RECORD(pList, PROCESS_LIST_ENTRY, Entry);
// 			if (wcsstr(szProcessName, tmpEntry->NameBuffer))
// 			{
// 				return TRUE;
// 			}
// 
			pBeginCompare = szProcessName + wcslen(szProcessName) - wcslen(tmpEntry->NameBuffer);
			if (_wcsnicmp(pBeginCompare, tmpEntry->NameBuffer, wcslen(tmpEntry->NameBuffer)) == 0)
			{
				//ExReleaseFastMutex(&g_PROCESS_LIST_ENTRYListLock);
				return TRUE;
			}

		}

		//ExReleaseFastMutex(&g_PROCESS_LIST_ENTRYListLock);	

	}

	return FALSE;
}

NTSTATUS
FltQueryInformationFileSyncronous (
    IN PFLT_INSTANCE Instance,
    IN PFILE_OBJECT FileObject,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass,
    OUT PULONG LengthReturned OPTIONAL
    )

/*++

Routine Description:

    This routine returns the requested information about a specified file.
    The information returned is determined by the FileInformationClass that
    is specified, and it is placed into the caller's FileInformation buffer.

Arguments:

    Instance - Supplies the Instance initiating this IO.

    FileObject - Supplies the file object about which the requested
        information should be returned.

    FileInformationClass - Specifies the type of information which should be
        returned about the file.

    Length - Supplies the length, in bytes, of the FileInformation buffer.

    FileInformation - Supplies a buffer to receive the requested information
        returned about the file.  This must be a buffer allocated from kernel
        space.

    LengthReturned - the number of bytes returned if the operation was
        successful.

Return Value:

    The status returned is the final completion status of the operation.

--*/

{
#if (NTDDI_VERSION >= NTDDI_LONGHORN)

	return FltQueryInformationFile(Instance,
									FileObject,
									FileInformation,
									Length,
									FileInformationClass,
									LengthReturned
									);

#else

    PFLT_CALLBACK_DATA data;
    NTSTATUS status;

    PAGED_CODE();

    status = FltAllocateCallbackData( Instance, FileObject, &data );

    if (!NT_SUCCESS( status )) {

        return status;
    }

    //
    //  Fill out callback data
    //

    data->Iopb->MajorFunction = IRP_MJ_QUERY_INFORMATION;
    data->Iopb->Parameters.QueryFileInformation.FileInformationClass = FileInformationClass;
    data->Iopb->Parameters.QueryFileInformation.Length = Length;
    data->Iopb->Parameters.QueryFileInformation.InfoBuffer = FileInformation;
    data->Iopb->IrpFlags = IRP_SYNCHRONOUS_API;


    FltPerformSynchronousIo( data );

    //
    //  Return Results
    //

    status = data->IoStatus.Status;

    if (NT_SUCCESS( status ) &&
        ARGUMENT_PRESENT(LengthReturned)) {

        *LengthReturned = (ULONG) data->IoStatus.Information;
    }

    FltFreeCallbackData( data );

    return status;
#endif
}

BOOL IsRootDirecotry(WCHAR * wszDir)
{
	SIZE_T length = wcslen(wszDir);
	
	// c:
	if((length == 2) && (wszDir[1] == L':'))
		return TRUE;
	//\\??\\c:
	if((length == 6) && 
		(_wcsnicmp(wszDir, L"\\??\\", 4) == 0) &&
		(wszDir[5] == L':'))
		return TRUE;
	//\\DosDevices\\c:
	if((length == 14) && 
		(_wcsnicmp(wszDir, L"\\DosDevices\\", 12) == 0) &&
		(wszDir[13] == L':'))
		return TRUE;
	//\\Device\\HarddiskVolume1
	if((length == 23) &&
		(_wcsnicmp(wszDir, L"\\Device\\HarddiskVolume", 22) == 0))
		return TRUE;
	
	
	return FALSE;
}


BOOL IsCharDirSep(WCHAR ch) 
{
    return (ch == L'\\' || ch == L'/');
}

//C:\\Program\\123456~1
//wszRootdir为:c:\\Program
//wszShortName为：123456~1

BOOL QueryDirShortForLongName(
					  WCHAR * wszRootDir, 
					  WCHAR * wszShortName, 
					  WCHAR *wszLongName, 
					  ULONG ulSize)
{
	UNICODE_STRING				ustrRootDir		= {0};
	UNICODE_STRING				ustrShortName	= {0};
	UNICODE_STRING				ustrLongName	= {0};
	OBJECT_ATTRIBUTES			oa				= {0};
	IO_STATUS_BLOCK				Iosb			= {0};
	NTSTATUS					ntStatus		= 0;
	HANDLE						hDirHandle		= 0;
	BYTE						*Buffer			= NULL;
	WCHAR						*wszRoot		= NULL;
	PFILE_BOTH_DIR_INFORMATION	pInfo			= NULL;

	RtlZeroMemory(&Iosb, sizeof(IO_STATUS_BLOCK));
	Iosb.Status = STATUS_NO_SUCH_FILE;

	wszRoot = ExAllocatePoolWithTag(PagedPool,
								  MAX_PATH * sizeof(WCHAR),
								  'L2S');
	if(wszRoot == NULL)
	{
		return FALSE;
	}

	RtlZeroMemory(wszRoot, MAX_PATH * sizeof(WCHAR));

	wcsncpy(wszRoot, wszRootDir, MAX_PATH);

	RtlInitUnicodeString(&ustrRootDir, wszRoot);
	RtlInitUnicodeString(&ustrShortName, wszShortName);

	if(IsRootDirecotry(wszRoot))
		RtlAppendUnicodeToString(&ustrRootDir, L"\\");

	InitializeObjectAttributes(&oa,
							   &ustrRootDir,
							   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
							   0, 
							   0);  
	
	ntStatus = ZwCreateFile(&hDirHandle,
							GENERIC_READ | SYNCHRONIZE,
							&oa,
							&Iosb,
							0, 
							FILE_ATTRIBUTE_DIRECTORY, 
							FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
							FILE_OPEN, 
							FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT , 
							0,
							0);

	if (!NT_SUCCESS(ntStatus)) 
	{ 
		ExFreePool(wszRoot);
		return FALSE;
	}

	ExFreePool(wszRoot);

	Buffer = ExAllocatePoolWithTag(PagedPool,
						  1024,
						  'L2S');
	if(Buffer == NULL)
	{
		ZwClose(hDirHandle);
		return FALSE;
	}

	RtlZeroMemory(Buffer, 1024);

	ntStatus = ZwQueryDirectoryFile(hDirHandle,
								NULL,
								0,
								0,
								&Iosb,
								Buffer,
								1024,
								FileBothDirectoryInformation,
								TRUE,
								&ustrShortName, //传回与 ustrShortName Match的项
								TRUE);

	if (!NT_SUCCESS(ntStatus)) 
	{
		ExFreePool(Buffer);
		ZwClose(hDirHandle);
		return FALSE;
	}

	ZwClose(hDirHandle);

	pInfo = (PFILE_BOTH_DIR_INFORMATION) Buffer;
	
	if(pInfo->FileNameLength == 0)
	{
		ExFreePool(Buffer);
		return FALSE;
	}

	ustrShortName.Length  = (USHORT)pInfo->FileNameLength;
	ustrShortName.MaximumLength = (USHORT)pInfo->FileNameLength;
	ustrShortName.Buffer = pInfo->FileName;	//长名

	if(ulSize < ustrShortName.Length)
	{	
		ExFreePool(Buffer);
		return FALSE;
	}

	ustrLongName.Length = 0;
	ustrLongName.MaximumLength = (USHORT)ulSize;
	ustrLongName.Buffer = wszLongName;

	RtlCopyUnicodeString(&ustrLongName, &ustrShortName);
	ExFreePool(Buffer);
	return TRUE;
}

BOOL QueryPathForLongName(WCHAR * wszFullPath, WCHAR * wszLongName, ULONG size)
{
	BOOL		rtn				= FALSE;
	WCHAR *		pchStart		= wszFullPath;
	WCHAR *		pchEnd			= NULL;
	WCHAR *		wszShortName	= NULL;
	
	//c:\\Program\\Files1~1-->获得Files1~1的长名
	while(*pchStart)
	{
		if(IsCharDirSep(*pchStart))
			pchEnd = pchStart;
		
		pchStart++;
	}
	//wszFullPath=c:\\Program
	//pchEnd = Files~1
	
	if(pchEnd)
	{
		*pchEnd++ = L'\0';
		//c:\\Program\\Files1~1
		//wszFullPath:c:\\Program
		//pchEnd:Files1~1
		wszShortName = pchEnd;
		rtn = QueryDirShortForLongName(wszFullPath, wszShortName, wszLongName, size);
		*(--pchEnd) = L'\\';
		//wszFullPath=c:\\Program\\Files1~1
	}
	return rtn;
}

//先把根目录拷贝到目标目录中，剩下的找到下一级目录是否含有~，如果有，则开始转化。
//如：c:\\Progam\\a~1\\b~1\hi~1.txt
//pchStart指向目录中前一个\\,pchEnd扫描并指向目录的下一个\\，其中如果发现了~，则是短名，需要转换。
//传c:\\Program\\a~1-->c:\\Progam\\ax
//传c:\\Program\\ax\\b~1-->c:\\Program\\ax\\by
//传c:\\Program\\ax\by\\hi~1.txt-->c:\\Program\\ax\by\\hiz.txt
BOOL ConverShortToLongName(WCHAR *wszLongName, WCHAR *wszShortName, ULONG size)
{
	WCHAR			*szResult		= NULL;
	WCHAR			*pToReslt		= NULL;
	WCHAR			*pchStart		= wszShortName;
	INT				nOffset			= 0;
  
	szResult = ExAllocatePoolWithTag(PagedPool,
						  sizeof(WCHAR) * (MAX_PATH * 2 + 1),
						  'L2S');

	if(szResult == NULL)
	{
		return FALSE;
	}
	
	RtlZeroMemory(szResult, sizeof(WCHAR) * (MAX_PATH * 2 + 1));
	pToReslt = szResult;


	//C:\\x\\-->\\??\\c:
	if (pchStart[0] && pchStart[1] == L':') 
	{
		*pToReslt++ = L'\\';
		*pToReslt++ = L'?';
		*pToReslt++ = L'?';
		*pToReslt++ = L'\\';
		*pToReslt++ = *pchStart++;
		*pToReslt++ = *pchStart++;
		nOffset = 4;
	}
	//\\DosDevices\\c:\\xx-->\\??\\c:
	else if (_wcsnicmp(pchStart, L"\\DosDevices\\", 12) == 0)
	{
		RtlStringCbCopyW(pToReslt, sizeof(WCHAR) * (MAX_PATH * 2 + 1), L"\\??\\");
		pToReslt += 4;
		pchStart += 12;
		while (*pchStart && !IsCharDirSep(*pchStart))
			*pToReslt++ = *pchStart++;
		nOffset = 4;
	}
	//\\Device\\HarddiskVolume1\\xx-->\\Device\\HarddiskVolume1
	else if (_wcsnicmp(pchStart, L"\\Device\\HardDiskVolume", 22) == 0)
	{
		RtlStringCbCopyW(pToReslt, sizeof(WCHAR) * (MAX_PATH * 2 + 1),L"\\Device\\HardDiskVolume");
		pToReslt += 22;
		pchStart += 22;
		while (*pchStart && !IsCharDirSep(*pchStart))
			*pToReslt++ = *pchStart++;
	}
	//\\??\\c:\\xx-->\\??\\c:
	else if (_wcsnicmp(pchStart, L"\\??\\", 4) == 0)
	{
		RtlStringCbCopyW(pToReslt, sizeof(WCHAR) * (MAX_PATH * 2 + 1), L"\\??\\");
		pToReslt += 4;
		pchStart += 4;

		while (*pchStart && !IsCharDirSep(*pchStart))
			*pToReslt++ = *pchStart++;
	}
	else
	{
		ExFreePool(szResult);
		return FALSE;
	}

	while (IsCharDirSep(*pchStart)) 
	{
		BOOL			bShortName			= FALSE;
		WCHAR			*pchEnd				= NULL;
		WCHAR			*pchReplacePos		= NULL;

		*pToReslt++ = *pchStart++;

		pchEnd = pchStart;
		pchReplacePos = pToReslt;

		while (*pchEnd && !IsCharDirSep(*pchEnd))
		{
			if(*pchEnd == L'~')
			{
				bShortName = TRUE;
			}

			*pToReslt++ = *pchEnd++;
		}

		*pToReslt = L'\0';
  
		if(bShortName)
		{
			WCHAR  * szLong = NULL;
			
			szLong = ExAllocatePoolWithTag(PagedPool,
						  sizeof(WCHAR) * MAX_PATH,
						  'L2S');
			if(szLong)
			{
				RtlZeroMemory(szLong,  sizeof(WCHAR) * MAX_PATH);

				if(QueryPathForLongName(szResult, szLong, sizeof(WCHAR) * MAX_PATH))
				{
					RtlStringCbCopyW(pchReplacePos, sizeof(WCHAR) * (MAX_PATH * 2 + 1), szLong);
					pToReslt = pchReplacePos + wcslen(pchReplacePos);
				}

				ExFreePool(szLong);
			}
		}

		pchStart = pchEnd;
	}

	wcsncpy(wszLongName, szResult + nOffset, size/sizeof(WCHAR));
	ExFreePool(szResult);
	return TRUE;
}

BOOL IsShortNamePath(WCHAR * wszFileName)
{
	WCHAR *p = wszFileName;

	while(*p != L'\0')
	{
		if(*p == L'~')
		{
			return TRUE;
		}
		p++;
	}
	
	return FALSE;
}

NTSTATUS  GetProcessFullNameByPid(HANDLE nPid, PUNICODE_STRING  FullPath)
{

    HANDLE               hFile      = NULL;
    ULONG                nNeedSize	= 0;
    NTSTATUS             nStatus    = STATUS_SUCCESS;
    NTSTATUS             nDeviceStatus = STATUS_DEVICE_DOES_NOT_EXIST;
    PEPROCESS            Process    = NULL;
    KAPC_STATE           ApcState   = {0};			
    PVOID                lpBuffer   = NULL;
    OBJECT_ATTRIBUTES	 ObjectAttributes = {0};
    IO_STATUS_BLOCK      IoStatus   = {0}; 
    PFILE_OBJECT         FileObject = NULL;
    PFILE_NAME_INFORMATION FileName = NULL;   
    WCHAR                FileBuffer[MAX_PATH] = {0};
    DECLARE_UNICODE_STRING_SIZE(ProcessPath,MAX_PATH);
    DECLARE_UNICODE_STRING_SIZE(DosDeviceName,MAX_PATH);
    
    PAGED_CODE();

    nStatus = PsLookupProcessByProcessId(nPid, &Process);
    if(NT_ERROR(nStatus))
    {
        KdPrint(("%s error PsLookupProcessByProcessId.\n",__FUNCTION__));
        return nStatus;
    }



    __try
    {

        KeStackAttachProcess(Process, &ApcState);
        
        nStatus = ZwQueryInformationProcess(
            NtCurrentProcess(),
            ProcessImageFileName,
            NULL,
            0,
            &nNeedSize
            );

        if (STATUS_INFO_LENGTH_MISMATCH != nStatus)
        {
            KdPrint(("%s NtQueryInformationProcess error.\n",__FUNCTION__)); 
            nStatus = STATUS_MEMORY_NOT_ALLOCATED;
            __leave;

        }

        lpBuffer = ExAllocatePoolWithTag(NonPagedPool, nNeedSize,'GetP');
        if (lpBuffer == NULL)
        {
            KdPrint(("%s ExAllocatePoolWithTag error.\n",__FUNCTION__));
            nStatus = STATUS_MEMORY_NOT_ALLOCATED;
            __leave; 
        }

       nStatus =  ZwQueryInformationProcess(
           NtCurrentProcess(),
           ProcessImageFileName, 
           lpBuffer, 
           nNeedSize,
           &nNeedSize
           );

       if (NT_ERROR(nStatus))
       {
           KdPrint(("%s NtQueryInformationProcess error2.\n",__FUNCTION__));
           __leave;
       }

       RtlCopyUnicodeString(&ProcessPath,(PUNICODE_STRING)lpBuffer);
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
           0,
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

       nDeviceStatus = RtlVolumeDeviceToDosName(FileObject->DeviceObject,&DosDeviceName);

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
        RtlInitUnicodeString(&ProcessPath,FileName->FileName);

        if (NT_SUCCESS(nDeviceStatus))
        {
            RtlCopyUnicodeString(FullPath,&DosDeviceName);
            RtlUnicodeStringCat(FullPath,&ProcessPath);
        }
        else
        {
            RtlCopyUnicodeString(FullPath,&ProcessPath);
        }
    }


    return nStatus;
}

