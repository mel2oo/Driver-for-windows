#include <ntddk.h>

typedef struct _FILE_LIST_ENTRY {

	LIST_ENTRY Entry;
	PWSTR NameBuffer;

} FILE_LIST_ENTRY, *PFILE_LIST_ENTRY;

typedef struct _FILE_DIRECTORY_INFORMATION {
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

NTSTATUS ZwQueryDirectoryFile(
	__in HANDLE  FileHandle,
	__in_opt HANDLE  Event,
	__in_opt PIO_APC_ROUTINE  ApcRoutine,
	__in_opt PVOID  ApcContext,
	__out PIO_STATUS_BLOCK  IoStatusBlock,
	__out PVOID  FileInformation,
	__in ULONG  Length,
	__in FILE_INFORMATION_CLASS  FileInformationClass,
	__in BOOLEAN  ReturnSingleEntry,
	__in_opt PUNICODE_STRING  FileName,
	__in BOOLEAN  RestartScan
);

NTSTATUS dfDeleteFile(const WCHAR *fileName)
{
	OBJECT_ATTRIBUTES                	objAttributes = { 0 };
	IO_STATUS_BLOCK                    	iosb = { 0 };
	HANDLE                           	handle = NULL;
	FILE_DISPOSITION_INFORMATION    	disInfo = { 0 };
	UNICODE_STRING						uFileName = { 0 };
	NTSTATUS                        	status = 0;

	RtlInitUnicodeString(&uFileName, fileName);

	InitializeObjectAttributes(&objAttributes, &uFileName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwCreateFile(
		&handle,
		SYNCHRONIZE | FILE_WRITE_DATA | DELETE,
		&objAttributes,
		&iosb,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
		NULL,
		0);
	if (!NT_SUCCESS(status))
	{
		if (status == STATUS_ACCESS_DENIED)
		{
			status = ZwCreateFile(
				&handle,
				SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
				&objAttributes,
				&iosb,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				FILE_OPEN,
				FILE_SYNCHRONOUS_IO_NONALERT,
				NULL,
				0);
			if (NT_SUCCESS(status))
			{
				FILE_BASIC_INFORMATION        basicInfo = { 0 };

				status = ZwQueryInformationFile(handle, &iosb,
					&basicInfo, sizeof(basicInfo), FileBasicInformation);
				if (!NT_SUCCESS(status))
				{
					KdPrint(("ZwQueryInformationFile(%wZ) failed(%x)\n", &uFileName, status));
				}

				basicInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
				status = ZwSetInformationFile(handle, &iosb,
					&basicInfo, sizeof(basicInfo), FileBasicInformation);
				if (!NT_SUCCESS(status))
				{
					KdPrint(("ZwSetInformationFile(%wZ) failed(%x)\n", &uFileName, status));
				}

				ZwClose(handle);
				status = ZwCreateFile(
					&handle,
					SYNCHRONIZE | FILE_WRITE_DATA | DELETE,
					&objAttributes,
					&iosb,
					NULL,
					FILE_ATTRIBUTE_NORMAL,
					FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
					FILE_OPEN,
					FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
					NULL,
					0);
			}
		}

		if (!NT_SUCCESS(status))
		{
			KdPrint(("ZwCreateFile(%wZ) failed(%x)\n", &uFileName, status));
			return status;
		}
	}

	disInfo.DeleteFile = TRUE;
	status = ZwSetInformationFile(handle, &iosb,
		&disInfo, sizeof(disInfo), FileDispositionInformation);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("ZwSetInformationFile(%wZ) failed(%x)\n", &uFileName, status));
	}

	ZwClose(handle);
	return status;
}

NTSTATUS dfDeleteDirectory(const WCHAR * directory)
{
	OBJECT_ATTRIBUTES                	objAttributes = { 0 };
	IO_STATUS_BLOCK                    	iosb = { 0 };
	HANDLE                            	handle = NULL;
	FILE_DISPOSITION_INFORMATION    	disInfo = { 0 };
	PVOID                            	buffer = NULL;
	ULONG                            	bufferLength = 0;
	BOOLEAN                            	restartScan = FALSE;
	PFILE_DIRECTORY_INFORMATION        	dirInfo = NULL;
	PWSTR                            	nameBuffer = NULL;	//记录文件夹
	UNICODE_STRING                    	nameString = { 0 };
	NTSTATUS                        	status = 0;
	LIST_ENTRY                        	listHead = { 0 };	//链表，用来存放删除过程中的目录
	PFILE_LIST_ENTRY                	tmpEntry = NULL;	//链表结点
	PFILE_LIST_ENTRY                	preEntry = NULL;
	UNICODE_STRING						uDirName = { 0 };

	RtlInitUnicodeString(&uDirName, directory);

	nameBuffer = (PWSTR)ExAllocatePoolWithTag(PagedPool, uDirName.Length + sizeof(WCHAR), 'DRID');
	if (!nameBuffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	tmpEntry = (PFILE_LIST_ENTRY)ExAllocatePoolWithTag(PagedPool, sizeof(FILE_LIST_ENTRY), 'DRID');
	if (!tmpEntry)
	{
		ExFreePool(nameBuffer);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlCopyMemory(nameBuffer, uDirName.Buffer, uDirName.Length);
	nameBuffer[uDirName.Length / sizeof(WCHAR)] = L'\0';

	InitializeListHead(&listHead);	//初始化链表
	tmpEntry->NameBuffer = nameBuffer;
	InsertHeadList(&listHead, &tmpEntry->Entry);	//将要删除的文件夹首先插入链表   

	//listHead里初始化为要删除的文件夹。
	//之后遍历文件夹下的文件和目录，判断是文件，则立即删除；判断是目录，则放进listHead里面
	//每次都从listHead里拿出一个目录来处理
	while (!IsListEmpty(&listHead))
	{

		//先将要删除的文件夹和之前打算删除的文件夹比较一下，如果从链表里取下来的还是之前的Entry，表明没有删除成功，说明里面非空
		//否则，已经成功删除，不可能是它自身；或者还有子文件夹，在前面，也不可能是它自身。
		tmpEntry = (PFILE_LIST_ENTRY)RemoveHeadList(&listHead);
		if (preEntry == tmpEntry)
		{
			status = STATUS_DIRECTORY_NOT_EMPTY;
			break;
		}

		preEntry = tmpEntry;
		InsertHeadList(&listHead, &tmpEntry->Entry); //放进去，等删除了里面的内容，再移除。如果移除失败，则说明还有子文件夹或者目录非空

		RtlInitUnicodeString(&nameString, tmpEntry->NameBuffer);
		InitializeObjectAttributes(&objAttributes, &nameString,
			OBJ_CASE_INSENSITIVE, NULL, NULL);
		//打开文件夹，进行查询
		status = ZwCreateFile(
			&handle,
			FILE_ALL_ACCESS,
			&objAttributes,
			&iosb,
			NULL,
			0,
			0,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("ZwCreateFile(%ws) failed(%x)\n", tmpEntry->NameBuffer, status));
			break;
		}
		//从第一个扫描
		restartScan = TRUE;
		while (TRUE)
		{

			buffer = NULL;
			bufferLength = 64;
			status = STATUS_BUFFER_OVERFLOW;

			while ((status == STATUS_BUFFER_OVERFLOW) || (status == STATUS_INFO_LENGTH_MISMATCH))
			{
				if (buffer)
				{
					ExFreePool(buffer);
				}

				bufferLength *= 2;
				buffer = ExAllocatePoolWithTag(PagedPool, bufferLength, 'DRID');
				if (!buffer)
				{
					KdPrint(("ExAllocatePool failed\n"));
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}

				status = ZwQueryDirectoryFile(handle, NULL, NULL,
					NULL, &iosb, buffer, bufferLength, FileDirectoryInformation,
					FALSE, NULL, restartScan);
			}

			if (status == STATUS_NO_MORE_FILES)
			{
				ExFreePool(buffer);
				status = STATUS_SUCCESS;
				break;
			}

			restartScan = FALSE;

			if (!NT_SUCCESS(status))
			{
				KdPrint(("ZwQueryDirectoryFile(%ws) failed(%x)\n", tmpEntry->NameBuffer, status));
				if (buffer)
				{
					ExFreePool(buffer);
				}
				break;
			}

			dirInfo = (PFILE_DIRECTORY_INFORMATION)buffer;

			nameBuffer = (PWSTR)ExAllocatePoolWithTag(PagedPool,
				wcslen(tmpEntry->NameBuffer) * sizeof(WCHAR) + dirInfo->FileNameLength + 4, 'DRID');
			if (!nameBuffer)
			{
				KdPrint(("ExAllocatePool failed\n"));
				ExFreePool(buffer);
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			//tmpEntry->NameBuffer是当前文件夹路径
			//下面的操作在拼接文件夹下面的文件路径

			RtlZeroMemory(nameBuffer, wcslen(tmpEntry->NameBuffer) * sizeof(WCHAR) + dirInfo->FileNameLength + 4);
			wcscpy(nameBuffer, tmpEntry->NameBuffer);
			wcscat(nameBuffer, L"\\");
			RtlCopyMemory(&nameBuffer[wcslen(nameBuffer)], dirInfo->FileName, dirInfo->FileNameLength);
			RtlInitUnicodeString(&nameString, nameBuffer);

			if (dirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				//如果是非'.'和'..'两个特殊的目录，则将目录放入listHead
				if ((dirInfo->FileNameLength == sizeof(WCHAR)) && (dirInfo->FileName[0] == L'.'))
				{

				}
				else if ((dirInfo->FileNameLength == sizeof(WCHAR) * 2) &&
					(dirInfo->FileName[0] == L'.') &&
					(dirInfo->FileName[1] == L'.'))
				{
				}
				else
				{
					//将文件夹插入listHead中
					PFILE_LIST_ENTRY localEntry;
					localEntry = (PFILE_LIST_ENTRY)ExAllocatePoolWithTag(PagedPool, sizeof(FILE_LIST_ENTRY), 'DRID');
					if (!localEntry)
					{
						KdPrint(("ExAllocatePool failed\n"));
						ExFreePool(buffer);
						ExFreePool(nameBuffer);
						status = STATUS_INSUFFICIENT_RESOURCES;
						break;
					}

					localEntry->NameBuffer = nameBuffer;
					nameBuffer = NULL;
					InsertHeadList(&listHead, &localEntry->Entry); //插入头部，先把子文件夹里的删除
				}
			}
			else
			{
				//文件，直接删除
				status = dfDeleteFile(nameBuffer);
				if (!NT_SUCCESS(status))
				{
					KdPrint(("dfDeleteFile(%wZ) failed(%x)\n", &nameString, status));
					ExFreePool(buffer);
					ExFreePool(nameBuffer);
					break;
				}
			}

			ExFreePool(buffer);
			if (nameBuffer)
			{
				ExFreePool(nameBuffer);
			}//继续在循环里处理下一个子文件或者子文件夹
		}//  while (TRUE) ，一直弄目录里的文件和文件夹

		if (NT_SUCCESS(status))
		{
			//再删除目录
			disInfo.DeleteFile = TRUE;
			status = ZwSetInformationFile(handle, &iosb,
				&disInfo, sizeof(disInfo), FileDispositionInformation);
			if (!NT_SUCCESS(status))
			{
				UNICODE_STRING uCompStr = { 0x00 };
				RtlInitUnicodeString(&uCompStr, tmpEntry->NameBuffer);
				if (RtlCompareUnicodeString(&uDirName, &uCompStr, TRUE) != 0)
				{
					KdPrint(("ZwSetInformationFile(%ws) failed(%x)\n", tmpEntry->NameBuffer, status));
				}

			}
		}

		ZwClose(handle);

		if (NT_SUCCESS(status))
		{
			//删除成功，从链表里移出该目录
			RemoveEntryList(&tmpEntry->Entry);
			ExFreePool(tmpEntry->NameBuffer);
			ExFreePool(tmpEntry);
		}
		//如果失败，则表明在文件夹还有子文件夹，继续先删除子文件夹
	}// while (!IsListEmpty(&listHead)) 

	while (!IsListEmpty(&listHead))
	{
		tmpEntry = (PFILE_LIST_ENTRY)RemoveHeadList(&listHead);
		ExFreePool(tmpEntry->NameBuffer);
		ExFreePool(tmpEntry);
	}

	return status;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("DriverUnload...\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);

	DbgPrint("DriverEntry...\n");

	dfDeleteDirectory(L"\\??\\c:\\123");

	return STATUS_SUCCESS;
}