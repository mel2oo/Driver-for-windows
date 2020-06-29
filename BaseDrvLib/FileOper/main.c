#include <ntifs.h>
#include <ntddk.h>

NTSTATUS FileOper(VOID);

NTSTATUS ntCreateFile(WCHAR *szFileName);
NTSTATUS ntCreateDirectory(WCHAR *szDirName);

NTSTATUS ntWriteFile(WCHAR *szFileName);
NTSTATUS ntReadFile(WCHAR *szFile);
NTSTATUS ntCopyFile(const WCHAR * src, const WCHAR * dst);
NTSTATUS ntMoveFile(const WCHAR * src, const WCHAR * dst);
NTSTATUS ntDeleteFile1(const WCHAR * filename);
NTSTATUS ntDeleteFile2(const WCHAR *fileName);

ULONG ntGetFileAttributes(const WCHAR * filename);
NTSTATUS ntSetFileAttribute(WCHAR *szFileName);

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS ntStatus = 0;

	WCHAR			*szFileName1 = L"\\??\\c:\\1.txt";
	WCHAR			*szFileName2 = L"\\??\\c:\\2.txt";

	ntStatus = ntDeleteFile2(szFileName1);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntDeleteFile2() failed%d\n", ntStatus);
		//return;
	}

	ntStatus = ntDeleteFile2(szFileName2);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntDeleteFile2() failed%ws,%x\n", szFileName2, ntStatus);
		return;
	}
	DbgPrint("Driver Unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	DbgPrint("Driver begin\n");
	pDriverObject->DriverUnload = DriverUnload;

	FileOper();

	return STATUS_SUCCESS;
}

NTSTATUS FileOper(VOID)
{
	NTSTATUS		ntStatus = STATUS_SUCCESS;
	ULONG			ulAttributes = 0;
	WCHAR			*szDirName = L"\\??\\c:\\BaseDrv\\";
	WCHAR			*szFileName1 = L"\\??\\c:\\1.txt";
	WCHAR			*szFileName2 = L"\\??\\c:\\2.txt";
	WCHAR			*szFileName3 = L"\\??\\C:\\BaseDrv\\3.txt";
	WCHAR			*szFileName4 = L"\\??\\C:\\BaseDrv\\4.txt";


	ntStatus = ntCreateFile(szFileName1);
	if (!NT_SUCCESS(ntStatus))
	{

		DbgPrint("ntCreateFile() failed:%x\n", ntStatus);
		return ntStatus;
	}

	ntStatus = ntCreateDirectory(szDirName);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntCreateDirectory() failed:%x\n", ntStatus);
		return ntStatus;
	}


	ntStatus = ntWriteFile(szFileName1);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntWriteFile() failed:%x\n", ntStatus);
		return ntStatus;
	}

	ntStatus = ntReadFile(szFileName1);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntReadFile() failed:%x\n", ntStatus);
		return ntStatus;
	}

	ntStatus = ntCopyFile(szFileName1, szFileName2);

	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntCopyFile() failed:%x\n", ntStatus);
		return ntStatus;
	}

	ntStatus = ntCopyFile(szFileName1, szFileName3);

	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntCopyFile() failed:%x\n", ntStatus);
		return ntStatus;
	}


	ntStatus = ntMoveFile(szFileName1, szFileName4);

	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntMoveFile() failed:%x\n", ntStatus);
		return ntStatus;
	}


	ulAttributes = ntGetFileAttributes(szFileName1);
	if (ulAttributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		DbgPrint("%S is a directory\n", szFileName1);
	}
	else
	{
		DbgPrint("%S is not a directory\n", szFileName1);

	}

	ulAttributes = ntGetFileAttributes(szDirName);
	if (ulAttributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		DbgPrint("%S is a directory\n", szDirName);
	}
	else
	{
		DbgPrint("%S is not a directory\n", szDirName);

	}

	//ntStatus = ntDeleteFile2(szFileName1);
	//if (!NT_SUCCESS(ntStatus))
	//{
	//	DbgPrint("ntDeleteFile2() failed\n", ntStatus);
	//	return ntStatus;
	//}

	//ntStatus = ntDeleteFile2(szFileName2);
	//if (!NT_SUCCESS(ntStatus))
	//{
	//	DbgPrint("ntDeleteFile2() failed\n", ntStatus);
	//	return ntStatus;
	//}

	return ntStatus;
}

NTSTATUS ntCreateFile(WCHAR *szFileName)//L"\\??\\c:\\doc\\1.txt"
{
	OBJECT_ATTRIBUTES		objAttrib = { 0 };
	UNICODE_STRING			uFileName = { 0 };
	IO_STATUS_BLOCK 		io_status = { 0 };
	HANDLE					hFile = NULL;
	NTSTATUS				status = 0;

	RtlInitUnicodeString(&uFileName, szFileName);
	InitializeObjectAttributes(
		&objAttrib,
		&uFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);


	status = ZwCreateFile(
		&hFile,
		GENERIC_WRITE,
		&objAttrib,
		&io_status,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		NULL,
		0);

	if (NT_SUCCESS(status))
	{
		ZwClose(hFile);
	}

	return status;
}

NTSTATUS ntCreateDirectory(WCHAR *szDirName)//L"\\??\\c:\\doc\\"
{
	OBJECT_ATTRIBUTES		objAttrib = { 0 };
	UNICODE_STRING			uDirName = { 0 };
	IO_STATUS_BLOCK 		io_status = { 0 };
	HANDLE					hFile = NULL;
	NTSTATUS				status = 0;

	RtlInitUnicodeString(&uDirName, szDirName);
	InitializeObjectAttributes(&objAttrib,
		&uDirName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwCreateFile(&hFile,
		GENERIC_READ | GENERIC_WRITE,
		&objAttrib,
		&io_status,
		NULL,
		FILE_ATTRIBUTE_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN_IF,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (NT_SUCCESS(status))
	{
		ZwClose(hFile);
	}

	return status;

}

ULONG ntGetFileAttributes(const WCHAR * filename)
{
	ULONG							dwRtn = 0;
	NTSTATUS						ntStatus = STATUS_UNSUCCESSFUL;
	OBJECT_ATTRIBUTES				objAttr = { 0 };
	UNICODE_STRING					uName = { 0 };
	FILE_NETWORK_OPEN_INFORMATION 	info = { 0 };


	if (filename == NULL)
	{
		return ntStatus;
	}
	RtlInitUnicodeString(&uName, filename);
	RtlZeroMemory(&info, sizeof(FILE_NETWORK_OPEN_INFORMATION));

	InitializeObjectAttributes(
		&objAttr,
		&uName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);
	ntStatus = ZwQueryFullAttributesFile(
		&objAttr,
		&info);
	if (NT_SUCCESS(ntStatus))
	{
		dwRtn = info.FileAttributes;
	}
	if (dwRtn & FILE_ATTRIBUTE_DIRECTORY)
	{
		DbgPrint("%S is a directory\n", filename);
	}
	return dwRtn;
}

NTSTATUS ntSetFileAttribute(WCHAR *szFileName)
{
	OBJECT_ATTRIBUTES 			objectAttributes = { 0 };
	IO_STATUS_BLOCK 			iostatus = { 0 };
	HANDLE 						hfile = NULL;
	UNICODE_STRING 				uFile = { 0 };
	FILE_STANDARD_INFORMATION	fsi = { 0 };
	FILE_POSITION_INFORMATION	fpi = { 0 };
	NTSTATUS					ntStatus = 0;


	RtlInitUnicodeString(&uFile, szFileName);
	InitializeObjectAttributes(&objectAttributes,
		&uFile,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	ntStatus = ZwCreateFile(&hfile,
		GENERIC_READ,
		&objectAttributes,
		&iostatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	ntStatus = ZwQueryInformationFile(hfile,
		&iostatus,
		&fsi,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);
	if (!NT_SUCCESS(ntStatus))
	{
		ZwClose(hfile);
		return ntStatus;
	}

	fpi.CurrentByteOffset.QuadPart = 100i64;


	ntStatus = ZwSetInformationFile(hfile,
		&iostatus,
		&fpi,
		sizeof(FILE_POSITION_INFORMATION),
		FilePositionInformation);

	ZwClose(hfile);
	return ntStatus;
}

NTSTATUS ntWriteFile(WCHAR *szFileName)
{
	OBJECT_ATTRIBUTES 	objectAttributes = { 0 };
	IO_STATUS_BLOCK 	iostatus = { 0 };
	HANDLE 				hfile = NULL;
	UNICODE_STRING 		uFile = { 0 };
	LARGE_INTEGER		number = { 0 };
	PUCHAR				pBuffer = NULL;
	NTSTATUS			ntStatus = STATUS_SUCCESS;


	RtlInitUnicodeString(&uFile, szFileName);

	InitializeObjectAttributes(&objectAttributes,
		&uFile,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	//创建文件
	ntStatus = ZwCreateFile(&hfile,
		GENERIC_WRITE,
		&objectAttributes,
		&iostatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_WRITE,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	pBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, 1024, 'ELIF');
	if (pBuffer == NULL)
	{
		ZwClose(hfile);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(pBuffer, 1024);

	RtlCopyMemory(pBuffer, L"Hello, world", wcslen(L"Hello, world") * sizeof(WCHAR));
	//写文件
	ntStatus = ZwWriteFile(hfile, NULL, NULL, NULL, &iostatus, pBuffer, 1024, NULL, NULL);


	ZwClose(hfile);

	ExFreePool(pBuffer);
	return ntStatus;
}

NTSTATUS ntReadFile(WCHAR *szFile)
{
	OBJECT_ATTRIBUTES 			objectAttributes = { 0 };
	IO_STATUS_BLOCK 			iostatus = { 0 };
	HANDLE 						hfile = NULL;
	UNICODE_STRING 				uFile = { 0 };
	FILE_STANDARD_INFORMATION	fsi = { 0 };
	PUCHAR						pBuffer = NULL;
	NTSTATUS					ntStatus = 0;

	RtlInitUnicodeString(&uFile, szFile);
	InitializeObjectAttributes(&objectAttributes,
		&uFile,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	ntStatus = ZwCreateFile(&hfile,
		GENERIC_READ,
		&objectAttributes,
		&iostatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	ntStatus = ZwQueryInformationFile(hfile,
		&iostatus,
		&fsi,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);
	if (!NT_SUCCESS(ntStatus))
	{
		ZwClose(hfile);
		return ntStatus;
	}

	pBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool,
		(LONG)fsi.EndOfFile.QuadPart, 'ELIF');
	if (pBuffer == NULL)
	{
		ZwClose(hfile);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ntStatus = ZwReadFile(
		hfile,
		NULL,
		NULL,
		NULL,
		&iostatus,
		pBuffer,
		(LONG)fsi.EndOfFile.QuadPart,
		NULL, NULL);

	ZwClose(hfile);
	ExFreePool(pBuffer);

	return ntStatus;
}

NTSTATUS ntCopyFile(const WCHAR * src, const WCHAR * dst)
{


	HANDLE					hSrcFile = NULL;
	HANDLE					hDstFile = NULL;
	UNICODE_STRING			uSrc = { 0 };
	UNICODE_STRING			uDst = { 0 };
	OBJECT_ATTRIBUTES		objSrcAttrib = { 0 };
	OBJECT_ATTRIBUTES		objDstAttrib = { 0 };
	NTSTATUS				status = 0;
	ULONG					uReadSize = 0;
	ULONG					uWriteSize = 0;
	ULONG					length = 0;
	PVOID 					buffer = NULL;
	LARGE_INTEGER 			offset = { 0 };
	IO_STATUS_BLOCK 		io_status = { 0 };

	RtlInitUnicodeString(&uSrc, src);
	RtlInitUnicodeString(&uDst, dst);

	InitializeObjectAttributes(&objSrcAttrib,
		&uSrc,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	InitializeObjectAttributes(&objDstAttrib,
		&uDst,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwCreateFile(
		&hSrcFile,
		FILE_READ_DATA | FILE_READ_ATTRIBUTES,
		&objSrcAttrib,
		&io_status,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	status = ZwCreateFile(
		&hDstFile,
		GENERIC_WRITE,
		&objDstAttrib,
		&io_status,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hSrcFile);
		return status;
	}

	buffer = ExAllocatePoolWithTag(PagedPool, 1024, 'ELIF');
	if (buffer == NULL)
	{
		ZwClose(hSrcFile);
		ZwClose(hDstFile);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	while (1)
	{
		status = ZwReadFile(
			hSrcFile, NULL, NULL, NULL,
			&io_status, buffer, PAGE_SIZE, &offset,
			NULL);
		if (!NT_SUCCESS(status))
		{
			if (status == STATUS_END_OF_FILE)
			{
				status = STATUS_SUCCESS;
			}
			break;
		}

		length = (ULONG)io_status.Information;

		status = ZwWriteFile(
			hDstFile, NULL, NULL, NULL,
			&io_status,
			buffer, length, &offset,
			NULL);
		if (!NT_SUCCESS(status))
			break;

		offset.QuadPart += length;

	}

	ExFreePool(buffer);

	ZwClose(hSrcFile);
	ZwClose(hDstFile);

	return status;
}

NTSTATUS ntMoveFile(const WCHAR * src, const WCHAR * dst)
{
	NTSTATUS		status = 0;

	status = ntCopyFile(src, dst);

	if (NT_SUCCESS(status))
	{
		status = ntDeleteFile2(src);
	}

	return status;
}

NTSTATUS ntDeleteFile1(const WCHAR * filename)
{
	NTSTATUS				ntStatus = 0;
	OBJECT_ATTRIBUTES		objAttr = { 0 };
	UNICODE_STRING			uName = { 0 };

	RtlInitUnicodeString(&uName, filename);
	InitializeObjectAttributes(
		&objAttr,
		&uName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);
	ntStatus = ZwDeleteFile(&objAttr);

	return ntStatus;

}

NTSTATUS ntDeleteFile2(const WCHAR *fileName)
{
	OBJECT_ATTRIBUTES                	objAttributes = { 0 };
	IO_STATUS_BLOCK                    	iosb = { 0 };
	HANDLE                           	handle = NULL;
	FILE_DISPOSITION_INFORMATION    	disInfo = { 0 };
	UNICODE_STRING						uFileName = { 0 };
	NTSTATUS                        	status = 0;

	RtlInitUnicodeString(&uFileName, fileName);

	InitializeObjectAttributes(&objAttributes,
		&uFileName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

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
					DbgPrint("ZwQueryInformationFile(%wZ) failed(%x)\n", &uFileName, status);
				}

				basicInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
				status = ZwSetInformationFile(handle, &iosb,
					&basicInfo, sizeof(basicInfo), FileBasicInformation);
				if (!NT_SUCCESS(status))
				{
					DbgPrint("ZwSetInformationFile(%wZ) failed(%x)\n", &uFileName, status);
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
			DbgPrint("ZwCreateFile(%wZ) failed(%x)\n", &uFileName, status);
			return status;
		}
	}

	disInfo.DeleteFile = TRUE;
	status = ZwSetInformationFile(handle, &iosb,
		&disInfo, sizeof(disInfo), FileDispositionInformation);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ZwSetInformationFile(%wZ) failed(%x)\n", &uFileName, status);
	}

	ZwClose(handle);
	return status;
}