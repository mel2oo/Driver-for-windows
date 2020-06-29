#include <ntddk.h>
#include <ntstrsafe.h>
#include <windef.h>

NTSTATUS RegOper(WCHAR *szKey);

NTSTATUS ntCreateKey(WCHAR *szKey);

NTSTATUS ntOpenKey(WCHAR *szKey);
NTSTATUS ntEnumerateSubKey(WCHAR *szKey);

NTSTATUS ntSetValueKey(WCHAR *szKey);
NTSTATUS ntQueryValueKey(WCHAR *szKey);
NTSTATUS ntEnumerateSubValueKey(WCHAR *szKey);
NTSTATUS ntDeleteValueKey(WCHAR *szKey);

NTSTATUS ntDeleteKey(WCHAR *szKey);

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS ntStatus = ntDeleteValueKey(L"\\Registry\\Machine\\SoftWare\\Mallocfree");
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntSetValueKey() failed:%x\n", ntStatus);
		return;
	}
	ntDeleteKey(L"\\Registry\\Machine\\SoftWare\\Mallocfree");
	DbgPrint("Driver Unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	DbgPrint("Driver begin\n");
	pDriverObject->DriverUnload = DriverUnload;

	RegOper(L"\\Registry\\Machine\\SoftWare\\Mallocfree");

	return STATUS_SUCCESS;
}

NTSTATUS RegOper(WCHAR *szKey)
{
	NTSTATUS		ntStatus = STATUS_UNSUCCESSFUL;
	WCHAR			szDeleteSubKey[MAX_PATH] = { 0 };

	if (szKey == NULL)
	{
		return ntStatus;
	}

	ntStatus = ntCreateKey(szKey);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntCreateKey() failed:%x\n", ntStatus);
		return ntStatus;
	}

	ntStatus = ntSetValueKey(szKey);

	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntSetValueKey() failed:%x\n", ntStatus);
		return ntStatus;
	}

	ntStatus = ntQueryValueKey(szKey);

	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntQueryValueKey() failed:%x\n", ntStatus);
		return ntStatus;
	}

	ntStatus = ntEnumerateSubValueKey(szKey);

	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntEnumerateSubValueKey() failed:%x\n", ntStatus);
		return ntStatus;
	}

	// 	ntStatus =  ntDeleteValueKey(szKey);
	// 	if (!NT_SUCCESS(ntStatus))
	// 	{
	// 		DbgPrint("ntSetValueKey() failed:%x\n", ntStatus);
	// 		return ntStatus;
	// 	}

	ntStatus = ntOpenKey(szKey);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntOpenKey() failed:%x\n", ntStatus);
		return ntStatus;
	}

	ntStatus = ntEnumerateSubKey(szKey);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ntEnumerateSubItem() failed:%x\n", ntStatus);
		return ntStatus;
	}

	// 	RtlStringCbCopyW(szDeleteSubKey, sizeof(szDeleteSubKey), szKey);
	// 	RtlStringCbCatW(szDeleteSubKey, sizeof(szDeleteSubKey), L"\\KernelDriver");
	// 	ntStatus = ntDeleteKey(szDeleteSubKey);
	// 	if (!NT_SUCCESS(ntStatus))
	// 	{
	// 		DbgPrint("ntDeleteKey() failed:%x\n", ntStatus);
	// 		return ntStatus;
	// 	}

	return ntStatus;
}


//创建KEY和SUBKEY示例
NTSTATUS ntCreateKey(WCHAR *szKey)
{

	UNICODE_STRING 		uRegKey = { 0 };
	HANDLE 				hRegister = NULL;
	ULONG 				ulResult = 0;
	OBJECT_ATTRIBUTES 	objectAttributes = { 0 };
	UNICODE_STRING 		subRegKey = { 0 };
	HANDLE 				hSubRegister = NULL;
	OBJECT_ATTRIBUTES 	subObjectAttributes = { 0 };
	NTSTATUS			ntStatus = STATUS_SUCCESS;

	RtlInitUnicodeString(&uRegKey, szKey);
	InitializeObjectAttributes(&objectAttributes,
		&uRegKey,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	ntStatus = ZwCreateKey(&hRegister,
		KEY_ALL_ACCESS,
		&objectAttributes,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		&ulResult);

	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	//开始创建SUBKEY

	RtlInitUnicodeString(&subRegKey, L"KernelDriver");

	InitializeObjectAttributes(&subObjectAttributes,
		&subRegKey,
		OBJ_CASE_INSENSITIVE,
		hRegister,
		NULL);
	ntStatus = ZwCreateKey(&hSubRegister,
		KEY_ALL_ACCESS,
		&subObjectAttributes,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		&ulResult);

	if (!NT_SUCCESS(ntStatus))
	{
		ZwClose(hRegister);
		return ntStatus;
	}

	ZwClose(hRegister);
	ZwClose(hSubRegister);

	return ntStatus;
}


NTSTATUS ntOpenKey(WCHAR *szKey)
{
	UNICODE_STRING 		RegUnicodeString = { 0 };
	HANDLE 				hRegister = NULL;
	OBJECT_ATTRIBUTES 	objectAttributes = { 0 };
	NTSTATUS			ntStatus = STATUS_SUCCESS;

	RtlInitUnicodeString(&RegUnicodeString, szKey);

	InitializeObjectAttributes(&objectAttributes,
		&RegUnicodeString,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	ntStatus = ZwOpenKey(&hRegister,
		KEY_ALL_ACCESS,
		&objectAttributes);

	if (NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	ZwClose(hRegister);
	return ntStatus;
}

//\\registry\\machine\\SYSTEM\\CurrentControlSet\\services\\LanmanServer
NTSTATUS ntEnumerateSubKey(WCHAR *szKey)
{
	UNICODE_STRING 			RegUnicodeString = { 0 };
	HANDLE 					hRegister = NULL;
	ULONG 					ulSize = 0;
	OBJECT_ATTRIBUTES 		objectAttributes = { 0 };
	NTSTATUS				ntStatus = STATUS_SUCCESS;
	UNICODE_STRING			uniKeyName = { 0 };
	PKEY_FULL_INFORMATION	pfi = NULL;
	ULONG					i = 0;
	PKEY_BASIC_INFORMATION  pbi = NULL;

	RtlInitUnicodeString(&RegUnicodeString, szKey);
	InitializeObjectAttributes(&objectAttributes,
		&RegUnicodeString,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	ntStatus = ZwOpenKey(&hRegister,
		KEY_ALL_ACCESS,
		&objectAttributes);

	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}


	//第一次调用ZwQueryKey为了获取KEY_FULL_INFORMATION数据的长度
	ntStatus = ZwQueryKey(hRegister,
		KeyFullInformation,
		NULL,
		0,
		&ulSize);
	if (STATUS_BUFFER_OVERFLOW != ntStatus &&
		STATUS_BUFFER_TOO_SMALL != ntStatus)
	{
		return ntStatus;
	}

	pfi =
		(PKEY_FULL_INFORMATION)
		ExAllocatePoolWithTag(PagedPool, ulSize, 'SGER');
	if (pfi == NULL)
	{
		ZwClose(hRegister);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//第二次调用ZwQueryKey为了获取KEY_FULL_INFORMATION数据的数据
	ntStatus = ZwQueryKey(hRegister,
		KeyFullInformation,
		pfi,
		ulSize,
		&ulSize);
	if (!NT_SUCCESS(ntStatus))
	{
		ExFreePool(pfi);
		ZwClose(hRegister);
		return ntStatus;
	}

	for (i = 0; i < pfi->SubKeys; i++)
	{
		//第一次调用ZwEnumerateKey为了获取KEY_BASIC_INFORMATION数据的长度
		ntStatus = ZwEnumerateKey(hRegister,
			i,
			KeyBasicInformation,
			NULL,
			0,
			&ulSize);
		if (STATUS_BUFFER_OVERFLOW != ntStatus &&
			STATUS_BUFFER_TOO_SMALL != ntStatus)
		{
			ZwClose(hRegister);
			ExFreePool(pfi);
			return ntStatus;
		}

		pbi = (PKEY_BASIC_INFORMATION)
			ExAllocatePoolWithTag(PagedPool, ulSize, 'SGER');
		if (pbi == NULL)
		{
			ZwClose(hRegister);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		//第二次调用ZwEnumerateKey为了获取KEY_BASIC_INFORMATION数据的数据
		ntStatus = ZwEnumerateKey(hRegister,
			i,
			KeyBasicInformation,
			pbi,
			ulSize,
			&ulSize);

		if (!NT_SUCCESS(ntStatus))
		{
			ZwClose(hRegister);
			ExFreePool(pfi);
			ExFreePool(pbi);
			return ntStatus;
		}

		uniKeyName.Length =
			uniKeyName.MaximumLength =
			(USHORT)pbi->NameLength;

		uniKeyName.Buffer = pbi->Name;

		DbgPrint("The %d sub item name is:%wZ\n", i, &uniKeyName);

		ExFreePool(pbi);
	}

	ExFreePool(pfi);
	ZwClose(hRegister);

	return ntStatus;
}


NTSTATUS ntDeleteKey(WCHAR *szKey)
{
	UNICODE_STRING 		RegUnicodeString = { 0 };
	HANDLE 				hRegister = NULL;
	OBJECT_ATTRIBUTES 	objectAttributes = { 0 };
	NTSTATUS			ntStatus = STATUS_SUCCESS;

	RtlInitUnicodeString(&RegUnicodeString, szKey);

	InitializeObjectAttributes(&objectAttributes,
		&RegUnicodeString,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	ntStatus = ZwOpenKey(&hRegister,
		KEY_ALL_ACCESS,
		&objectAttributes);

	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	ntStatus = ZwDeleteKey(hRegister);

	ZwClose(hRegister);
	return ntStatus;
}
//\\registry\\machine\SYSTEM\CurrentControlSet\services\LanmanServer

NTSTATUS ntSetValueKey(WCHAR *szKey)
{
	UNICODE_STRING 		RegUnicodeString = { 0 };
	HANDLE 				hRegister = NULL;
	OBJECT_ATTRIBUTES 	objectAttributes = { 0 };
	UNICODE_STRING 		ValueName = { 0 };
	NTSTATUS			ntStatus = STATUS_SUCCESS;
	ULONG				ulValue = 0;
	WCHAR				*strValue = L"hello world";
	CHAR				buffer[1024] = { 0 };

	RtlInitUnicodeString(&RegUnicodeString, szKey);

	InitializeObjectAttributes(
		&objectAttributes,
		&RegUnicodeString,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);

	ntStatus = ZwOpenKey(&hRegister,
		KEY_ALL_ACCESS,
		&objectAttributes);

	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	RtlInitUnicodeString(&ValueName, L"REG_DWORD");
	ulValue = 1000;
	ZwSetValueKey(hRegister,
		&ValueName,
		0,
		REG_DWORD,
		&ulValue,
		sizeof(ulValue));

	RtlInitUnicodeString(&ValueName, L"REG_SZ");

	ZwSetValueKey(hRegister,
		&ValueName,
		0,
		REG_SZ,
		strValue,
		wcslen(strValue) * sizeof(WCHAR) + sizeof(WCHAR));

	RtlInitUnicodeString(&ValueName, L"REG_BINARY");

	RtlFillMemory(buffer, sizeof(buffer), 0xFF);
	ZwSetValueKey(hRegister,
		&ValueName,
		0,
		REG_BINARY,
		buffer,
		sizeof(buffer));

	//todo:add a multisz valuekey

	ZwClose(hRegister);
	return ntStatus;
}


NTSTATUS ntDeleteValueKey(WCHAR *szKey)
{
	UNICODE_STRING 		RegUnicodeString = { 0 };
	HANDLE 				hRegister = NULL;
	OBJECT_ATTRIBUTES 	objectAttributes = { 0 };
	UNICODE_STRING 		ValueName = { 0 };
	ULONG 				ulSize = 0;
	NTSTATUS			ntStatus = STATUS_SUCCESS;

	RtlInitUnicodeString(&RegUnicodeString, szKey);

	InitializeObjectAttributes(&objectAttributes,
		&RegUnicodeString,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	ntStatus = ZwOpenKey(&hRegister,
		KEY_ALL_ACCESS,
		&objectAttributes);
	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	RtlInitUnicodeString(&ValueName, L"REG_DWORD");
	ntStatus = ZwDeleteValueKey(hRegister, &ValueName);

	ZwClose(hRegister);
	return ntStatus;
}

NTSTATUS ntQueryValueKey(WCHAR *szKey)
{
	UNICODE_STRING 					RegUnicodeString = { 0 };
	HANDLE 							hRegister = 0;
	OBJECT_ATTRIBUTES 				objectAttributes = { 0 };
	UNICODE_STRING 					ValueName = { 0 };
	ULONG 							ulSize = 0;
	NTSTATUS						ntStatus = STATUS_SUCCESS;
	PKEY_VALUE_PARTIAL_INFORMATION	pvpi = NULL;

	RtlInitUnicodeString(&RegUnicodeString, szKey);

	InitializeObjectAttributes(&objectAttributes,
		&RegUnicodeString,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	ntStatus = ZwOpenKey(&hRegister,
		KEY_ALL_ACCESS,
		&objectAttributes);
	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	RtlInitUnicodeString(&ValueName, L"REG_DWORD");

	ntStatus = ZwQueryValueKey(hRegister,
		&ValueName,
		KeyValuePartialInformation,
		NULL,
		0,
		&ulSize);

	if (ntStatus != STATUS_BUFFER_OVERFLOW &&
		ntStatus != STATUS_BUFFER_TOO_SMALL)
	{
		ZwClose(hRegister);
		return ntStatus;
	}

	pvpi =
		(PKEY_VALUE_PARTIAL_INFORMATION)
		ExAllocatePoolWithTag(PagedPool, ulSize, 'SGER');
	if (pvpi == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ntStatus = ZwQueryValueKey(hRegister,
		&ValueName,
		KeyValuePartialInformation,
		pvpi,
		ulSize,
		&ulSize);
	if (!NT_SUCCESS(ntStatus))
	{
		ExFreePool(pvpi);
		ZwClose(hRegister);
		return ntStatus;
	}

	if (pvpi->Type == REG_DWORD && pvpi->DataLength == sizeof(ULONG))
	{
		PULONG pulValue = (PULONG)pvpi->Data;
	}

	ExFreePool(pvpi);

	RtlInitUnicodeString(&ValueName, L"REG_SZ");

	ntStatus = ZwQueryValueKey(hRegister,
		&ValueName,
		KeyValuePartialInformation,
		NULL,
		0,
		&ulSize);

	if (ntStatus == STATUS_OBJECT_NAME_NOT_FOUND || ulSize == 0)
	{
		ZwClose(hRegister);
		return ntStatus;
	}
	pvpi =
		(PKEY_VALUE_PARTIAL_INFORMATION)
		ExAllocatePoolWithTag(PagedPool, ulSize, 'SGER');
	if (pvpi == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ntStatus = ZwQueryValueKey(hRegister,
		&ValueName,
		KeyValuePartialInformation,
		pvpi,
		ulSize,
		&ulSize);
	if (!NT_SUCCESS(ntStatus))
	{
		ExFreePool(pvpi);
		ZwClose(hRegister);
		return ntStatus;
	}

	if (pvpi->Type == REG_SZ)
	{
		UNICODE_STRING uStr;
		uStr.Length = pvpi->DataLength;
		uStr.MaximumLength = pvpi->DataLength;

		uStr.Buffer = pvpi->Data;

		DbgPrint("Value:%S\n", pvpi->Data);
		DbgPrint("Value:%wZ\n", &uStr);
	}
	ExFreePool(pvpi);
	ZwClose(hRegister);
	return ntStatus;
}

//\\registry\\machine\SYSTEM\CurrentControlSet\services\LanmanServer
NTSTATUS ntEnumerateSubValueKey(WCHAR *szKey)
{
	UNICODE_STRING 					RegUnicodeString = { 0 };
	HANDLE 							hRegister = NULL;
	OBJECT_ATTRIBUTES 				objectAttributes = { 0 };
	ULONG 							ulSize = 0;
	UNICODE_STRING					uniKeyName = { 0 };
	ULONG							i = 0;
	NTSTATUS						ntStatus = 0;
	PKEY_VALUE_BASIC_INFORMATION	pvbi = NULL;
	PKEY_FULL_INFORMATION			pfi = NULL;

	RtlInitUnicodeString(&RegUnicodeString, szKey);

	InitializeObjectAttributes(&objectAttributes,
		&RegUnicodeString,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	ntStatus = ZwOpenKey(&hRegister,
		KEY_ALL_ACCESS,
		&objectAttributes);

	if (!NT_SUCCESS(ntStatus))
	{
		return ntStatus;
	}

	ntStatus = ZwQueryKey(hRegister,
		KeyFullInformation,
		NULL,
		0,
		&ulSize);
	if (STATUS_BUFFER_OVERFLOW != ntStatus &&
		STATUS_BUFFER_TOO_SMALL != ntStatus)
	{
		ZwClose(hRegister);
		return ntStatus;
	}

	pfi =
		(PKEY_FULL_INFORMATION)
		ExAllocatePoolWithTag(PagedPool, ulSize, 'SGER');
	if (pfi == NULL)
	{
		ZwClose(hRegister);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ntStatus = ZwQueryKey(hRegister,
		KeyFullInformation,
		pfi,
		ulSize,
		&ulSize);
	if (!NT_SUCCESS(ntStatus))
	{
		ZwClose(hRegister);
		ExFreePool(pfi);
		return ntStatus;
	}

	for (i = 0; i < pfi->Values; i++)
	{
		ntStatus = ZwEnumerateValueKey(hRegister,
			i,
			KeyValueBasicInformation,
			NULL,
			0,
			&ulSize);

		if (STATUS_BUFFER_OVERFLOW != ntStatus &&
			STATUS_BUFFER_TOO_SMALL != ntStatus)
		{
			ZwClose(hRegister);
			ExFreePool(pfi);
			return ntStatus;
		}

		pvbi =
			(PKEY_VALUE_BASIC_INFORMATION)
			ExAllocatePoolWithTag(PagedPool, ulSize, 'SGER');
		if (pvbi == NULL)
		{
			ZwClose(hRegister);
			ExFreePool(pfi);
			return ntStatus;
		}

		ntStatus = ZwEnumerateValueKey(hRegister,
			i,
			KeyValueBasicInformation,
			pvbi,
			ulSize,
			&ulSize);
		if (!NT_SUCCESS(ntStatus))
		{
			ZwClose(hRegister);
			ExFreePool(pfi);
			ExFreePool(pvbi);
			return ntStatus;
		}

		uniKeyName.Length =
			uniKeyName.MaximumLength =
			(USHORT)pvbi->NameLength;

		uniKeyName.Buffer = pvbi->Name;

		DbgPrint("The %d sub value name:%wZ\n", i, &uniKeyName);

		if (pvbi->Type == REG_SZ)
		{
			DbgPrint("type:REG_SZ\n");
		}
		else if (pvbi->Type == REG_MULTI_SZ)
		{
			DbgPrint("type:REG_MULTI_SZ\n");

		}
		else if (pvbi->Type == REG_DWORD)
		{
			DbgPrint("type:REG_DWORD\n");
		}
		else if (pvbi->Type == REG_BINARY)
		{
			DbgPrint("type:REG_BINARY\n");
		}

		ExFreePool(pvbi);
	}

	ExFreePool(pfi);
	ZwClose(hRegister);

	return ntStatus;
}