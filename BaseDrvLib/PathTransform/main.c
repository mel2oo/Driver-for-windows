#include <ntddk.h>
#include <ntstrsafe.h>
#include <windef.h>

#define REG_PATH L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares"

/*
	实现strchr
*/
WCHAR*  RTLUnicodeStringChr(PUNICODE_STRING IN pStr, WCHAR chr)
{
	ULONG i = 0;
	ULONG size = pStr->Length >> 1;

	for (i = 0; i < size; i++) 
	{
		if (pStr->Buffer[i] == chr) 
		{
			return pStr->Buffer + i;
		}
	}

	return NULL;
}

/*
	实现strstr
*/
WCHAR*  RTLUnicodeStringStr(const PUNICODE_STRING IN pStr, const PUNICODE_STRING IN pSubStr)
{
	USHORT uLengthStep = 0;
	USHORT uStrlen = pStr->Length;
	USHORT uSubStrlen = pSubStr->Length;
	USHORT i = 0;
	UNICODE_STRING str1 = { 0 };
	str1.MaximumLength = uStrlen;
	UNICODE_STRING str2 = { 0 };
	str2.MaximumLength = uSubStrlen;
	str2.Buffer = pSubStr->Buffer;
	//str2.Length = pSubStr->Length;

	if (pStr == NULL || pSubStr == NULL || uStrlen < uSubStrlen) 
	{
		return NULL;
	}

	uLengthStep = ((uStrlen - uSubStrlen) >> 1) + 1;

	for (i = 0; i < uLengthStep; i++) 
	{
		str1.Length = str1.MaximumLength = (USHORT)uSubStrlen;
		str2.Length = str2.MaximumLength = (USHORT)uSubStrlen;
		str1.Buffer = pStr->Buffer + i;
		str2.Buffer = pSubStr->Buffer;
		if (0 == RtlCompareUnicodeString(&str1, &str2, TRUE)) 
		{
			return pStr->Buffer + i;
		}
	}

	return NULL;
}

UNICODE_STRING* getShareName(PUNICODE_STRING IN pStrUnc, PUNICODE_STRING OUT pStrShare) 
{
	WCHAR * pTmp = pStrUnc->Buffer;
	WCHAR *pSharStart = NULL;
	WCHAR *pSharEnd = NULL;
	ULONG uShareLen = 0;//share长度

	ULONG i = 0;
	ULONG uSize = (pStrUnc->Length) >> 1;
	//先取SharedDocs观察得shareDocs开头是第三个'\\',结束是第四个‘\\’,所有涉及以下流程
	ULONG uTmp = 1;//取第三个'\\'标志位

	if (pTmp == NULL) 
	{
		return NULL;
	}
	//取ShareDocs
	for (i = 0; i < uSize; i++)
	{
		if (pStrUnc->Buffer[i] == L'\\') {
			if (uTmp == 3)
			{
				pSharStart = pStrUnc->Buffer + i + 1;
			}
			else if (uTmp == 4) {
				pSharEnd = pStrUnc->Buffer + i - 1;
			}
			uTmp++;
		}
	}

	if (NULL == pSharStart || NULL == pSharEnd) 
	{
		return NULL;
	}

	uShareLen = pSharEnd - pSharStart + 1;

	pStrShare->Buffer = pSharStart;
	pStrShare->Length = uShareLen * sizeof(WCHAR);

	return pStrShare;
}

//逻辑和取share略有差距，所以变量注释有些就没改
UNICODE_STRING* getFileName(PUNICODE_STRING IN pStrUnc, PUNICODE_STRING OUT pStrShare) 
{
	WCHAR * pTmp = pStrUnc->Buffer;

	WCHAR *pSharStart = NULL;
	WCHAR *pSharEnd = NULL;
	ULONG uShareLen = 0;//share长度

	ULONG i = 0;
	ULONG uSize = (pStrUnc->Length) >> 1;
	//先取SharedDocs观察得开始是第四个‘\\’,所有涉及以下流程
	ULONG uTmp = 1;//取第四个'\\'标志位

	if (pTmp == NULL) 
	{
		return NULL;
	}

	//取ShareDocs
	for (i = 0; i < uSize; i++)
	{
		if (pStrUnc->Buffer[i] == L'\\') 
		{
			if (uTmp == 4)
			{
				pSharStart = pStrUnc->Buffer + i;

				break;
			}
			uTmp++;
		}
	}
	if (NULL == pSharStart) 
	{
		return NULL;
	}

	uShareLen = pStrUnc->Length - (i) * sizeof(WCHAR);

	pStrShare->Buffer = pSharStart;
	pStrShare->Length = uShareLen;

	return pStrShare;
}

//\\servername\SharedDocs\xxxx -> C:\\Documents and Settings\\All Users\\Documents\\xxx
NTSTATUS UNC2Local(PUNICODE_STRING IN pStrUnc, PUNICODE_STRING OUT pStrLocal)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	//我的思路是先将L"Doc\\1.txt"的截取出Doc，然后去查注册表，找到Path，再把后面拼接起来
	UNICODE_STRING StrShare = { 0 };
	StrShare.MaximumLength = MAX_PATH;
	StrShare.Length = 0;
	UNICODE_STRING uStrReg = { 0 };
	ULONG ulResult = 0;//放长度
	PKEY_VALUE_PARTIAL_INFORMATION	pvpi = NULL;

	UNICODE_STRING StrFile = { 0 };
	StrFile.MaximumLength = MAX_PATH;
	StrFile.Length = 0;

	getShareName(pStrUnc, &StrShare);
	getFileName(pStrUnc, &StrFile);

	OBJECT_ATTRIBUTES objectAttr = { 0 };
	HANDLE hRegister = NULL;

	DbgPrint("ShareName is %wZ\n", &StrShare);
	DbgPrint("file is %wZ\n", &StrFile);
	//查询注册表shared信息
	RtlInitUnicodeString(&uStrReg, REG_PATH);
	InitializeObjectAttributes(&objectAttr,
		&uStrReg,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwOpenKey(&hRegister,KEY_ALL_ACCESS,&objectAttr);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[RegQueryValueKey]ZwOpenKey failed!\n");

		return status;
	}

	status = ZwQueryValueKey(hRegister,
		&StrShare,
		KeyValuePartialInformation,
		NULL,
		0,
		&ulResult);

	if (status != STATUS_BUFFER_OVERFLOW &&
		status != STATUS_BUFFER_TOO_SMALL)
	{
		ZwClose(hRegister);
		return status;
	}

	pvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, ulResult, 'SGER');
	if (pvpi == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = ZwQueryValueKey(hRegister,
		&StrShare,
		KeyValuePartialInformation,
		pvpi,
		ulResult,
		&ulResult);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pvpi);
		ZwClose(hRegister);
		return status;
	}

	if (pvpi->Type != REG_MULTI_SZ) 
	{
		if (pvpi)
		{
			ExFreePool(pvpi);
		}

		if (hRegister)
		{
			ZwClose(hRegister);
		}

		return status;
	}
	//然后解析path=
	UNICODE_STRING uszLoc = { 0 };
	uszLoc.Length = (USHORT)pvpi->DataLength;
	uszLoc.MaximumLength = (USHORT)pvpi->DataLength;
	uszLoc.Buffer = (WCHAR*)(pvpi->Data);
	DbgPrint("uszLoc is %wZ\n", &uszLoc);//中间变量，保存查处的
	UNICODE_STRING uszLoc2 = { 0 }; //中间变量
	WCHAR * pTmp = 0;
	RtlInitUnicodeString(&uszLoc2, L"Path=");
	pTmp = RTLUnicodeStringStr(&uszLoc, &uszLoc2);
	//DbgPrint("pTmp is %wZ\n", *pTmp);
	if (NULL == pTmp)
	{
		status = STATUS_UNSUCCESSFUL;
		if (pvpi)
		{
			ExFreePool(pvpi);
		}

		if (hRegister)
		{
			ZwClose(hRegister);
		}

		return status;
	}
	else 
	{

		WCHAR* i = 0;
		RtlInitUnicodeString(&uszLoc2, pTmp + wcslen(L"Path="));

		RtlAppendUnicodeStringToString(pStrLocal, &uszLoc2);
		DbgPrint("pStrLocal is %wZ\n", *pStrLocal);

		RtlAppendUnicodeStringToString(pStrLocal, &StrFile);
		DbgPrint("pStrLocal is %wZ\n", *pStrLocal);
		status = STATUS_SUCCESS;
		if (pvpi)
		{
			ExFreePool(pvpi);
		}
		if (hRegister)
		{
			ZwClose(hRegister);
		}

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

	NTSTATUS status				= STATUS_UNSUCCESSFUL;

	/*
		U2Local
	*/
	UNICODE_STRING strUnc		= { 0 };
	UNICODE_STRING strLocal		= { 0 };

	strLocal.MaximumLength = MAX_PATH;
	strLocal.Length = 0;
	strLocal.Buffer = ExAllocatePoolWithTag(PagedPool, MAX_PATH * sizeof(WCHAR), 'TSET');
	RtlZeroMemory(strLocal.Buffer, MAX_PATH * sizeof(WCHAR));
	RtlInitUnicodeString(&strUnc, L"\\\\127.0.0.1\\Doc\\1.txt");//这里写死，已经在该目录下分享了文件

	status = UNC2Local(&strUnc, &strLocal);
	if (!NT_SUCCESS(status)) {
		DbgPrint("没找到\n");
	}
	else
	{
		DbgPrint("%wZ\n", &strLocal);
	}

	ExFreePool(strLocal.Buffer);

	return STATUS_SUCCESS;
}