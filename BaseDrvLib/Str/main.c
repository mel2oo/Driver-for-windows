#include <ntddk.h>
#include <ntstrsafe.h>

#define MAX_PATH 260

/*
	Allocate memory from stack space
*/
VOID UseUnicodeStringFromStack()
{
	UNICODE_STRING ustr = { 0 };
	WCHAR buf[512] = L"Hello World";

	ustr.Buffer = buf;
	ustr.Length = wcslen(buf) * sizeof(WCHAR);
	ustr.MaximumLength = (wcslen(buf) + 1) * sizeof(WCHAR);

	DbgPrint("%wZ\n", ustr);
}

/*
	Allocate memory from heap space
*/
VOID UseUnicodeStringFromHeap()
{
	UNICODE_STRING ustr = { 0 };
	WCHAR buf[] = L"Hello World";

	ustr.Length = wcslen(buf) * sizeof(WCHAR);
	ustr.MaximumLength = (wcslen(buf) + 1) * sizeof(WCHAR);
	ustr.Buffer = ExAllocatePoolWithTag(PagedPool, ustr.MaximumLength, 'Rios');

	if (ustr.Buffer == NULL)
	{
		DbgPrint("Allocate space fail\n");
		return;
	}

	RtlZeroMemory(ustr.Buffer, ustr.MaximumLength);
	RtlCopyMemory(ustr.Buffer, buf, ustr.Length);

	DbgPrint("%wZ\n", ustr);

	if (ustr.Buffer != NULL)
	{
		ExFreePoolWithTag(ustr.Buffer, 'Rios');
		ustr.Buffer = NULL;
		ustr.Length = ustr.MaximumLength = 0;
	}
}

/*
	Allocate memory from const space
*/
VOID UseUnicodeStringFromConst()
{
	UNICODE_STRING ustr = { 0 };
	WCHAR buf[] = L"Hello World";

	RtlInitUnicodeString(&ustr, buf);

	DbgPrint("%wZ\n", ustr);
}

/*
	RtlCopyUnicodeString
*/
VOID UseUnicodeStringCopy()
{
	UNICODE_STRING SourceString = { 0 };
	UNICODE_STRING DestinationString = { 0 };

	RtlInitUnicodeString(&SourceString, L"Hello World");

	DestinationString.Length = SourceString.Length;
	DestinationString.MaximumLength = SourceString.MaximumLength;
	DestinationString.Buffer = ExAllocatePoolWithTag(PagedPool, DestinationString.MaximumLength, 'Rios');

	if (DestinationString.Buffer == NULL)
	{
		DbgPrint("Allocate space fail\n");
		return;
	}

	RtlCopyUnicodeString(&DestinationString, &SourceString);

	DbgPrint("%wZ\n%wZ\n", SourceString, DestinationString);

	if (DestinationString.Buffer != NULL)
	{
		ExFreePoolWithTag(DestinationString.Buffer, 'Rios');
		DestinationString.Length = DestinationString.MaximumLength = 0;
	}
}

/*
	RtlEqualUnicodeString
*/
VOID UseUnicodeStringCompare()
{
	UNICODE_STRING str1;
	UNICODE_STRING str2;

	RtlInitUnicodeString(&str1, L"Hello World");
	RtlInitUnicodeString(&str2, L"Hello World");

	if (RtlEqualUnicodeString(&str1, &str2, TRUE))
	{
		DbgPrint("this string are equal\n");
	}
	else
	{
		DbgPrint("this string are not equal\n");
	}
}

/*
	RtlUpcaseUnicodeString
*/
VOID UseUnicodeStringUpper()
{
	UNICODE_STRING SourceString = { 0 };
	UNICODE_STRING DestinationString = { 0 };;

	RtlInitUnicodeString(&SourceString, L"Hello World");

	DestinationString.Length = SourceString.Length;
	DestinationString.MaximumLength = SourceString.MaximumLength;
	DestinationString.Buffer = ExAllocatePoolWithTag(PagedPool, DestinationString.MaximumLength, 'Rios');

	if (DestinationString.Buffer == NULL)
	{
		DbgPrint("Allocate space fail\n");
		return;
	}

	RtlUpcaseUnicodeString(
		&DestinationString,
		&SourceString,
		FALSE);

	DbgPrint("%wZ\n%wZ\n", SourceString, DestinationString);

	if (DestinationString.Buffer != NULL)
	{
		ExFreePoolWithTag(DestinationString.Buffer, 'Rios');
		DestinationString.Length = DestinationString.MaximumLength = 0;
	}
}

/*
	RtlUnicodeStringToInteger
	RtlIntegerToUnicodeString

	RtlUnicodeStringToAnsiString
	RtlAnsiStringToUnicodeString

	RtlAppendUnicodeStringToString
	RtlAppendUnicodeToString

	安全的函数，含有溢出检测 --- #include <ntstrsafe.h>
	
	RtlUnicodeStringInit(&uStr,szStr);

	RtlUnicodeStringCopy(&uStr,&uStr1);

	RtlUnicodeStringCat(&uStr,&uStr1);
*/

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("DriverUnload...\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);

	DbgPrint("DriverEntry...\n");

	pDriverObject->DriverUnload = DriverUnload;

	UseUnicodeStringFromStack();

	UseUnicodeStringFromHeap();

	UseUnicodeStringFromConst();

	UseUnicodeStringCopy();

	UseUnicodeStringCompare();

	UseUnicodeStringUpper();

	return STATUS_SUCCESS;
}