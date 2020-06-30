#include "precomp.h"

GENERIC_MAPPING g_KeyMapping = {KEY_READ, KEY_WRITE, KEY_EXECUTE, KEY_ALL_ACCESS};
static WCHAR g_wszAltitude[] = L"370020";

PGENERIC_MAPPING IoGetKeyGenericMapping( )
{
	return &g_KeyMapping;
}

BOOL MyObQueryObjectName(HANDLE hObjHandle, PUNICODE_STRING ustrObjectName, BOOL bNeedAllocateName)
{
	PVOID			pQueryBuffer		= NULL;
	DWORD			dwReqSize			= 0;
	NTSTATUS		ntStatus			= 0;
	__try
	{
		dwReqSize = sizeof(OBJECT_NAME_INFORMATION) + (MAX_PATH + 32)*sizeof(WCHAR);
		
		pQueryBuffer = ExAllocatePoolWithTag(PagedPool, dwReqSize, 'RFLM');
		
		if(pQueryBuffer == NULL)
			return FALSE;
		
		ntStatus = ZwQueryObject(hObjHandle, 
			ObjectNameInfo,
			pQueryBuffer,
			dwReqSize,
			&dwReqSize);
		
		if((ntStatus == STATUS_INFO_LENGTH_MISMATCH) ||
			(ntStatus == STATUS_BUFFER_OVERFLOW) ||
			(ntStatus == STATUS_BUFFER_TOO_SMALL))
		{
			ExFreePool(pQueryBuffer);
			pQueryBuffer = NULL;
			
			pQueryBuffer = ExAllocatePoolWithTag(PagedPool, dwReqSize, 'RFLM');
			
			if(pQueryBuffer == NULL)
			{
				return FALSE;
			}
			
			ntStatus = ZwQueryObject(hObjHandle, 
				ObjectNameInfo,
				pQueryBuffer,
				dwReqSize,
				&dwReqSize);
			
		}
		
		if(NT_SUCCESS(ntStatus))
		{ 
			OBJECT_NAME_INFORMATION * pNameInfo = (OBJECT_NAME_INFORMATION *)pQueryBuffer;
			
			if(bNeedAllocateName)
			{
				ustrObjectName->Buffer = ExAllocatePoolWithTag(PagedPool, pNameInfo->Name.Length + sizeof(WCHAR), 'RFLM');
				
				if(ustrObjectName->Buffer)
				{
					RtlZeroMemory(ustrObjectName->Buffer, pNameInfo->Name.Length + sizeof(WCHAR));
					ustrObjectName->Length = 0;
					ustrObjectName->MaximumLength = pNameInfo->Name.Length;
					RtlCopyUnicodeString(ustrObjectName, &pNameInfo->Name);
				}
				else
					ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				
			}
			else
				RtlCopyUnicodeString(ustrObjectName, &pNameInfo->Name);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ntStatus = GetExceptionCode();
	}
	
	if(pQueryBuffer)
	{
		ExFreePool(pQueryBuffer);
		pQueryBuffer = NULL;
	}
	
	return NT_SUCCESS(ntStatus);
}


LARGE_INTEGER g_RegCookie;

#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSTATUS TlGetObjectNameOnVistaAndLater(PVOID Object, PUNICODE_STRING Name)
{
	PUNICODE_STRING			pKeyName = NULL;
	NTSTATUS				ntStatus = 0;

	if(Object == NULL || Name == NULL)
		return STATUS_INVALID_PARAMETER;

	ntStatus = CmCallbackGetKeyObjectID(&g_RegCookie,
									  Object,
									  NULL,
									 &pKeyName);

	if(NT_SUCCESS(ntStatus) == FALSE)
	{
		return ntStatus;
	}

	Name->Buffer = ( PWCHAR )ExAllocatePoolWithTag( 
							PagedPool, 
							pKeyName->Length,
							'RFLM'
							);

	if(Name->Buffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(Name->Buffer, pKeyName->Length);

	Name->Length = 0;
	Name->MaximumLength = pKeyName->Length;

	RtlCopyUnicodeString(Name, pKeyName);
	return STATUS_SUCCESS;
}
#endif

NTSTATUS TlGetObjectNameOnXP(PVOID Object, PUNICODE_STRING Name)
{
	UNICODE_STRING				ustrKeyName				= {0};
	HANDLE						ObjectHandle			= NULL;
	NTSTATUS					ntStatus				= 0;

	if(Object == NULL || Name == NULL)
		return STATUS_INVALID_PARAMETER;

	ntStatus = ObOpenObjectByPointer(Object,
							  OBJ_KERNEL_HANDLE ,
							  0,
							  0,
							  NULL,
							  KernelMode,
							  &ObjectHandle);

	if(NT_SUCCESS(ntStatus) == FALSE)
	{
		return ntStatus;
	}

	if(MyObQueryObjectName(ObjectHandle, &ustrKeyName, TRUE) == FALSE)
	{
		ZwClose(ObjectHandle);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	ZwClose(ObjectHandle);

	Name->Buffer = ( PWCHAR )ExAllocatePoolWithTag( 
							PagedPool, 
							ustrKeyName.Length,
							'RFLM'
							);

	if(Name->Buffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(Name->Buffer, ustrKeyName.Length);

	Name->Length = 0;
	Name->MaximumLength = ustrKeyName.Length;

	RtlCopyUnicodeString(Name, &ustrKeyName);
	ExFreePool(ustrKeyName.Buffer);

	return STATUS_SUCCESS;
}

NTSTATUS TlGetObjectFullName(PVOID Object, PUNICODE_STRING Name)
{
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	return TlGetObjectNameOnVistaAndLater(Object, Name);
#else
	return TlGetObjectNameOnXP(Object, Name);
#endif
}


NTSTATUS MyDeleteKey(PREG_DELETE_KEY_INFORMATION Data)
{
	NTSTATUS			ntStatus		= 0;
	UNICODE_STRING		ustrKeyName		= {0};

	__try
	{

		if((ExGetPreviousMode() == KernelMode))
		{
			return STATUS_SUCCESS;
		}

		if(NT_SUCCESS(TlGetObjectFullName(Data->Object, &ustrKeyName)) == FALSE)
		{
			return STATUS_SUCCESS;
		}
		DbgPrint("DeleteKey Key:%wZ\n", &ustrKeyName);

		ExFreePool(ustrKeyName.Buffer);

	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return STATUS_SUCCESS;
}

NTSTATUS MySetValueKey(PREG_SET_VALUE_KEY_INFORMATION Data)
{
	NTSTATUS				ntStatus				= 0;
	UNICODE_STRING			ustrKeyName				= {0};
	UNICODE_STRING			ustrTarget				= {0};
	WCHAR					wszKeyPath[MAX_PATH]	= {0};

	__try
	{
		
		if((ExGetPreviousMode() == KernelMode))
		{
			return STATUS_SUCCESS;
		}

		if(NT_SUCCESS(TlGetObjectFullName(Data->Object, &ustrKeyName)) == FALSE)
		{

			return STATUS_SUCCESS;
		}

		ustrTarget.Buffer = wszKeyPath;
		ustrTarget.MaximumLength = MAX_PATH * sizeof(WCHAR);
		
		RtlCopyUnicodeString(&ustrTarget, &ustrKeyName);


		ExFreePool(ustrKeyName.Buffer);

		if (ustrTarget.Buffer[ustrTarget.Length/sizeof(WCHAR) - 1] != L'\\' )
			RtlAppendUnicodeToString(&ustrTarget, L"\\");

		RtlAppendUnicodeStringToString(&ustrTarget, Data->ValueName);
		DbgPrint("SetValueKey Key:%wZ\n", &ustrTarget);

	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

	}

	return STATUS_SUCCESS;
}

NTSTATUS MyDeleteValueKey(PREG_DELETE_VALUE_KEY_INFORMATION Data)
{
	NTSTATUS				ntStatus				= 0;
	UNICODE_STRING			ustrKeyName				= {0};
	UNICODE_STRING			ustrTarget				= {0};
	WCHAR					wszKeyPath[MAX_PATH]	= {0};


	__try
	{

		if((ExGetPreviousMode() == KernelMode))
		{
			return STATUS_SUCCESS;
		}

		if(NT_SUCCESS(TlGetObjectFullName(Data->Object, &ustrKeyName)) == FALSE)
		{
			return STATUS_SUCCESS;
		}

		ustrTarget.Buffer = wszKeyPath;
		ustrTarget.MaximumLength = MAX_PATH * sizeof(WCHAR);
		
		RtlCopyUnicodeString(&ustrTarget, &ustrKeyName);

		ExFreePool(ustrKeyName.Buffer);

		if (ustrTarget.Buffer[ustrTarget.Length/sizeof(WCHAR) - 1]!=L'\\' )
			RtlAppendUnicodeToString(&ustrTarget, L"\\");

		RtlAppendUnicodeStringToString(&ustrTarget, Data->ValueName);
		DbgPrint("DeleteValueKey Key:%wZ\n", &ustrTarget);

	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

	}

	return STATUS_SUCCESS;
}

NTSTATUS MyRenameKey(PREG_RENAME_KEY_INFORMATION Data)
{
	NTSTATUS				ntStatus	= 0;
	UNICODE_STRING			ustrKeyName = {0};
	
	__try
	{
		if((ExGetPreviousMode() == KernelMode))
		{
			return STATUS_SUCCESS;
		}

		if(NT_SUCCESS(TlGetObjectFullName(Data->Object, &ustrKeyName)) == FALSE)
		{
			return STATUS_SUCCESS;
		}

		DbgPrint("RenameKey Key:%wZ\n", &ustrKeyName);

		ExFreePool(ustrKeyName.Buffer);


	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

	}

	return STATUS_SUCCESS;
}

NTSTATUS MyCreateKey(PREG_PRE_CREATE_KEY_INFORMATION Data)
{
	NTSTATUS			ntStatus				= 0;
	UNICODE_STRING		ustrTarget				= {0};
	WCHAR				wszKeyName[MAX_PATH]	= {0};

	__try
	{
		if((ExGetPreviousMode() == KernelMode))
		{
			return STATUS_SUCCESS;
		}
		
		ustrTarget.Buffer = wszKeyName;
		ustrTarget.MaximumLength = MAX_PATH * sizeof(WCHAR);
		
		RtlCopyUnicodeString(&ustrTarget, Data->CompleteName);
		DbgPrint("CreateKey Key:%wZ\n", &ustrTarget);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}

	return STATUS_SUCCESS;
}

NTSTATUS MyCreateKeyEx(PREG_CREATE_KEY_INFORMATION Data)
{
	NTSTATUS			ntStatus	= 0;
	UNICODE_STRING		ustrKeyName	= {0};
	UNICODE_STRING		ustrTarget	= {0};

	__try
	{
		if((ExGetPreviousMode() == KernelMode))
		{

			return STATUS_SUCCESS;
		}

		if(NT_SUCCESS(TlGetObjectFullName(Data->RootObject, &ustrKeyName)) == FALSE)
		{

			return STATUS_SUCCESS;
		}

		ustrTarget.MaximumLength = MAX_PATH * sizeof(WCHAR);
		
		RtlCopyUnicodeString(&ustrTarget, &ustrKeyName);

		ExFreePool(ustrKeyName.Buffer);
		
		if(Data->CompleteName)
		{
			RtlAppendUnicodeToString(&ustrTarget, L"\\");
			RtlAppendUnicodeStringToString(&ustrTarget, Data->CompleteName);
		}

		DbgPrint("CreateKeyEx :%wZ\n", ustrTarget);

	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{

	}

	return STATUS_SUCCESS;
}


NTSTATUS MyRegCallback
(
	PVOID CallbackContext, 
	PVOID Argument1, 
	PVOID Argument2
)
{
	switch( (REG_NOTIFY_CLASS) Argument1)
	{
	case RegNtPreDeleteKey :
		return MyDeleteKey((PREG_DELETE_KEY_INFORMATION) Argument2);
	case RegNtPreSetValueKey:
		return MySetValueKey((PREG_SET_VALUE_KEY_INFORMATION) Argument2);
	case RegNtPreDeleteValueKey:
		return MyDeleteValueKey((PREG_DELETE_VALUE_KEY_INFORMATION) Argument2);
	case RegNtPreRenameKey:
		return MyRenameKey((PREG_RENAME_KEY_INFORMATION) Argument2);
	case RegNtPreCreateKey:
		return MyCreateKey((PREG_PRE_CREATE_KEY_INFORMATION) Argument2);	
	case RegNtPreCreateKeyEx:
		return MyCreateKeyEx((PREG_CREATE_KEY_INFORMATION) Argument2);

	}

	return STATUS_SUCCESS;
}

NTSTATUS startRegMon(PDRIVER_OBJECT driverObject)
{
#if (NTDDI_VERSION >= NTDDI_VISTA)
	UNICODE_STRING uAltitude;

	RtlInitUnicodeString(&uAltitude, g_wszAltitude);
	return CmRegisterCallbackEx(MyRegCallback,
						  &uAltitude,
						  driverObject,
						  NULL,
						  &g_RegCookie,
						  NULL);	
#else
	return CmRegisterCallback(MyRegCallback,
							  NULL,
							 &g_RegCookie);

#endif
						  
}

VOID stopRegMon( )
{
	CmUnRegisterCallback(g_RegCookie);
}
