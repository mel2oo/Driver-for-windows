#include "DriverEntry.h"

LARGE_INTEGER CmHandle;

// 获取注册表完整路径
BOOLEAN GetRegisterObjectCompletePath(PUNICODE_STRING pRegistryPath, PVOID pRegistryObject)
{
	// 判断数据地址是否有效
	if ((FALSE == MmIsAddressValid(pRegistryObject)) ||
		(NULL == pRegistryObject))
	{
		return FALSE;
	}
	// 申请内存
	ULONG ulSize = 512;
	PVOID lpObjectNameInfo = ExAllocatePool(NonPagedPool, ulSize);
	if (NULL == lpObjectNameInfo)
	{
		return FALSE;
	}
	// 获取注册表路径
	ULONG ulRetLen = 0;
	NTSTATUS status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)lpObjectNameInfo, ulSize, &ulRetLen);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(lpObjectNameInfo);
		return FALSE;
	}
	// 复制
	RtlCopyUnicodeString(pRegistryPath, (PUNICODE_STRING)lpObjectNameInfo);
	// 释放内存
	ExFreePool(lpObjectNameInfo);
	return TRUE;
}


// 判断是否是保护注册表路径
BOOLEAN IsProtectReg(UNICODE_STRING ustrRegPath)
{
	if (NULL != wcsstr(ustrRegPath.Buffer, L"Everything"))
	{
		return TRUE;
	}

	return FALSE;
}

NTSTATUS RegisterMonCallback(_In_ PVOID CallbackContext, _In_opt_ PVOID Argument1, _In_opt_ PVOID Argument2)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING ustrRegPath;

	// 获取操作类型
	LONG lOperateType = (REG_NOTIFY_CLASS)Argument1;
	// 申请内存
	ustrRegPath.Length = 0;
	ustrRegPath.MaximumLength = 1024 * sizeof(WCHAR);
	ustrRegPath.Buffer = ExAllocatePool(NonPagedPool, ustrRegPath.MaximumLength);
	if (NULL == ustrRegPath.Buffer)
	{
		return status;
	}
	RtlZeroMemory(ustrRegPath.Buffer, ustrRegPath.MaximumLength);
	// 判断操作
	switch (lOperateType)
	{
		// 创建注册表之前
	case RegNtPreCreateKey:
	{
		// 获取注册表路径
		GetRegisterObjectCompletePath(&ustrRegPath, ((PREG_CREATE_KEY_INFORMATION)Argument2)->RootObject);

		// 显示
		DbgPrint("[RegNtPreCreateKey][%wZ][%wZ]\n", &ustrRegPath, ((PREG_CREATE_KEY_INFORMATION)Argument2)->CompleteName);
		break;
	}
	// 打开注册表之前
	case RegNtPreOpenKey:
	{
		// 获取注册表路径
		GetRegisterObjectCompletePath(&ustrRegPath, ((PREG_CREATE_KEY_INFORMATION)Argument2)->RootObject);

		// 显示
		DbgPrint("[RegNtPreOpenKey][%wZ][%wZ]\n", &ustrRegPath, ((PREG_CREATE_KEY_INFORMATION)Argument2)->CompleteName);
		break;
	}
	// 删除键之前
	case RegNtPreDeleteKey:
	{
		// 获取注册表路径
		GetRegisterObjectCompletePath(&ustrRegPath, ((PREG_DELETE_KEY_INFORMATION)Argument2)->Object);

		// 显示
		DbgPrint("[RegNtPreDeleteKey][%wZ]\n", &ustrRegPath);
		break;
	}
	// 删除键值之前
	case RegNtPreDeleteValueKey:
	{
		// 获取注册表路径
		GetRegisterObjectCompletePath(&ustrRegPath, ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->Object);

		// 显示
		DbgPrint("[RegNtPreDeleteValueKey][%wZ][%wZ]\n", &ustrRegPath, ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->ValueName);
		break;
	}
	// 修改键值之前
	case RegNtPreSetValueKey:
	{
		// 获取注册表路径
		GetRegisterObjectCompletePath(&ustrRegPath, ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->Object);

		// 显示
		DbgPrint("[RegNtPreSetValueKey][%wZ][%wZ]\n", &ustrRegPath, ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->ValueName);
		break;
	}
	default:
		break;
	}
	// 判断是否是被保护的注册表
	if (IsProtectReg(ustrRegPath))
	{
		// 拒绝操作
		status = STATUS_ACCESS_DENIED;
	}
	// 释放内存
	if (NULL != ustrRegPath.Buffer)
	{
		ExFreePool(ustrRegPath.Buffer);
		ustrRegPath.Buffer = NULL;
	}

	// 获取当前进程, 即操作注册表的进程
	PEPROCESS pEProcess = PsGetCurrentProcess();
	if (NULL != pEProcess)
	{
		UCHAR *lpszProcessName = PsGetProcessImageFileName(pEProcess);
		if (NULL != lpszProcessName)
		{
			DbgPrint("Current Process[%s]\n", lpszProcessName);
		}
	}

	return status;
}

VOID DrivrUnload(PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS status;
	CmUnRegisterCallback(CmHandle);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegpath)
{
	NTSTATUS status = STATUS_SUCCESS;

	pDriverObject->DriverUnload = DrivrUnload;

	status = CmRegisterCallback(RegisterMonCallback, NULL, &CmHandle);

	return status;
}