#include <ntddk.h>
#include "./hash/hash.h"

#define		HASH_TABLE_SIZE	100

PHASHTABLE g_pHashTable = NULL; //HASH表
ERESOURCE  g_HashTableLock;

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("DriverUnload...\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);

	DbgPrint("DriverEntry...\n");

	pDriverObject->DriverUnload = DriverUnload;

	/*
		// 初始化创建hash表
		g_pHashTable = InitializeTable(HASH_TABLE_SIZE);
		if (g_pHashTable == NULL)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		InitLock(&g_HashTableLock);

		LockWrite(&g_HashTableLock);
		Insert((DWORD)lpFileObject, lpData, g_pHashTable);
		UnLockWrite(&g_HashTableLock);

		lpTwoWay = Find((DWORD)lpFileObject, g_pHashTable);

		LockWrite(&g_HashTableLock);
		Remove((DWORD)lpFileObject, g_pHashTable);
		UnLockWrite(&g_HashTableLock);

		// 释放hash表

		DeleteLock(&g_HashTableLock);	//卸载历程中删除锁

		if (g_pHashTable)
		{
			DestroyTable(g_pHashTable);
		}	
	*/



	return STATUS_SUCCESS;
}