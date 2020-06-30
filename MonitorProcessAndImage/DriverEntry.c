#include "DriverEntry.h"


VOID CreateProcessRoutineEx(IN HANDLE  ParentId, IN HANDLE  ProcessId, IN BOOLEAN  Create)
{
	if (Create)
	{
		KdPrint(("[SysTest] Process Created. ParentId:(%d) ProcessId:(%d).\n", ParentId, ProcessId));

		PEPROCESS Process = NULL;
		NTSTATUS status;
		INT i;

		status = PsLookupProcessByProcessId(ProcessId, &Process);
		if (NT_SUCCESS(status))
		{
			for (i = 0; i < 3 * PAGE_SIZE; i++)
			{
				if (!strncmp("notepad.exe", (PCHAR)Process + i, strlen("notepad.exe")))
				{
					if (i < 3 * PAGE_SIZE)
					{
						KdPrint(("ProcessName:%s\n", (PCHAR)((ULONG)Process + i)));
						break;
					}
				}
			}
		}
	}
	else
	{
		KdPrint(("[SysTest] Process Terminated ProcessId:(%d).ParentId:(%d) .\n", ProcessId, ParentId));
	}

	return;
}

VOID LoadImageNotifyRoutine(__in_opt PUNICODE_STRING FullImageName, __in HANDLE ProcessId, __in PIMAGE_INFO ImageInfo)
{
	KdPrint(("LoadImageNotifyRoutine\n"));
}

VOID DrivrUnload(PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS status;

	status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)CreateProcessRoutineEx, TRUE);

	status = PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)LoadImageNotifyRoutine);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegpath)
{
	NTSTATUS status;

	status = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)CreateProcessRoutineEx, FALSE);

	status = PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)LoadImageNotifyRoutine);

	return status;
}