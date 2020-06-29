

#include <ntifs.h>
#include <ntdddisk.h>
#include <ntimage.h>
#include <stdio.h>
#include <windef.h>
#include <ntstrsafe.h>

#include "namelookup.h"
#include "namelookupdef.h"
#include "sfilter.h"
#include "misc.h"

#include "ioctlcmd.h"
#include "SFLock.h"
#include "hash.h"

#include "UserInteraction.h"

#pragma warning(disable:4995)

NTSTATUS
NTAPI
ZwQueryInformationProcess(
						  __in HANDLE ProcessHandle,
						  __in PROCESSINFOCLASS ProcessInformationClass,
						  __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
						  __in ULONG ProcessInformationLength,
						  __out_opt PULONG ReturnLength
    );



