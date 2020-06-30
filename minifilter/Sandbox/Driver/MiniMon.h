#ifndef __MINIMON_H__
#define __MINIMON_H__

FLT_PREOP_CALLBACK_STATUS
Callback_PreCreateFile (
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
Callback_PostCreateFile (
     PFLT_CALLBACK_DATA Data,
     PCFLT_RELATED_OBJECTS FltObjects,
     PVOID CompletionContext,
     FLT_POST_OPERATION_FLAGS Flags
    );


FLT_PREOP_CALLBACK_STATUS
Callback_PreSetInformationFile (
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
Callback_PostSetInformationFile (
     PFLT_CALLBACK_DATA Data,
     PCFLT_RELATED_OBJECTS FltObjects,
     PVOID CompletionContext,
     FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
Callback_PreQueryDirectoryInformation (
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID *CompletionContext
	);

NTSTATUS MiniMonUnload (
	FLT_FILTER_UNLOAD_FLAGS Flags
	);


VOID MiniMonInstanceTeardownStart(
  __in PCFLT_RELATED_OBJECTS  FltObjects,
  __in FLT_INSTANCE_TEARDOWN_FLAGS  Reason
    );

NTSTATUS
MiniMonInstanceSetup (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );
NTSTATUS initFileMonitor (
	PDRIVER_OBJECT DriverObject 
	);

NTSTATUS startMiniMonitor( );
VOID stopMiniMonitor( );
VOID UnloadMiniMonitor(PDRIVER_OBJECT DriverObject );

#endif 

