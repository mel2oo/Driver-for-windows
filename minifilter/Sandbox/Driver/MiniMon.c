#include "precom.h"

PFLT_FILTER gp_Filter = NULL;
extern PFLT_INSTANCE	g_SbVolInstance;
extern UNICODE_STRING	g_ustrVolumeDeviceName;


const FLT_CONTEXT_REGISTRATION MiniMonitorContext[] = {

    { FLT_STREAMHANDLE_CONTEXT,
      0,
      NULL,
      sizeof(FILE_STREAMHANDLE_CONTEXT),
      'FCLM' },

	{ FLT_STREAM_CONTEXT,
      0,
      NULL,
      sizeof(FILE_STREAM_CONTEXT),
      'FCLM' },

	{ FLT_INSTANCE_CONTEXT,
      0,
      NULL,
      sizeof(INSTANCE_CONTEXT),
      'FCLM' },

    { FLT_CONTEXT_END }
};

const FLT_OPERATION_REGISTRATION MiniMonitorCallbacks[] = {

    { IRP_MJ_CREATE,
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      Callback_PreCreateFile,
      Callback_PostCreateFile},

	{  IRP_MJ_SET_INFORMATION,
      0,
      Callback_PreSetInformationFile,
      Callback_PostSetInformationFile},

    { IRP_MJ_OPERATION_END}
};

const FLT_REGISTRATION MiniMonitorRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
	MiniMonitorContext,					//  ContextRegistration
    MiniMonitorCallbacks,               //  Operation callbacks
    MiniMonUnload,						//  FilterUnload
	MiniMonInstanceSetup,				//  InstanceSetup
    NULL,								//  InstanceQueryTeardown
    MiniMonInstanceTeardownStart,       //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent
};

NTSTATUS
MiniMonUnload (
    __in FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
	stopMiniMonitor();

    return STATUS_SUCCESS;
}

NTSTATUS
MiniMonInstanceSetup (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
	FILE_FS_OBJECTID_INFORMATION ObjectIdInfo;
	PINSTANCE_CONTEXT Context = NULL;
	PFLT_VOLUME Volume = NULL;
	BOOL bNew = FALSE;
	IO_STATUS_BLOCK IoStatusBlock;
	WCHAR szRoot[MAX_PATH] = L"";
	NTSTATUS ntStatus = 0;
	
	ntStatus = FltGetInstanceContext(FltObjects->Instance,
								   &Context);

	if(!NT_SUCCESS(ntStatus))
	{

		ntStatus = FltAllocateContext(gp_Filter,
							FLT_INSTANCE_CONTEXT,
							sizeof(INSTANCE_CONTEXT),
							PagedPool,
							&Context);

		if(!NT_SUCCESS(ntStatus))
		{
			return STATUS_SUCCESS;
		}

		RtlZeroMemory(Context, sizeof(INSTANCE_CONTEXT));
		bNew = TRUE;
	}

	Context->m_DeviceType = VolumeDeviceType;
	Context->m_FSType = VolumeFilesystemType;

	if(NT_SUCCESS(FltGetVolumeFromInstance(FltObjects->Instance, &Volume)))
	{
		DWORD dwRtn = 0;
		UNICODE_STRING uName;
		FLT_VOLUME_PROPERTIES Properties;

		RtlZeroMemory(&Properties, sizeof(FLT_VOLUME_PROPERTIES));

		uName.Length = 0;
		uName.MaximumLength = MAX_PATH * sizeof(WCHAR);
		uName.Buffer = Context->m_VolumeName;

		FltGetVolumeName(Volume, &uName, NULL);

		FltGetVolumeProperties(Volume, &Properties, sizeof(FLT_VOLUME_PROPERTIES), &dwRtn);

		FltObjectDereference(Volume);

		Context->m_SectorSize = Properties.SectorSize;
		Context->m_DeviceCharacteristics = Properties.DeviceCharacteristics;
	}
	ntStatus = FltQueryVolumeInformation(FltObjects->Instance, 
										&IoStatusBlock,
										&ObjectIdInfo, 
										sizeof(FILE_FS_OBJECTID_INFORMATION), 
										FileFsObjectIdInformation
										);
  	if (NT_SUCCESS(ntStatus))
  	{
  
  	}
	if(bNew)
	{
		ntStatus = FltSetInstanceContext(FltObjects->Instance, 
							  FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
							  Context,
							  NULL);
	}

    FltReleaseContext(Context);

	return STATUS_SUCCESS;
}

VOID MiniMonInstanceTeardownStart(
  __in PCFLT_RELATED_OBJECTS  FltObjects,
  __in FLT_INSTANCE_TEARDOWN_FLAGS  Reason
    )
{

}

FLT_PREOP_CALLBACK_STATUS
Callback_PreCreateFile (
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext
    )
{
	NTSTATUS status = 0;


	status = sbPreCreateFile(Data, FltObjects);

	if(!NT_SUCCESS(status)|| status == STATUS_REPARSE)
		return FLT_PREOP_COMPLETE;


	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
Callback_PostCreateFile (
     PFLT_CALLBACK_DATA Data,
     PCFLT_RELATED_OBJECTS FltObjects,
     PVOID CompletionContext,
     FLT_POST_OPERATION_FLAGS Flags
    )
{
	NTSTATUS status = 0;

	sbPostCreateFile(Data, FltObjects);


	if(!NT_SUCCESS(status))
		return FLT_POSTOP_FINISHED_PROCESSING;

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
Callback_PreSetInformationFile (
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext
    )
{
	NTSTATUS status = 0;

	status = sbPreSetInformationFile(Data, FltObjects);
	if(!NT_SUCCESS(status))
		return FLT_PREOP_COMPLETE;

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
Callback_PostSetInformationFile (
     PFLT_CALLBACK_DATA Data,
     PCFLT_RELATED_OBJECTS FltObjects,
     PVOID CompletionContext,
     FLT_POST_OPERATION_FLAGS Flags
    )
{

	sbPostSetInformationFile(Data, FltObjects);

	return FLT_POSTOP_FINISHED_PROCESSING;
}


NTSTATUS initFileMonitor (PDRIVER_OBJECT DriverObject )
{
	return FltRegisterFilter( DriverObject,
		&MiniMonitorRegistration,
		&gp_Filter );
}

NTSTATUS startMiniMonitor( )
{
	if(gp_Filter)
        return FltStartFiltering( gp_Filter );
	return STATUS_UNSUCCESSFUL;
}

VOID stopMiniMonitor( )
{
	if(gp_Filter)
	{
		FltUnregisterFilter( gp_Filter );
		gp_Filter = NULL;
	}
}



VOID UnloadMiniMonitor(PDRIVER_OBJECT DriverObject )
{
	stopMiniMonitor( );
	return;
}

