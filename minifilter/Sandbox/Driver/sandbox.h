#ifndef __FSSANDBOX_H__
#define __FSSANDBOX_H__


#define		STATUS_SB_TRY_REPARSE			0xe0000001
#define		STATUS_SB_REPARSED				0xe0000002
#define		STATUS_SB_DIR_CREATED			0xe0000005

typedef struct _FILE_STREAMHANDLE_CONTEXT 
{
	BOOL		 m_bNewFile;
	FILE_INFORMATION_CLASS m_QueryType;
	PFILE_OBJECT 	outSideSbFileObj;
	PFLT_INSTANCE 	pInstance;
	WCHAR		 	m_Name[MAX_PATH];
	BOOL			m_bDelete;
	HANDLE			handle;
	WCHAR		 	m_FileName[MAX_PATH];
}FILE_STREAMHANDLE_CONTEXT,*PFILE_STREAMHANDLE_CONTEXT;

typedef struct _FILE_STREAM_CONTEXT {
	DWORD		 m_BaseVersion;
	DWORD		 m_Flags;
}FILE_STREAM_CONTEXT,*PFILE_STREAM_CONTEXT;

typedef struct _INSTANCE_CONTEXT {
	// FILE_DEVICE_CD_ROM_FILE_SYSTEM 
	// FILE_DEVICE_DISK_FILE_SYSTEM 
	// FILE_DEVICE_NETWORK_FILE_SYSTEM
	ULONG m_DeviceType; 
	// FILE_READ_ONLY_DEVICE 
	// FILE_FLOPPY_DISKETTE
	// FILE_REMOTE_DEVICE
	// FILE_REMOVABLE_MEDIA
	ULONG m_DeviceCharacteristics;
	// FLT_FSTYPE_UNKNOWN
	// FLT_FSTYPE_NTFS
	// FLT_FSTYPE_FAT
	// FLT_FSTYPE_CDFS
	// FLT_FSTYPE_NFS
	ULONG m_FSType;
	ULONG m_SectorSize;
	WCHAR m_VolumeName[MAX_PATH];
	
}INSTANCE_CONTEXT ,*PINSTANCE_CONTEXT ;

#define MyNew(_type, _count) \
(_type*)ExAllocatePoolWithTag(NonPagedPool, sizeof(_type) * (_count), 'FCLM')

#define MyDelete(_p) \
do{if(!(_p)) break; ExFreePool((_p)); (_p) = NULL;}while(0)

NTSTATUS 
InitSb(VOID);


NTSTATUS 
sbPreCreateFile(
	IN OUT PFLT_CALLBACK_DATA Data,
	IN PCFLT_RELATED_OBJECTS FltObjects
	);

NTSTATUS
sbPostCreateFile(
	IN OUT PFLT_CALLBACK_DATA Data, 
	IN PCFLT_RELATED_OBJECTS FltObjects
	);

NTSTATUS
sbPreSetInformationFile(
	IN OUT PFLT_CALLBACK_DATA Data, 
	IN PCFLT_RELATED_OBJECTS FltObjects
	);

NTSTATUS
sbPostSetInformationFile(
	IN OUT PFLT_CALLBACK_DATA Data, 
	IN PCFLT_RELATED_OBJECTS FltObjects
	);

VOID
SbCleanContextCallback(
    IN PFLT_CONTEXT  Context,
    IN FLT_CONTEXT_TYPE  ContextType
    );

BOOL 
SbIsFilenameWithSandboxPrefix(
	WCHAR *filename
	);

NTSTATUS 
SbGetFileNameInformation(
	PFLT_VOLUME		pVolume,
	PFLT_INSTANCE	pInstance,
	PFILE_OBJECT 	pFileObject,
	BOOLEAN			bGetFromCache,
	PFLT_FILE_NAME_INFORMATION	*pNameInfo
	);

#endif
