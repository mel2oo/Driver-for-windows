
#ifndef __FSFILESYSTEM_H__
#define __FSFILESYSTEM_H__

#define DEL_MARK L".rem"
#define DEL_LENGTH 4

#define FI_COMPARE_RESULT_SAME 			1
#define FI_COMPARE_RESULT_DELETION_MARK	2

#define STATUS_NO_PARENT_PATH	1;


#define FI_GET_FILE_NAME(pSrcBuffer, ulNameOffset) (PWCHAR)((PBYTE)(pSrcBuffer) + (ulNameOffset))
#define FI_GET_FILE_NAME_LEN(pSrcBuffer, ulNameLengthOffset) (*((PULONG)((PBYTE)pSrcBuffer + ulNameLengthOffset)))
#define FI_GET_NEXT_ENTRY_OFFSET(pSrcBuffer) *(PULONG)(pSrcBuffer)
#define FI_GET_NEXT_ENTRY(pSrcBuffer) (PBYTE)((pSrcBuffer) + FI_GET_NEXT_ENTRY_OFFSET(pSrcBuffer))


#define		SB_GET_DISPOSITION(Options)		((Options & 0xFF000000) >> 24)
#define		SB_WITH_CREATE_ACCESS(Options)	(((Options == FILE_SUPERSEDE) || (Options == FILE_CREATE) || (Options == FILE_OPEN_IF) || (Options == FILE_OVERWRITE_IF)))
#define		SB_IS_DIRECTORY(Options)		((Options & FILE_DIRECTORY_FILE) != 0)

#define		SB_WRITE_ACCESS(Access)			((Access & FILE_GENERIC_WRITE) != 0)
#define		SB_DELETE_ACCESS(Access)		((Access & DELETE) != 0)
#define		SB_READONLY_ACCESS(Access)		((SB_WRITE_ACCESS(Access) == FALSE))
#define		SB_READONLY_ACCESS2(Access)		((SB_DELETE_ACCESS(Access) == FALSE))

#define UNICODE_STRING_CONST(x) \
{sizeof(L##x)-2, sizeof(L##x), L##x}


VOID SbGetSandboxPath(
	IN	PWCHAR	szSandboxName,
	IN	BOOL	bRegistry, 
	OUT	PWCHAR	lpszSandboxPath
	);


NTSTATUS
SbConvertToSbName(
	IN PUNICODE_STRING			pSandboxPath,
	IN PUNICODE_STRING			pSrcName,
	OUT PUNICODE_STRING			pDstName,
	OUT PUNICODE_STRING			pVolName
	);

NTSTATUS
SbConvertInSbNameToOutName(
	IN  PFLT_FILTER					pFilter,
	IN	PUNICODE_STRING				pNameInfo,
	IN  PUNICODE_STRING				pSandboxPath,
	OUT	PUNICODE_STRING				pSrcName,
	OUT PUNICODE_STRING				pustrVolumeDeviceName
	);

NTSTATUS
SbConvertDosToSbName(
	IN PUNICODE_STRING			pSandboxPath,
	IN PUNICODE_STRING			puszSrcName,
	IN OUT PUNICODE_STRING			pDestName
	);

NTSTATUS 
SbVolDeviceToDosName(
    IN PUNICODE_STRING VolumeDeviceName,
    OUT PWCHAR pDriverLetterChar,
    OUT PUSHORT	pusVolumeDeviceVolumeNameLength
    );


NTSTATUS
SbRedirectFile(
	IN	PFLT_CALLBACK_DATA 		Data,
	IN	PCFLT_RELATED_OBJECTS	FltObjects,
	IN	PUNICODE_STRING			pUstrDstFileName
	);


NTSTATUS
SbPrepareSandboxPath(
	IN PFLT_FILTER	pFilter,
	IN PFLT_INSTANCE	pInstance,
	IN PUNICODE_STRING  pSandboxPath,
	IN PUNICODE_STRING	pFileName,
	IN ACCESS_MASK		desiredAccess
	);

NTSTATUS
SbGetParentPath(
	IN PUNICODE_STRING pFileName,
	OUT PUNICODE_STRING pOutPath,
	IN BOOL bInsandbox);


NTSTATUS
SbCopyFile(
	IN PFLT_FILTER	pFilter,
	IN PFLT_INSTANCE	pSrcInstance,
	IN PFILE_OBJECT		pSrcFileObject,
	IN PUNICODE_STRING	pSrcFileName,
	IN PFLT_INSTANCE	pDstInstance,
	IN PUNICODE_STRING	pDstFileName,
	IN BOOLEAN 			bDirectory
	);


NTSTATUS
SbDoCopyFile(
	IN PFLT_FILTER	pFilter,
	IN PFILE_OBJECT	pSrcObject,
	IN PFLT_INSTANCE	pSrcInstance,
	IN PUNICODE_STRING	pSrcFileName,
	IN PFLT_INSTANCE	pDstInstance,
	IN PUNICODE_STRING	pDstFileName,
	IN BOOLEAN          bDirectory
	);

NTSTATUS
SbTraverseDirectory(
	IN PFLT_INSTANCE	pInstance,
	IN PFILE_OBJECT		pFileObject,
	IN PUNICODE_STRING	pQueryName,
	IN ULONG			uInformaton,
	IN PVOID			*pBuffer,
	IN PULONG			pSize
	);

BOOLEAN
SbFileExist(
	IN PFLT_FILTER	pFilter,
	IN PFLT_INSTANCE	pInstance,
	IN PUNICODE_STRING	pFileName
	);


PFLT_INSTANCE 
SbGetVolumeInstance(
	IN PFLT_FILTER		pFilter,
	IN PUNICODE_STRING	pVolumeName
	);

PFILE_OBJECT
SbGetFileObject(
	IN 		PCFLT_RELATED_OBJECTS FltObjects,
	IN 		PFLT_CALLBACK_DATA Data,
	IN 		BOOLEAN FEInSandbox,
	IN		PUNICODE_STRING pSandboxPath,
	OUT 	PFLT_INSTANCE *ppFEInstance,
	OUT		HANDLE*		handle
	);


NTSTATUS 
SbIsDirectory(
	IN 		PFILE_OBJECT fileObject,
	IN 		PUNICODE_STRING dirName, 
	IN 		PFLT_FILTER filter, 
	IN 		PFLT_INSTANCE instance, 
	OUT 	BOOLEAN* directory
	);

BOOLEAN
SBDeleteOneFile(
	IN	PFLT_INSTANCE Instance,
	IN	PFLT_FILTER  filter,
 	IN	PFILE_OBJECT pFile_obj,
  	IN 	PUNICODE_STRING FEName
	);

BOOLEAN
SbCreateOneFile(
	IN		PFLT_FILTER			filter,
	IN 		PFLT_INSTANCE		instance,
	OUT		PFILE_OBJECT*		fileObject,
	IN 		PUNICODE_STRING		fileName,
	IN 		BOOLEAN				bRtFileObj,
	IN      ACCESS_MASK			access_mask,
	IN      ULONG				createDisposition,
	IN		BOOLEAN				bDirectory
	);

USHORT 
SbGetVolLength(
	PFLT_FILTER pFilter, 
	PUNICODE_STRING pustrFullPath
	);

BOOLEAN
SbGetDestinationFileNameInformation(
		PVOID 				pInfo,
	   	PUNICODE_STRING		ustrRenamedName,
	   	BOOLEAN*			allocateMem
	  	);

PVOID 
MyAllocateMemory(
		IN POOL_TYPE	PoolType,
		IN SIZE_T		NumberOfBytes
		);

NTSTATUS 
SbGetFileNameInformation(
		PFLT_VOLUME		pVolume,
		PFLT_INSTANCE		pInstance,
		PFILE_OBJECT 		pFileObject,
		BOOLEAN			bGetFromCache,
		PFLT_FILE_NAME_INFORMATION	*pNameInfo
		);
BOOL 
SbIsFilenameWithSandboxPrefix(WCHAR *filename);

VOID
SbCleanContextCallback(
		IN PFLT_CONTEXT  Context,
		IN FLT_CONTEXT_TYPE  ContextType
		);

BOOL 
SbOperWillModifyFile(ACCESS_MASK DesiredAccess);

#endif
