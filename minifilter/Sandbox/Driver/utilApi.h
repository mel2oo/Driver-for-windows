#ifndef __UTILAPI_H__
#define __UTILAPI_H__


BOOL TlQueryObjectName(HANDLE objHandle, PUNICODE_STRING objName, BOOL allocateName);
BOOL TlObQueryObjectName(PVOID pObject, PUNICODE_STRING objName, BOOL allocateName);
BOOL TlIsNtDeviceName(WCHAR * filename);
BOOL TlIsDosName(WCHAR * filename);
BOOL TlIsShortName(WCHAR * filename);
BOOL TlQueryVolumeName(WCHAR ch, WCHAR * name, USHORT size);

NTSTATUS
  FltIsDirectorySafe(
    IN PFILE_OBJECT  FileObject,
    IN PFLT_INSTANCE  Instance,
    OUT PBOOLEAN  IsDirectory
    );

NTSTATUS
FltQueryInformationFileSyncronous (
    IN PFLT_INSTANCE Instance,
    IN PFILE_OBJECT FileObject,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass,
    OUT PULONG LengthReturned OPTIONAL
    );

BOOL TlIsFileExist(IN PFLT_FILTER		Filter,
					 IN PFLT_INSTANCE  	Instance,
					 IN PUNICODE_STRING	pustrFileName);
BOOL
RtlFindSubString (
    IN PUNICODE_STRING String,
    IN PUNICODE_STRING SubString
    );

BOOL RtlPatternMatch (
		IN WCHAR * pat, 
		IN WCHAR * str
		);
BOOL RtlPatternNMatch(
		WCHAR * pat, 
		WCHAR * str, 
		DWORD count);

BOOL TlCanAccessChangeFile(ACCESS_MASK DesiredAccess);
BOOL SbShouldBeSandBoxed(HANDLE pid);

NTSTATUS TlQuerySymbolicLinkName(PUNICODE_STRING SymbolicLinkName, 
								 PUNICODE_STRING LinkTarget);

BOOL NTAPI GetNtDeviceName(WCHAR * filename, WCHAR * ntname);
BOOL NTAPI GetNTLinkName(WCHAR *wszNTName, WCHAR *wszFileName);
NTSTATUS  GetProcessFullNameByPid(HANDLE nPid, PUNICODE_STRING  FullPath);

BOOL IsShortNamePath(WCHAR * wszFileName);
BOOL ConverShortToLongName(WCHAR *wszLongName, WCHAR *wszShortName, ULONG size);


typedef enum _OBJECT_INFO_CLASS {
    ObjectBasicInfo,
		ObjectNameInfo,
		ObjectTypeInfo,
		ObjectAllTypesInfo,
		ObjectProtectionInfo
} OBJECT_INFO_CLASS;

NTSTATUS
NTAPI
ZwQueryInformationProcess(
						  __in HANDLE ProcessHandle,
						  __in PROCESSINFOCLASS ProcessInformationClass,
						  __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
						  __in ULONG ProcessInformationLength,
						  __out_opt PULONG ReturnLength
    );

#endif
