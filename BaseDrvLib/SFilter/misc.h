#ifndef _MISC_H_
#define _MISC_H_

#ifndef MAX_PATH
#define MAX_PATH 296
#endif

#define PROCESS_QUERY_INFORMATION (0x0400) 
#define INVALID_PID_VALUE 0xFFFFFFFF

BOOL IsSystemProcess( );

BOOL NTAPI GetNtDeviceName(WCHAR * filename, WCHAR * ntname);
BOOL NTAPI GetNTLinkName(WCHAR *wszNTName, WCHAR *wszFileName);
BOOL IsDosDeviceName(WCHAR * filename);


NTSTATUS  GetProcessFullNameByPid(HANDLE nPid, PUNICODE_STRING  FullPath);
BOOL IsShortNamePath(WCHAR * wszFileName);
BOOL ConverShortToLongName(WCHAR *wszLongName, WCHAR *wszShortName, ULONG size);

BOOLEAN IsDir(PIO_STACK_LOCATION pIrpStack);

BOOLEAN IsPatternMatch(PUNICODE_STRING Expression, PUNICODE_STRING Name, BOOLEAN IgnoreCase);
BOOL PatternMatch(WCHAR * pat, WCHAR * str);
BOOL PatternNMatch(WCHAR * pat, WCHAR * str, DWORD count);

#endif