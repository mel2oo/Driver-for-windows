
#define MAX_PATH	260
typedef ULONG DWORD;

#pragma warning(disable:4996)

typedef struct _OP_INFO
{
    WCHAR     m_ProcessName[MAX_PATH];
    DWORD     m_ulProcessID;
    ULONG     m_ulWaitID;
    LIST_ENTRY m_List;
} OP_INFO, *POP_INFO;

typedef struct _RING3_OP_INFO
{
    WCHAR     m_ProcessName[MAX_PATH];
    DWORD     m_ulProcessID;
    ULONG     m_ulWaitID;


} RING3_OP_INFO, *PRING3_OP_INFO;

typedef struct _RING3_REPLY
{
    ULONG	m_ulWaitID;
    ULONG	m_ulBlocked;
}RING3_REPLY;

typedef struct _WAIT_LIST_ENTRY
{
	LIST_ENTRY	m_List;
	ULONG		m_ulWaitID;
	KEVENT		m_ulWaitEvent;
	ULONG		m_bBlocked;
}WAIT_LIST_ENTRY;


typedef enum _R3_RESULT
{
    R3Result_Pass,
    R3Result_Block, 
    R3Result_DefaultNon,	
}R3_RESULT;

typedef struct _KAPC_STATE
{
	LIST_ENTRY ApcListHead[2];
	PKPROCESS Process;
	UCHAR KernelApcInProgress;
	UCHAR KernelApcPending;
	UCHAR UserApcPending;
}KAPC_STATE, *PKAPC_STATE;

NTSTATUS  PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);
NTKERNELAPI VOID KeStackAttachProcess(PRKPROCESS PROCESS, PKAPC_STATE ApcState);
NTSTATUS ZwQueryInformationProcess(ULONG ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
NTKERNELAPI VOID KeUnstackDetachProcess(PKAPC_STATE ApcState);

