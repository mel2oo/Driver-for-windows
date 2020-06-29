#ifndef USERINTERACTION_H
#define USERINTERACTION_H

#define		OPERTYPELEN		64
typedef struct _OP_INFO
{
    WCHAR     m_ProcessName[MAX_PATH];

    ULONG     m_ulWaitID;

	WCHAR	  m_szOper[OPERTYPELEN];
	
    WCHAR     m_TargetName[MAX_PATH];
    WCHAR     m_TargetNameEx[MAX_PATH];
	LIST_ENTRY m_List;
} OP_INFO, *LPOP_INFO;

typedef struct _RING3_OP_INFO
{
    WCHAR     m_ProcessName[MAX_PATH];

    ULONG     m_ulWaitID;

	WCHAR	  m_szOper[OPERTYPELEN];
	
    WCHAR     m_TargetName[MAX_PATH];
    WCHAR     m_TargetNameEx[MAX_PATH];
	
} RING3_OP_INFO, *LPRING3_OP_INFO;


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


typedef enum _USER_RESULT
{
		User_Pass,
		User_Block, 
		User_DefaultNon,	
}USER_RESULT;

#define FILE_OP_FLAG_OPEN						0x00000000
#define FILE_OP_FLAG_CREATE						0x00000001
#define FILE_OP_FLAG_READ						0x00000010
#define FILE_OP_FLAG_CREATE_SECTION				0x00000040
#define FILE_OP_FLAG_WRITE						0x00000100
#define FILE_OP_FLAG_ATTRIBUTE					0x00001000
#define FILE_OP_FLAG_USER_MODE_CALLBACK			0x00004000
#define FILE_OP_FLAG_DELETE						0x00010000
#define FILE_OP_FLAG_RENAME						0x00100000
#define FILE_OP_FLAG_RENAME2					0x00200000
#define FILE_OP_FLAG_BASIC						0x01000000
#define FILE_OP_FLAG_WRITTEN_ON_CLEANUP         0x02000000
#define FILE_OP_FLAG_OPEN_WITH_WRITE_ACCESS		0x40000000


USER_RESULT __stdcall hipsGetResultFromUser(WCHAR *szOperType, 
											WCHAR *szTarget, 
											WCHAR *szTargetEx, 
											USER_RESULT DefaultAction);

WAIT_LIST_ENTRY* FindWaitEntryByID(PLIST_ENTRY lpListHeader, ULONG ulWaitID);


#endif
