// InstallDrvDlg.cpp : implementation file
//

#include "stdafx.h"
#include "InstallDrv.h"
#include "InstallDrvDlg.h"
#include "Instdrv.h"
#include "ioctlcmd.h"
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

TCHAR g_driverLabel[] = _T("server100");		//需要与驱动中要建立的设备名一致
TCHAR g_driverName[] = _T("server.sys");	//驱动文件名
TCHAR g_driverPath[MAX_PATH] = _T("\0");

BOOL g_bInitialized = FALSE;
HANDLE gh_Device = INVALID_HANDLE_VALUE;

DWORD InitDriver()
{
	
	int iRetCode = ERROR_SUCCESS;
	HANDLE h_Device = INVALID_HANDLE_VALUE;
	DWORD d_error = 0;
	
	int time = 0;

	if (g_bInitialized)
	{
		return iRetCode;
	}

	try 
	{

		if(g_driverPath[0] ==_T('\0'))
		{
			GetCurrentDirectory(MAX_PATH, g_driverPath);
			PathAppend(g_driverPath, g_driverName);
		}
			
		if (LoadDeviceDriver(g_driverLabel, g_driverPath ,&h_Device, &d_error) == FALSE)
		{
			throw d_error;
		}

		gh_Device = h_Device;

	}
	catch (DWORD error) 
	{
		LPVOID lpMsgBuf = NULL;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | 
			FORMAT_MESSAGE_FROM_SYSTEM | 
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
			(LPTSTR) &lpMsgBuf, 0, NULL);
		MessageBox( NULL, (LPCTSTR)lpMsgBuf, _T("Error"), MB_OK | MB_ICONINFORMATION ); 
		if (lpMsgBuf)
			LocalFree(lpMsgBuf);
		
		return -1;	
	}
	
	g_bInitialized = TRUE;

	return (iRetCode);
} //InitDriver()

/////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	//{{AFX_DATA(CAboutDlg)
	enum { IDD = IDD_ABOUTBOX };
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CAboutDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CAboutDlg)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
	//{{AFX_DATA_INIT(CAboutDlg)
	//}}AFX_DATA_INIT
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAboutDlg)
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
	//{{AFX_MSG_MAP(CAboutDlg)
		// No message handlers
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CInstallDrvDlg dialog

CInstallDrvDlg::CInstallDrvDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CInstallDrvDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CInstallDrvDlg)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CInstallDrvDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CInstallDrvDlg)
		// NOTE: the ClassWizard will add DDX and DDV calls here
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CInstallDrvDlg, CDialog)
	//{{AFX_MSG_MAP(CInstallDrvDlg)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_SND, OnButtonSnd)
	ON_BN_CLICKED(IDC_BUTTON_START, OnButtonStart)
	ON_BN_CLICKED(IDC_BUTTON_STOP, OnButtonStop)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CInstallDrvDlg message handlers

BOOL CInstallDrvDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

// 	m_PopUpdlg.Create(IDD_POPUP_DIALOG);
// 	m_PopUpdlg.CenterWindow();
	
	// TODO: Add extra initialization here

	GetDlgItem(IDC_BUTTON_START)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_STOP)->EnableWindow(FALSE);
	
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CInstallDrvDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CInstallDrvDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, (WPARAM) dc.GetSafeHdc(), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CInstallDrvDlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}

#ifdef _DEBUG
#define _USEDEBUGPRINT
#endif

#ifdef _USEDEBUGPRINT
VOID DebugPrint(const CHAR *psz, ...);
#else
#define DebugPrint (void) 0
#endif

#ifdef _USEDEBUGPRINT
void DebugPrint(const TCHAR *psz, ...)
{	
	if (psz) 
	{
		TCHAR szBuf[1024] ={_T("[Client]")};
		DWORD dwLen = _tcslen(_T("[Client]"));
		
        va_list  args;
        va_start(args, psz);
		
        _stprintf( szBuf+ dwLen, psz, args );
		
		va_end(args);
		
		_tcscat(szBuf, _T("\n"));
        OutputDebugString(szBuf);
	}
}
#endif

void CInstallDrvDlg::OnButtonSnd() 
{
	DWORD ret = 0;
	DWORD read = 0;
	DWORD dwIn = 2011;

	if (InitDriver() != ERROR_SUCCESS)
	{
		DebugPrint(_T("加载驱动失败"));
		return;
	}
	DebugPrint(_T("开始攻击"));

	g_bInitialized = FALSE;
// 	DeviceIoControl(gh_Device, 
// 		IOCTL_XXX_YYY,
// 		&dwIn,
// 		sizeof(dwIn),
// 		&ret,
// 		sizeof(ret),
// 		&read,
// 		NULL);

// 	CString szRet;
// 	szRet.Format(_T("%d"), ret);
// 	MessageBox(szRet, _T("驱动返回"), MB_OK);

	DeviceIoControl(gh_Device, 
		IOCTL_XXX_ATTACK,
		&dwIn,
		sizeof(dwIn),
		&ret,
		sizeof(ret),
		&read,
		NULL);

 	CloseHandle(gh_Device);
	UnloadDeviceDriver(g_driverName);
	
}

CWinThread	*g_hReadThread = NULL;
BOOL	g_bToExitThread = FALSE;
HANDLE	g_hOverlappedEvent = NULL;

typedef struct _FILE_OP_INFO
{
    WCHAR     m_ProcessName[MAX_PATH];
    WCHAR     m_CmdLine[MAX_PATH];
    DWORD	  m_ulProcessID;
    DWORD     m_ulThreadID;
    ULONG     m_ulFileOP;
    ULONG     m_ulWaitID;
    DWORD     m_ulPPID;

    WCHAR     m_FileName[MAX_PATH];
    WCHAR     m_FileNameEx[MAX_PATH];
} FILE_OP_INFO, *LPFILE_OP_INFO;

typedef struct _RING3_REPLY
{
    ULONG	m_ulWaitID;
    ULONG	m_ulBlocked;
}RING3_REPLY;

typedef void (*FILE_AUDIT_CALLBACK_EX)(FILE_OP_INFO *pCallBack, int Num);
FILE_AUDIT_CALLBACK_EX g_lpfnCallBackEx = NULL;


VOID  NotifyDriverResult(ULONG ulWaitID, BOOL bBlocked)
{
    if (gh_Device == INVALID_HANDLE_VALUE)
    {
        return ;
    }
	
    RING3_REPLY R3Reply;
    R3Reply.m_ulWaitID = ulWaitID;
    R3Reply.m_ulBlocked = bBlocked;
	
    ULONG ulBytesReturn = 0;
    ::DeviceIoControl(gh_Device, IOCTL_NOTIFY_DRIVER_RESULT, &R3Reply, sizeof(RING3_REPLY), NULL, 0, &ulBytesReturn, NULL);
    
    return ;
}
BOOL  HandleData(FILE_OP_INFO *pCallBackData)
{
	DebugPrint(_T("准备弹框"));

	CPopupDlg dlg;

	dlg.SetProcess(pCallBackData->m_ProcessName);
	dlg.SetAction(pCallBackData->m_ulFileOP==0?_T("创建"):_T("删除"));
	dlg.SetFileName(pCallBackData->m_FileName[0]==_T('\0')?_T("c:\\Program Files\\common.dll"):pCallBackData->m_FileName);
	dlg.SetDetail(_T("有进程正在非法攻击"));

	dlg.DoModal();

	if (dlg.m_nRadio == 0)
	{
		DebugPrint(_T("弹框允许"));
		return FALSE;
	}
	DebugPrint(_T("弹框阻止"));
	return TRUE;
}

void  MyCallBack(FILE_OP_INFO *pCallBack, int Num)
{
	FILE_OP_INFO * currData = pCallBack;
	CString szNum;
	szNum.Format(_T("Num:%d"), Num);
	DebugPrint(szNum);

	for(int i = 0; i < Num; i++)
	{
		BOOL bResult = HandleData(currData);  // 此处可以弹框获得用户的结果
		if (bResult)
		{
			NotifyDriverResult(pCallBack->m_ulWaitID, TRUE);
		}
		else
		{
			NotifyDriverResult(pCallBack->m_ulWaitID, FALSE);
		}
		currData++;
	}
}

UINT ReadThreadEx(LPVOID lpContext)
{
    OVERLAPPED Overlapped;

	CInstallDrvDlg *pDlg = (CInstallDrvDlg *)lpContext;

	g_lpfnCallBackEx = MyCallBack;
    
    g_hOverlappedEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    
    if (g_hOverlappedEvent == NULL || g_lpfnCallBackEx == NULL || gh_Device == INVALID_HANDLE_VALUE)
    {
		DebugPrint(_T("参数非法"));
        return -1;
    }
    
    memset(&Overlapped, 0, sizeof(OVERLAPPED));
    
    ULONG ulReturn = 0;
    ULONG ulBytesReturn = 0;
    
    FILE_OP_INFO FileOpInfo;
    Overlapped.hEvent = g_hOverlappedEvent;
	
    ::SleepEx(1, TRUE);
    
    while (TRUE)
    {
        ulReturn = ReadFile(gh_Device, &FileOpInfo, sizeof(FILE_OP_INFO), &ulBytesReturn, &Overlapped);
        
        if (g_bToExitThread == TRUE)
        {
			DebugPrint(_T("线程要退出了"));
            break;
        }
        
        if (ulReturn == 0)
        {
            if (GetLastError() == ERROR_IO_PENDING)
            {
				DebugPrint(_T("PENDING IO"));
                ULONG ulApiReturn = WaitForSingleObject(Overlapped.hEvent, INFINITE);
				
                if (ulApiReturn == WAIT_FAILED)
                {
                    break;
                }
                if (g_bToExitThread == TRUE)
                {
                    break;
                }
            }
            else
            {
                continue;
            }
        }
		if (ulBytesReturn == sizeof(FILE_OP_INFO))
		{
			g_lpfnCallBackEx(&FileOpInfo, 1);
		}

    }
    
    return 0;
}

void CInstallDrvDlg::OnButtonStart() 
{

    DWORD dwThreadID = 0;
    g_bToExitThread = FALSE;

	if (InitDriver() != ERROR_SUCCESS)
	{
		return;
	}

    g_hReadThread = AfxBeginThread(ReadThreadEx, this);

	g_hReadThread->SuspendThread();
	g_hReadThread->m_bAutoDelete = FALSE;
	g_hReadThread->ResumeThread();
    

    if (g_hReadThread == NULL)
    {
        CloseHandle(gh_Device);
		g_bInitialized = FALSE;
        gh_Device = INVALID_HANDLE_VALUE;
        return;
    }
	GetDlgItem(IDC_BUTTON_START)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_STOP)->EnableWindow(TRUE);
}

void CInstallDrvDlg::OnButtonStop() 
{
	
    g_bToExitThread = TRUE;
    if (g_hOverlappedEvent != NULL)
    {
        ResetEvent(g_hOverlappedEvent);
		
        if (g_hReadThread != NULL)
        {
            if (WaitForSingleObject(g_hReadThread->m_hThread, 3000) == WAIT_TIMEOUT)
            {
                TerminateThread(g_hReadThread->m_hThread, 0);
            }
			delete g_hReadThread;
            g_hReadThread = NULL;
        }
		
        CloseHandle(g_hOverlappedEvent);
        g_hOverlappedEvent = NULL;
    }
    if (gh_Device != INVALID_HANDLE_VALUE)
    {
        CloseHandle(gh_Device);
		g_bInitialized = FALSE;
        gh_Device = INVALID_HANDLE_VALUE;
    }

	GetDlgItem(IDC_BUTTON_START)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_STOP)->EnableWindow(FALSE);
    return;
}
