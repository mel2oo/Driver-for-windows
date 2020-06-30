// InstallDrvDlg.cpp : implementation file
//

#include "stdafx.h"
#include "InstallDrv.h"
#include "InstallDrvDlg.h"
#include "ioctlcmd.h"

#pragma comment(lib, "strsafe.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "fltlib.lib")	//这个居然在TOOLS-->OPTIONS-->VC++ Directories-->Lib中设置了还不好使

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

BOOL g_bInitialized = FALSE;
HANDLE gh_Device = INVALID_HANDLE_VALUE;

#define DRIVER_NAME ("sandbox")
#define DRIVER_PATH (".\\sandbox.sys.sys")
#define DRIVER_ALTITUDE	 "370020"

// SYS文件跟程序放在同个目录下
// InstallDriver(DRIVER_NAME,DRIVER_PATH,DRIVER_ALTITUDE);
// 启动驱动服务 StartDriver(DRIVER_NAME);
// 停止驱动服务 StopDriver(DRIVER_NAME);
// 卸载服务 DeleteDriver(DRIVER_NAME);

BOOL InstallDriver(const char* lpszDriverName,const char* lpszDriverPath,const char* lpszAltitude)
{
	char    szTempStr[MAX_PATH];
	HKEY    hKey;
	DWORD    dwData;
	char    szDriverImagePath[MAX_PATH];    

	if( NULL==lpszDriverName || NULL==lpszDriverPath )
	{
		return FALSE;
	}
	//得到完整的驱动路径
	GetFullPathNameA(lpszDriverPath, MAX_PATH, szDriverImagePath, NULL);

	SC_HANDLE hServiceMgr=NULL;// SCM管理器的句柄
	SC_HANDLE hService=NULL;// NT驱动程序的服务句柄

	//打开服务控制管理器
	hServiceMgr = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
	if( hServiceMgr == NULL ) 
	{
		// OpenSCManager失败
		CloseServiceHandle(hServiceMgr);
		return FALSE;        
	}

	// OpenSCManager成功  

	//创建驱动所对应的服务
	hService = CreateServiceA( hServiceMgr,
		lpszDriverName,             // 驱动程序的在注册表中的名字
		lpszDriverName,             // 注册表驱动程序的DisplayName 值
		SERVICE_ALL_ACCESS,         // 加载驱动程序的访问权限
		SERVICE_FILE_SYSTEM_DRIVER, // 表示加载的服务是文件系统驱动程序
		SERVICE_DEMAND_START,       // 注册表驱动程序的Start 值
		SERVICE_ERROR_IGNORE,       // 注册表驱动程序的ErrorControl 值
		szDriverImagePath,          // 注册表驱动程序的ImagePath 值
		"FSFilter Activity Monitor",// 注册表驱动程序的Group 值
		NULL, 
		"FltMgr",                   // 注册表驱动程序的DependOnService 值
		NULL, 
		NULL);

	if( hService == NULL ) 
	{        
		if( GetLastError() == ERROR_SERVICE_EXISTS ) 
		{
			//服务创建失败，是由于服务已经创立过
			CloseServiceHandle(hService);       // 服务句柄
			CloseServiceHandle(hServiceMgr);    // SCM句柄
			return TRUE; 
		}
		else 
		{
			CloseServiceHandle(hService);       // 服务句柄
			CloseServiceHandle(hServiceMgr);    // SCM句柄
			return FALSE;
		}
	}
	CloseServiceHandle(hService);       // 服务句柄
	CloseServiceHandle(hServiceMgr);    // SCM句柄

	//-------------------------------------------------------------------------------------------------------
	// SYSTEM\\CurrentControlSet\\Services\\DriverName\\Instances子健下的键值项 
	//-------------------------------------------------------------------------------------------------------
	strcpy(szTempStr,"SYSTEM\\CurrentControlSet\\Services\\");
	strcat(szTempStr,lpszDriverName);
	strcat(szTempStr,"\\Instances");
	if(RegCreateKeyExA(HKEY_LOCAL_MACHINE,szTempStr,0,"",TRUE,KEY_ALL_ACCESS,NULL,&hKey,(LPDWORD)&dwData)!=ERROR_SUCCESS)
	{
		return FALSE;
	}
	// 注册表驱动程序的DefaultInstance 值 
	strcpy(szTempStr,lpszDriverName);
	strcat(szTempStr," Instance");
	if(RegSetValueExA(hKey,"DefaultInstance",0,REG_SZ,(CONST BYTE*)szTempStr,(DWORD)strlen(szTempStr))!=ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegFlushKey(hKey);//刷新注册表
	RegCloseKey(hKey);


	//-------------------------------------------------------------------------------------------------------
	// SYSTEM\\CurrentControlSet\\Services\\DriverName\\Instances\\DriverName Instance子健下的键值项 
	//-------------------------------------------------------------------------------------------------------
	strcpy(szTempStr,"SYSTEM\\CurrentControlSet\\Services\\");
	strcat(szTempStr,lpszDriverName);
	strcat(szTempStr,"\\Instances\\");
	strcat(szTempStr,lpszDriverName);
	strcat(szTempStr," Instance");
	if(RegCreateKeyExA(HKEY_LOCAL_MACHINE,szTempStr,0,"",TRUE,KEY_ALL_ACCESS,NULL,&hKey,(LPDWORD)&dwData)!=ERROR_SUCCESS)
	{
		return FALSE;
	}
	// 注册表驱动程序的Altitude 值
	strcpy(szTempStr,lpszAltitude);
	if(RegSetValueExA(hKey,"Altitude",0,REG_SZ,(CONST BYTE*)szTempStr,(DWORD)strlen(szTempStr))!=ERROR_SUCCESS)
	{
		return FALSE;
	}
	// 注册表驱动程序的Flags 值
	dwData=0x0;
	if(RegSetValueExA(hKey,"Flags",0,REG_DWORD,(CONST BYTE*)&dwData,sizeof(DWORD))!=ERROR_SUCCESS)
	{
		return FALSE;
	}
	RegFlushKey(hKey);//刷新注册表
	RegCloseKey(hKey);

	return TRUE;
}

BOOL StartDriver(const char* lpszDriverName)
{
	SC_HANDLE        schManager;
	SC_HANDLE        schService;

	if(NULL==lpszDriverName)
	{
		return FALSE;
	}

	schManager=OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if(NULL==schManager)
	{
		CloseServiceHandle(schManager);
		return FALSE;
	}
	schService=OpenServiceA(schManager,lpszDriverName,SERVICE_ALL_ACCESS);
	if(NULL==schService)
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		return FALSE;
	}

	if(!StartService(schService,0,NULL))
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		if( GetLastError() == ERROR_SERVICE_ALREADY_RUNNING ) 
		{             
			// 服务已经开启
			return TRUE;
		} 
		return FALSE;
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);

	return TRUE;
}

BOOL StopDriver(const char* lpszDriverName)
{
	SC_HANDLE        schManager;
	SC_HANDLE        schService;
	SERVICE_STATUS    svcStatus;
	bool            bStopped=false;

	schManager=OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if(NULL==schManager)
	{
		return FALSE;
	}
	schService=OpenServiceA(schManager,lpszDriverName,SERVICE_ALL_ACCESS);
	if(NULL==schService)
	{
		CloseServiceHandle(schManager);
		return FALSE;
	}    
	if(!ControlService(schService,SERVICE_CONTROL_STOP,&svcStatus) && (svcStatus.dwCurrentState!=SERVICE_STOPPED))
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		return FALSE;
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);

	return TRUE;
}

BOOL DeleteDriver(const char* lpszDriverName)
{
	SC_HANDLE        schManager;
	SC_HANDLE        schService;
	SERVICE_STATUS    svcStatus;

	schManager=OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if(NULL==schManager)
	{
		return FALSE;
	}
	schService=OpenServiceA(schManager,lpszDriverName,SERVICE_ALL_ACCESS);
	if(NULL==schService)
	{
		CloseServiceHandle(schManager);
		return FALSE;
	}
	ControlService(schService,SERVICE_CONTROL_STOP,&svcStatus);
	if(!DeleteService(schService))
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schManager);
		return FALSE;
	}
	CloseServiceHandle(schService);
	CloseServiceHandle(schManager);

	return TRUE;
}


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
	m_lpContext = NULL;
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
		
        StringCbPrintf( szBuf+ dwLen, 1024-dwLen, psz, args );
		
		va_end(args);
		
		StringCbCat(szBuf, 2, _T("\n"));
        OutputDebugString(szBuf);
	}
}
#endif

void CInstallDrvDlg::OnButtonSnd() 
{

	
}

CWinThread	*g_hReadThread = NULL;
BOOL	g_bToExitThread = FALSE;


typedef struct _OP_INFO
{
    WCHAR     m_ProcessName[MAX_PATH];

    WCHAR     m_FileName[MAX_PATH];
    WCHAR     m_FileNameEx[MAX_PATH];
} OP_INFO, *LPOP_INFO;

typedef struct _RING3_REPLY
{
    ULONG	m_ulWaitID;
    BOOL	m_bBlocked;
}RING3_REPLY;

BOOL  HandleData(OP_INFO *pCallBackData)
{
	DebugPrint(_T("准备弹框"));

	CPopupDlg dlg;

	dlg.SetProcess(pCallBackData->m_ProcessName);
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

BOOL  MyCallBack(OP_INFO *pCallBack, int Num)
{
	OP_INFO	*currData = pCallBack;
	CString			szNum = _T("");

	//for(int i = 0; i < Num; i++)
	{
		BOOL bResult = HandleData(currData);  // 此处可以弹框获得用户的结果
		return bResult;
		
	}
}

UINT SandboxThread(PSANDBOX_THREAD_CONTEXT  lpContext)
{
	PSANDBOX_NOTIFICATION	notification	= NULL;
	SANDBOX_REPLY_MESSAGE	replyMessage	= {0};
	PSANDBOX_MESSAGE		message			= {0};
	LPOVERLAPPED			pOvlp			= {0};
	BOOL					result			= FALSE;
	DWORD					outSize			= 0;
	HRESULT					hr				= 0;
	ULONG_PTR				key				= 0;

#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant

	while (g_bToExitThread == FALSE)
	{

#pragma warning(pop)

		//
		//  Poll for messages from the filter component to scan.
		//

		result = GetQueuedCompletionStatus( lpContext->Completion, &outSize, &key, &pOvlp, INFINITE );

		//
		//  Obtain the message: note that the message we sent down via FltGetMessage() may NOT be
		//  the one dequeued off the completion queue: this is solely because there are multiple
		//  threads per single port handle. Any of the FilterGetMessage() issued messages can be
		//  completed in random order - and we will just dequeue a random one.
		//
		if (key == (ULONG_PTR) -1)
		{
			break;

		}

		message = CONTAINING_RECORD( pOvlp, SANDBOX_MESSAGE, Ovlp );

		if (!result) 
		{

			//
			//  An error occured.
			//

			hr = HRESULT_FROM_WIN32( GetLastError() );
			break;
		}

		notification = &message->Notification;

		assert(notification->BytesToScan <= SANDBOX_READ_BUFFER_SIZE);
		__analysis_assume(notification->BytesToScan <= SANDBOX_READ_BUFFER_SIZE);

		result = MyCallBack((OP_INFO *)notification->Contents, notification->BytesToScan);

		replyMessage.ReplyHeader.Status = 0;
		replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;

		//
		//  Need to invert the boolean -- result is true if found
		//  foul language, in which case SafeToOpen should be set to false.
		//

		replyMessage.Reply.SafeToOpen = !result;

		hr = FilterReplyMessage( lpContext->Port,
			(PFILTER_REPLY_HEADER) &replyMessage,
			sizeof( replyMessage ) );

		if (SUCCEEDED( hr )) 
		{

		} 
		else 
		{
			break;
		}

		memset( &message->Ovlp, 0, sizeof( OVERLAPPED ) );

		hr = FilterGetMessage( lpContext->Port,
			&message->MessageHeader,
			FIELD_OFFSET( SANDBOX_MESSAGE, Ovlp ),
			&message->Ovlp );

		if (hr != HRESULT_FROM_WIN32( ERROR_IO_PENDING )) 
		{

			break;
		}
	}

	if (!SUCCEEDED( hr )) 
	{

		if (hr == HRESULT_FROM_WIN32( ERROR_INVALID_HANDLE )) 
		{


		} 
		else 
		{

		}
	}

	free( message );

	return hr;
}

HANDLE OpenDevice()
{
	//测试驱动程序  
	HANDLE hDevice = CreateFile(_T("\\\\.\\sandbox"),  
		GENERIC_WRITE | GENERIC_READ,  
		0,  
		NULL,  
		OPEN_EXISTING,  
		0,  
		NULL);  
	if( hDevice != INVALID_HANDLE_VALUE )  
	{
		printf( "Create Device ok ! \n" );  
	}
	else  
	{
		printf( "Create Device faild %d ! \n", GetLastError() ); 
		return NULL;
	}

	return hDevice;
} 

void CInstallDrvDlg::OnButtonStart() 
{

    DWORD						dwThreadID	= 0;
	HRESULT						hr			= NULL;
	HANDLE						port		= NULL;
	HANDLE						completion	= NULL;

	//安装驱动调用这个函数
	BOOL bRet = InstallDriver(DRIVER_NAME, DRIVER_PATH, DRIVER_ALTITUDE);
	if (bRet == FALSE)
	{
		return;
	}
	//启动驱动调用这个函数
	bRet = StartDriver(DRIVER_NAME);
	if (bRet == FALSE)
	{
		return;
	}


    g_bToExitThread = FALSE;

	m_lpContext = new SANDBOX_THREAD_CONTEXT;
	if (m_lpContext == NULL)
	{
		return;
	}

	hr = FilterConnectCommunicationPort( SandboxPortName,
		0,
		NULL,
		0,
		NULL,
		&port );

	if (IS_ERROR( hr )) 
	{

		return ;
	}

	//
	//  Create a completion port to associate with this handle.
	//

	completion = CreateIoCompletionPort( port,
		NULL,
		0,
		1);

	if (completion == NULL) 
	{

		CloseHandle( port );
		return;
	}

	m_lpContext->Port = port;
	m_lpContext->Completion = completion;


    g_hReadThread = AfxBeginThread((AFX_THREADPROC)SandboxThread, (LPVOID)m_lpContext);

	g_hReadThread->SuspendThread();
	g_hReadThread->m_bAutoDelete = FALSE;
	g_hReadThread->ResumeThread();
    

    if (g_hReadThread == NULL)
    {

        return;
    }
	GetDlgItem(IDC_BUTTON_START)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_STOP)->EnableWindow(TRUE);
}

void CInstallDrvDlg::OnButtonStop() 
{
	
    g_bToExitThread = TRUE;
	ULONG_PTR upData = (ULONG_PTR) -1;
	if (m_lpContext == NULL)
	{
		return;
	}
	PostQueuedCompletionStatus(m_lpContext->Completion, 0, (DWORD)&upData, NULL);

    {
		
        if (g_hReadThread != NULL)
        {
            if (WaitForSingleObject(g_hReadThread->m_hThread, 3000) == WAIT_TIMEOUT)
            {
                TerminateThread(g_hReadThread->m_hThread, 0);
            }
			delete g_hReadThread;
            g_hReadThread = NULL;
        }
    }
	delete m_lpContext;
	m_lpContext = NULL;

	// 	//停止驱动调用这个
	StopDriver(DRIVER_NAME);
	// 	//删除服务调用这个
	DeleteDriver(DRIVER_NAME);

	GetDlgItem(IDC_BUTTON_START)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_STOP)->EnableWindow(FALSE);
    return;
}
