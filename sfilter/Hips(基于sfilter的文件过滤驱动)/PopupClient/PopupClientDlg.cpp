// PopupClientDlg.cpp : implementation file
//

#include "stdafx.h"
#include "PopupClient.h"
#include "PopupClientDlg.h"

#include "ioctlcmd.h"
#include <shlwapi.h>
#include "PopupDlg.h"

#pragma comment(lib, "shlwapi.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define DRIVER_NAME _T("hipsdrv")
#define DRIVER_PATH _T(".\\hipsdrv.sys")

HANDLE gh_Device = INVALID_HANDLE_VALUE;

CWinThread	*g_hReadThread = NULL;
BOOL	g_bToExitThread = FALSE;
HANDLE	g_hOverlappedEvent = NULL;

BOOL LoadDriver(TCHAR* lpszDriverName,TCHAR* lpszDriverPath)
{
	TCHAR szDriverImagePath[1024] = {0}/*_T("D:\\Popup\\PopupDrv.sys")*/;
	//得到完整的驱动路径
	GetFullPathName(lpszDriverPath, 1024, szDriverImagePath, NULL);

	BOOL bRet = FALSE;

	SC_HANDLE hServiceMgr=NULL;//SCM管理器的句柄
	SC_HANDLE hServiceDDK=NULL;//NT驱动程序的服务句柄

	//打开服务控制管理器
	hServiceMgr = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );

	if( hServiceMgr == NULL )  
	{
		//OpenSCManager失败
		//printf( "OpenSCManager() Failed %d ! \n", GetLastError() );
		bRet = FALSE;
		goto BeforeLeave;
	}
	else
	{
		////OpenSCManager成功
		printf( "OpenSCManager() ok ! \n" );  
	}

	//创建驱动所对应的服务
	hServiceDDK = CreateService( hServiceMgr,
		lpszDriverName, //驱动程序的在注册表中的名字  
		lpszDriverName, // 注册表驱动程序的 DisplayName 值  
		SERVICE_ALL_ACCESS, // 加载驱动程序的访问权限  
		SERVICE_KERNEL_DRIVER,// 表示加载的服务是驱动程序  
		SERVICE_DEMAND_START, // 注册表驱动程序的 Start 值  
		SERVICE_ERROR_IGNORE, // 注册表驱动程序的 ErrorControl 值  
		szDriverImagePath, // 注册表驱动程序的 ImagePath 值  
		_T("FSFilter Activity Monitor"),  //GroupOrder HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GroupOrderList
		NULL,  
		NULL,  
		NULL,  
		NULL);  

	DWORD dwRtn;
	//判断服务是否失败
	if( hServiceDDK == NULL )  
	{  
		dwRtn = GetLastError();
		if( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS )  
		{  
			//由于其他原因创建服务失败
			//printf( "CrateService() Failed %d ! \n", dwRtn );  
			bRet = FALSE;
			goto BeforeLeave;
		}  
		else  
		{
			//服务创建失败，是由于服务已经创立过
			printf( "CrateService() Faild Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS! \n" );  
		}

		// 驱动程序已经加载，只需要打开  
		hServiceDDK = OpenService( hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS );  
		if( hServiceDDK == NULL )  
		{
			//如果打开服务也失败，则意味错误
			dwRtn = GetLastError();  
			//printf( "OpenService() Failed %d ! \n", dwRtn );  
			bRet = FALSE;
			goto BeforeLeave;
		}  
		else 
		{
			//printf( "OpenService() ok ! \n" );
		}
	}  
	else  
	{
		//printf( "CrateService() ok ! \n" );
	}

	//开启此项服务
	bRet= StartService( hServiceDDK, NULL, NULL );  
	if( !bRet )  
	{  
		DWORD dwRtn = GetLastError();  
		if( dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING )  
		{  
			//printf( "StartService() Failed %d ! \n", dwRtn );  
			bRet = FALSE;
			goto BeforeLeave;
		}  
		else  
		{  
			if( dwRtn == ERROR_IO_PENDING )  
			{  
				//设备被挂住
				//printf( "StartService() Failed ERROR_IO_PENDING ! \n");
				bRet = FALSE;
				goto BeforeLeave;
			}  
			else  
			{  
				//服务已经开启
				//printf( "StartService() Failed ERROR_SERVICE_ALREADY_RUNNING ! \n");
				bRet = TRUE;
				goto BeforeLeave;
			}  
		}  
	}
	bRet = TRUE;
//离开前关闭句柄
BeforeLeave:
	if(hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if(hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return bRet;
}

//卸载驱动程序  
BOOL UnloadDriver( TCHAR * szSvrName )  
{
	BOOL bRet = FALSE;
	SC_HANDLE hServiceMgr=NULL;//SCM管理器的句柄
	SC_HANDLE hServiceDDK=NULL;//NT驱动程序的服务句柄
	SERVICE_STATUS SvrSta;
	//打开SCM管理器
	hServiceMgr = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );  
	if( hServiceMgr == NULL )  
	{
		//带开SCM管理器失败
		printf( "OpenSCManager() Failed %d ! \n", GetLastError() );  
		bRet = FALSE;
		goto BeforeLeave;
	}  
	else  
	{
		//带开SCM管理器失败成功
		printf( "OpenSCManager() ok ! \n" );  
	}
	//打开驱动所对应的服务
	hServiceDDK = OpenService( hServiceMgr, szSvrName, SERVICE_ALL_ACCESS );  

	if( hServiceDDK == NULL )  
	{
		//打开驱动所对应的服务失败
		printf( "OpenService() Failed %d ! \n", GetLastError() );  
		bRet = FALSE;
		goto BeforeLeave;
	}  
	else  
	{  
		printf( "OpenService() ok ! \n" );  
	}  
	//停止驱动程序，如果停止失败，只有重新启动才能，再动态加载。  
	if( !ControlService( hServiceDDK, SERVICE_CONTROL_STOP , &SvrSta ) )  
	{  
		printf( "ControlService() Failed %d !\n", GetLastError() );  
	}  
	else  
	{
		//打开驱动所对应的失败
		printf( "ControlService() ok !\n" );  
	}  
	//动态卸载驱动程序。  
	if( !DeleteService( hServiceDDK ) )  
	{
		//卸载失败
		printf( "DeleteSrevice() Failed %d !\n", GetLastError() );  
	}  
	else  
	{  
		//卸载成功
		printf( "DelServer:eleteSrevice() ok !\n" );  
	}  
	bRet = TRUE;
BeforeLeave:
//离开前关闭打开的句柄
	if(hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if(hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return bRet;	
} 

HANDLE OpenDevice()
{
	//测试驱动程序  
	HANDLE hDevice = CreateFile(_T("\\\\.\\hipsdrv"),  
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

typedef struct _R3_REPLY
{
    ULONG	m_ulWaitID;
    ULONG	m_ulBlocked;
}R3_REPLY;

#define		OPERTYPELEN		64

typedef struct _OP_INFO
{
    WCHAR     m_ProcessName[MAX_PATH];
	
    ULONG     m_ulWaitID;
	
	WCHAR	  m_szOper[OPERTYPELEN];
	
    WCHAR     m_TargetName[MAX_PATH];
    WCHAR     m_TargetNameEx[MAX_PATH];

} OP_INFO, *POP_INFO;


VOID  SendResultToR0(ULONG ulWaitID, BOOL bBlocked)
{
    if (gh_Device == INVALID_HANDLE_VALUE)
    {
        return ;
    }
	
    R3_REPLY R3Reply;
    R3Reply.m_ulWaitID = ulWaitID;
    R3Reply.m_ulBlocked = bBlocked;
	
    ULONG ulRet = 0;
    ::DeviceIoControl(gh_Device, IOCTL_SEND_RESULT_TO_R0, &R3Reply, sizeof(R3_REPLY), NULL, 0, &ulRet, NULL);
    
    return ;
}
BOOL  HandleData(OP_INFO *pOpInfoData)
{

	CPopupDlg dlg;

	dlg.SetProcess(pOpInfoData->m_ProcessName);
	dlg.SetTarget(pOpInfoData->m_TargetName);
	CString szDetail;
	szDetail.Format(_T("有进程:%s\r\n正在:%s\r\n目标:%s"), 
		pOpInfoData->m_ProcessName, 
		pOpInfoData->m_szOper,
		pOpInfoData->m_TargetName);

	dlg.SetDetail(szDetail);

	dlg.DoModal();

	if (dlg.m_bAllow == 0)
	{
		return FALSE;
	}

	return TRUE;
}

void  PopupInfoToUser(OP_INFO *pOpInfo, int Num)
{
	OP_INFO * currData = pOpInfo;
	CString szNum;

	for(int i = 0; i < Num; i++)
	{
		BOOL bResult = HandleData(currData);  // 此处可以弹框获得用户的结果
		if (bResult)
		{
			SendResultToR0(pOpInfo->m_ulWaitID, TRUE);
		}
		else
		{
			SendResultToR0(pOpInfo->m_ulWaitID, FALSE);
		}
		currData++;
	}
}

UINT ReadThreadProc(LPVOID lpContext)
{
    OVERLAPPED Overlapped;

    
    g_hOverlappedEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    
    if (g_hOverlappedEvent == NULL || gh_Device == INVALID_HANDLE_VALUE)
    {
        return -1;
    }
    
    memset(&Overlapped, 0, sizeof(OVERLAPPED));
    
    ULONG ulReturn = 0;
    ULONG ulBytesReturn = 0;
    
    OP_INFO OpInfo;
    Overlapped.hEvent = g_hOverlappedEvent;
	
    ::SleepEx(1, TRUE);
    
    while (TRUE)
    {
        ulReturn = ReadFile(gh_Device, &OpInfo, sizeof(OP_INFO), &ulBytesReturn, &Overlapped);
        
        if (g_bToExitThread == TRUE)
        {
            break;
        }
        
        if (ulReturn == 0)
        {
            if (GetLastError() == ERROR_IO_PENDING)
            {
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
		if (ulBytesReturn == sizeof(OP_INFO))
		{
			PopupInfoToUser(&OpInfo, 1);
		}

    }
    
    return 0;
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
// CPopupClientDlg dialog

CPopupClientDlg::CPopupClientDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CPopupClientDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CPopupClientDlg)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CPopupClientDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CPopupClientDlg)
		// NOTE: the ClassWizard will add DDX and DDV calls here
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CPopupClientDlg, CDialog)
	//{{AFX_MSG_MAP(CPopupClientDlg)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_STOP, OnButtonStop)
	ON_WM_CLOSE()
	ON_COMMAND(ID_MENU_EXIT, OnMenuExit)
	ON_COMMAND(ID_MENU_RESTORE, OnMenuRestore)
	ON_WM_DESTROY()
	//}}AFX_MSG_MAP
	ON_MESSAGE(WM_ICON_NOTIFY, OnTrayNotification)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CPopupClientDlg message handlers

BOOL CPopupClientDlg::OnInitDialog()
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
	
	// TODO: Add extra initialization here

	NOTIFYICONDATA m_tnid;
	
	m_tnid.cbSize=sizeof(NOTIFYICONDATA);//设置结构大小// 
	m_tnid.hWnd=this->m_hWnd;//设置图标对应的窗口 
	m_tnid.uFlags=NIF_MESSAGE|NIF_ICON|NIF_TIP;//图标属性 
	m_tnid.uCallbackMessage=WM_ICON_NOTIFY;//应用程序定义的回调消息ID
	
	CString szToolTip; 
	szToolTip=_T("HIPS -- 客户端程序"); 
	_tcscpy(m_tnid.szTip, szToolTip);//帮助信息 
	m_tnid.uID=IDR_MAINFRAME;//应用程序图标  
	m_tnid.hIcon=m_hIcon;//图标句柄 
	PNOTIFYICONDATA m_ptnid=&m_tnid; 
	::Shell_NotifyIcon(NIM_ADD,m_ptnid);//增加图标到系统盘
	
	GetDlgItem(IDOK)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_STOP)->EnableWindow(FALSE);
	
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CPopupClientDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

	if(nID == SC_MINIMIZE)
	{
		ShowWindow(FALSE); //隐藏窗口
	}

}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CPopupClientDlg::OnPaint() 
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
HCURSOR CPopupClientDlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}

void CPopupClientDlg::OnButtonStop() 
{
	// TODO: Add your control notification handler code here
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
        gh_Device = INVALID_HANDLE_VALUE;
    }
	//UnloadDriver(DRIVER_NAME);
	
	GetDlgItem(IDOK)->EnableWindow(TRUE);
	GetDlgItem(IDC_BUTTON_STOP)->EnableWindow(FALSE);
	
}

void CPopupClientDlg::OnOK() 
{
	// TODO: Add extra validation here

	DWORD dwThreadID = 0;
    g_bToExitThread = FALSE;
	//加载驱动
	BOOL bRet = LoadDriver(DRIVER_NAME,DRIVER_PATH);
	if (!bRet)
	{
		MessageBox(_T("加载驱动失败"), _T("Error"), MB_OK);
		return;
	}
		
	
	gh_Device = OpenDevice();
	if (gh_Device == NULL)
	{
		MessageBox(_T("打开设备失败"), _T("Error"), MB_OK);
		return;
	}
	
    g_hReadThread = AfxBeginThread(ReadThreadProc, this);
	
	g_hReadThread->SuspendThread();
	g_hReadThread->m_bAutoDelete = FALSE;
	g_hReadThread->ResumeThread();
    
	
    if (g_hReadThread == NULL)
    {
        CloseHandle(gh_Device);
        gh_Device = INVALID_HANDLE_VALUE;
		UnloadDriver(DRIVER_NAME);
        return;
    }
	GetDlgItem(IDOK)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_STOP)->EnableWindow(TRUE);
}

LRESULT CPopupClientDlg::OnTrayNotification(WPARAM wParam, LPARAM lParam)
{
	switch(lParam) 
	{
	case WM_LBUTTONDOWN:
		{
			AfxGetApp()->m_pMainWnd->ShowWindow(SW_SHOWNORMAL);
			SetForegroundWindow();
			break;	
		}
	case WM_RBUTTONUP:
		{
			POINT point;
			HMENU hMenu, hSubMenu;
			GetCursorPos(&point); //鼠标位置
			hMenu = LoadMenu(NULL, 
				MAKEINTRESOURCE(IDR_MENU_TRAY)); // 加载菜单
			hSubMenu = GetSubMenu(hMenu, 0);//得到子菜单(因为弹出式菜单是子菜单)
			SetMenuDefaultItem(hSubMenu, -1, FALSE);//设置缺省菜单项,-1为无缺省项
			SetForegroundWindow(); // 激活窗口并置前
			
			TrackPopupMenu(hSubMenu, 0, 
				point.x, point.y, 0, m_hWnd, NULL);
			
		}
	}
	return 1;
}


void CPopupClientDlg::OnClose() 
{

	NOTIFYICONDATA   nd = {0};

	nd.cbSize				=   sizeof(NOTIFYICONDATA); 
	nd.hWnd					=   m_hWnd; 
	nd.uID					=   IDR_MAINFRAME; 
	nd.uFlags				=   NIF_ICON|NIF_MESSAGE|NIF_TIP; 
	nd.uCallbackMessage		=   WM_ICON_NOTIFY; 
	nd.hIcon				=   m_hIcon; 

	Shell_NotifyIcon(NIM_DELETE,   &nd); 

	CDialog::OnCancel();
}

void CPopupClientDlg::OnMenuExit() 
{
	OnClose();
	
}

void CPopupClientDlg::OnMenuRestore() 
{
	ShowWindow(SW_SHOWNORMAL);
	SetForegroundWindow();
	
}

void CPopupClientDlg::OnDestroy() 
{
	CDialog::OnDestroy();
	
}
