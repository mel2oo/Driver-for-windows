// PopupClient.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "PopupClient.h"
#include "PopupClientDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CPopupClientApp

BEGIN_MESSAGE_MAP(CPopupClientApp, CWinApp)
	//{{AFX_MSG_MAP(CPopupClientApp)
		// NOTE - the ClassWizard will add and remove mapping macros here.
		//    DO NOT EDIT what you see in these blocks of generated code!
	//}}AFX_MSG
	ON_COMMAND(ID_HELP, CWinApp::OnHelp)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CPopupClientApp construction

CPopupClientApp::CPopupClientApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}

/////////////////////////////////////////////////////////////////////////////
// The one and only CPopupClientApp object

CPopupClientApp theApp;

/////////////////////////////////////////////////////////////////////////////
// CPopupClientApp initialization

BOOL CPopupClientApp::InitInstance()
{
	AfxEnableControlContainer();

	m_hSem = CreateSemaphore(NULL, 1, 1, AfxGetApp()->m_pszAppName); //theAppName
	// 信号量已存在？ 
	// 信号量存在，则程序已有一个实例运行 
	if (GetLastError() == ERROR_ALREADY_EXISTS) 
	{ 
		// 关闭信号量句柄 
		CloseHandle(m_hSem); 
		m_hSem = NULL;
		//MessageBox(NULL, L"程序已经运行", L"Error", MB_OK);
		HWND hWnd = ::FindWindow(NULL, _T("PopupClient"));
			if (hWnd)
			{
				::SetForegroundWindow(hWnd); 
				::ShowWindow(hWnd, SW_SHOW);
			}
			// 前一实例已存在，但找不到其主窗 
			// 可能出错了 
			// 退出本实例 
			return FALSE; 
	}


	// Standard initialization
	// If you are not using these features and wish to reduce the size
	//  of your final executable, you should remove from the following
	//  the specific initialization routines you do not need.

#ifdef _AFXDLL
	Enable3dControls();			// Call this when using MFC in a shared DLL
#else
	Enable3dControlsStatic();	// Call this when linking to MFC statically
#endif

	CPopupClientDlg dlg;
	m_pMainWnd = &dlg;
	int nResponse = dlg.DoModal();
	if (nResponse == IDOK)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with OK
	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with Cancel
	}

	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.
	return FALSE;
}

int CPopupClientApp::ExitInstance() 
{
	// TODO: Add your specialized code here and/or call the base class
	if (m_hSem)
	{
		CloseHandle(m_hSem);
	}

	return CWinApp::ExitInstance();
}
