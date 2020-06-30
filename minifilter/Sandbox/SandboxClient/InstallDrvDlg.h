// InstallDrvDlg.h : header file
//

#if !defined(AFX_INSTALLDRVDLG_H__60386D0D_0857_4A47_AA11_B8EF2B9D1D5A__INCLUDED_)
#define AFX_INSTALLDRVDLG_H__60386D0D_0857_4A47_AA11_B8EF2B9D1D5A__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "PopupDlg.h"

/////////////////////////////////////////////////////////////////////////////
// CInstallDrvDlg dialog
typedef struct _SANDBOX_THREAD_CONTEXT 
{

	HANDLE Port;
	HANDLE Completion;

} SANDBOX_THREAD_CONTEXT, *PSANDBOX_THREAD_CONTEXT;

class CInstallDrvDlg : public CDialog
{
// Construction
public:
	CInstallDrvDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	//{{AFX_DATA(CInstallDrvDlg)
	enum { IDD = IDD_INSTALLDRV_DIALOG };
		// NOTE: the ClassWizard will add data members here
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CInstallDrvDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL
public:
	CPopupDlg m_PopUpdlg;

// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	//{{AFX_MSG(CInstallDrvDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnButtonSnd();
	afx_msg void OnButtonStart();
	afx_msg void OnButtonStop();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
private:

	PSANDBOX_THREAD_CONTEXT	m_lpContext;
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.



const PWSTR SandboxPortName = L"\\SandboxPortGUI";

#define SANDBOX_READ_BUFFER_SIZE   1024

typedef struct _SANDBOX_NOTIFICATION 
{

	ULONG BytesToScan;
	ULONG Reserved;             // for quad-word alignement of the Contents structure
	UCHAR Contents[SANDBOX_READ_BUFFER_SIZE];

} SANDBOX_NOTIFICATION, *PSANDBOX_NOTIFICATION;

typedef struct _SANDBOX_REPLY 
{

	BOOLEAN SafeToOpen;

} SANDBOX_REPLY, *PSANDBOX_REPLY;


#pragma pack(1)

typedef struct _SANDBOX_MESSAGE 
{

	//
	//  Required structure header.
	//

	FILTER_MESSAGE_HEADER MessageHeader;


	//
	//  Private SANDBOX-specific fields begin here.
	//

	SANDBOX_NOTIFICATION Notification;

	//
	//  Overlapped structure: this is not really part of the message
	//  However we embed it instead of using a separately allocated overlap structure
	//

	OVERLAPPED Ovlp;

} SANDBOX_MESSAGE, *PSANDBOX_MESSAGE;

typedef struct _SANDBOX_REPLY_MESSAGE 
{

	//
	//  Required structure header.
	//

	FILTER_REPLY_HEADER ReplyHeader;

	//
	//  Private SANDBOX-specific fields begin here.
	//

	SANDBOX_REPLY Reply;

} SANDBOX_REPLY_MESSAGE, *PSANDBOX_REPLY_MESSAGE;



#endif // !defined(AFX_INSTALLDRVDLG_H__60386D0D_0857_4A47_AA11_B8EF2B9D1D5A__INCLUDED_)
