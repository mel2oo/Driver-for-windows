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
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_INSTALLDRVDLG_H__60386D0D_0857_4A47_AA11_B8EF2B9D1D5A__INCLUDED_)
