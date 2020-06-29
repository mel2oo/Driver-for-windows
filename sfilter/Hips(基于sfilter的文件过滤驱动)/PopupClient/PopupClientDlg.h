// PopupClientDlg.h : header file
//

#if !defined(AFX_POPUPCLIENTDLG_H__D011D1BA_9C1A_4397_B616_53A1283D82CA__INCLUDED_)
#define AFX_POPUPCLIENTDLG_H__D011D1BA_9C1A_4397_B616_53A1283D82CA__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define		WM_ICON_NOTIFY	WM_USER+100

/////////////////////////////////////////////////////////////////////////////
// CPopupClientDlg dialog

class CPopupClientDlg : public CDialog
{
// Construction
public:
	CPopupClientDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	//{{AFX_DATA(CPopupClientDlg)
	enum { IDD = IDD_POPUPCLIENT_DIALOG };
		// NOTE: the ClassWizard will add data members here
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CPopupClientDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	//{{AFX_MSG(CPopupClientDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnButtonStop();
	virtual void OnOK();
	afx_msg void OnClose();
	afx_msg void OnMenuExit();
	afx_msg void OnMenuRestore();
	afx_msg void OnDestroy();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
	LRESULT OnTrayNotification(WPARAM wParam, LPARAM lParam);
protected:
		NOTIFYICONDATA m_tnid;
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_POPUPCLIENTDLG_H__D011D1BA_9C1A_4397_B616_53A1283D82CA__INCLUDED_)
