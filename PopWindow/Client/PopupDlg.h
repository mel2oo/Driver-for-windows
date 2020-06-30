#if !defined(AFX_POPUPDLG_H__0DF3135B_1F9B_458E_B4B8_EA47D895BC75__INCLUDED_)
#define AFX_POPUPDLG_H__0DF3135B_1F9B_458E_B4B8_EA47D895BC75__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// PopupDlg.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CPopupDlg dialog

class CPopupDlg : public CDialog
{
// Construction
public:
	VOID SetFileName(LPCTSTR szFileName);
	VOID SetAction(LPCTSTR szAction);
	VOID SetProcess(LPCTSTR szProcessName);
	VOID SetDetail(LPCTSTR szDetail);
	void SetMyTimer(UINT lefttime=30);
	CPopupDlg(CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CPopupDlg)
	enum { IDD = IDD_POPUP_DIALOG };
	int		m_nRadio;
	CString	m_szDetail;
	CString	m_szAction;
	CString	m_szFile;
	CString	m_szLeftTime;
	CString	m_szProcess;
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CPopupDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(CPopupDlg)
	afx_msg void OnButtonConfirm();
	afx_msg void OnTimer(UINT nIDEvent);
	virtual BOOL OnInitDialog();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
protected:
	int m_lefttime;
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_POPUPDLG_H__0DF3135B_1F9B_458E_B4B8_EA47D895BC75__INCLUDED_)
