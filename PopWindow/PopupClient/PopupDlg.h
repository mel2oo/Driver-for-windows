#if !defined(AFX_POPUPDLG_H__593CBEF1_D2D5_4567_A4D1_5F02E6D8DE58__INCLUDED_)
#define AFX_POPUPDLG_H__593CBEF1_D2D5_4567_A4D1_5F02E6D8DE58__INCLUDED_

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
	VOID SetProcess(LPCTSTR lpszProcess);
	VOID SetDetail(LPCTSTR lpszDetail);
	VOID SetMyTimer(UINT lefttime);
	CPopupDlg(CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CPopupDlg)
	enum { IDD = IDD_DIALOG_POP };
	CString	m_edtDetail;
	int		m_bAllow;
	CString	m_szProcess;
	CString	m_szTime;
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
	virtual void OnOK();
	afx_msg void OnTimer(UINT nIDEvent);
	virtual BOOL OnInitDialog();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
protected:
	int m_lefttime;
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_POPUPDLG_H__593CBEF1_D2D5_4567_A4D1_5F02E6D8DE58__INCLUDED_)
