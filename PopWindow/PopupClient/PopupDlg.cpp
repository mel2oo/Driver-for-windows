// PopupDlg.cpp : implementation file
//

#include "stdafx.h"
#include "popupclient.h"
#include "PopupDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CPopupDlg dialog
#define TIMER_ELAPSE_ID	1000

CPopupDlg::CPopupDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CPopupDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CPopupDlg)
	m_edtDetail = _T("");
	m_bAllow = 1;
	m_szProcess = _T("");
	m_szTime = _T("ªπ £: 30 √Î");
	//}}AFX_DATA_INIT
	m_lefttime = 30;
}


void CPopupDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CPopupDlg)
	DDX_Text(pDX, IDC_EDIT_DETAIL, m_edtDetail);
	DDX_Radio(pDX, IDC_RADIO_ALLOW, m_bAllow);
	DDX_Text(pDX, IDC_STATIC_PROCESS, m_szProcess);
	DDX_Text(pDX, IDC_STATIC_TIME, m_szTime);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CPopupDlg, CDialog)
	//{{AFX_MSG_MAP(CPopupDlg)
	ON_WM_TIMER()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CPopupDlg message handlers

void CPopupDlg::OnOK() 
{
	// TODO: Add extra validation here
	KillTimer(TIMER_ELAPSE_ID);
	
	CDialog::OnOK();
}

void CPopupDlg::OnTimer(UINT nIDEvent) 
{
	// TODO: Add your message handler code here and/or call default
	switch(nIDEvent)
	{
	case TIMER_ELAPSE_ID:
		UpdateData(TRUE);
		m_szTime.Format(_T("ªπ £: %2d √Î"), --m_lefttime);
		UpdateData(FALSE);
		if (m_lefttime == 0)
		{
			KillTimer(nIDEvent);
			UpdateData(TRUE);
			CDialog::OnOK();
		}
		break;
	default:
		break;
	}
	
	CDialog::OnTimer(nIDEvent);
}

BOOL CPopupDlg::OnInitDialog() 
{
	CDialog::OnInitDialog();
	
	// TODO: Add extra initialization here
	SetTimer(TIMER_ELAPSE_ID, 1*1000, NULL);
	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}

VOID CPopupDlg::SetMyTimer(UINT lefttime)
{
	m_lefttime = lefttime;
	m_szTime = _T("ªπ ££∫ 30 √Î");
	SetTimer(TIMER_ELAPSE_ID, 1*1000, NULL);
}

VOID CPopupDlg::SetDetail(LPCTSTR lpszDetail)
{
	m_edtDetail = lpszDetail;
}

VOID CPopupDlg::SetProcess(LPCTSTR lpszProcess)
{
	m_szProcess = lpszProcess;

}
