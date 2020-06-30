// PopupDlg.cpp : implementation file
//

#include "stdafx.h"
#include "installdrv.h"
#include "PopupDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CPopupDlg dialog


CPopupDlg::CPopupDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CPopupDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CPopupDlg)
	m_nRadio = 0;
	m_szDetail = _T("");
	m_szAction = _T("");
	m_szFile = _T("");
	m_szLeftTime = _T("ªπ £: 30 √Î");
	m_szProcess = _T("");
	//}}AFX_DATA_INIT
	m_lefttime = 30;
}


void CPopupDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CPopupDlg)
	DDX_Radio(pDX, IDC_RADIO_ALLOW, m_nRadio);
	DDX_Text(pDX, IDC_EDIT_DETAIL, m_szDetail);
	DDX_Text(pDX, IDC_STATIC_ACTION, m_szAction);
	DDX_Text(pDX, IDC_STATIC_FILE, m_szFile);
	DDX_Text(pDX, IDC_STATIC_LEFTTIME, m_szLeftTime);
	DDX_Text(pDX, IDC_STATIC_PROCESS, m_szProcess);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CPopupDlg, CDialog)
	//{{AFX_MSG_MAP(CPopupDlg)
	ON_BN_CLICKED(IDC_BUTTON_CONFIRM, OnButtonConfirm)
	ON_WM_TIMER()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CPopupDlg message handlers
#define TIMER_ELAPSE_ID	1000

void CPopupDlg::OnButtonConfirm() 
{
	KillTimer(TIMER_ELAPSE_ID);
	CDialog::OnOK();	
}



void CPopupDlg::OnTimer(UINT nIDEvent) 
{
	switch(nIDEvent)
	{
	case TIMER_ELAPSE_ID:
		UpdateData(TRUE);
		m_szLeftTime.Format(_T("ªπ £: %2d √Î"), --m_lefttime);
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
	HICON hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	SetIcon(hIcon, TRUE);
	SetIcon(hIcon, FALSE);
	
	SetTimer(TIMER_ELAPSE_ID, 1*1000, NULL);
	
	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}

void CPopupDlg::SetMyTimer(UINT lefttime)
{
	m_lefttime = lefttime;
	m_szLeftTime = _T("ªπ £: 30 √Î");
	SetTimer(TIMER_ELAPSE_ID, 1*1000, NULL);
}

VOID CPopupDlg::SetDetail(LPCTSTR szDetail)
{
	m_szDetail = szDetail;
}

VOID CPopupDlg::SetProcess(LPCTSTR szProcessName)
{
	m_szProcess = szProcessName;
}

VOID CPopupDlg::SetAction(LPCTSTR szAction)
{
	m_szAction = szAction;
}

VOID CPopupDlg::SetFileName(LPCTSTR szFileName)
{
	m_szFile = szFileName;
}
