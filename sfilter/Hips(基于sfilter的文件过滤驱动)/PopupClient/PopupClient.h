// PopupClient.h : main header file for the POPUPCLIENT application
//

#if !defined(AFX_POPUPCLIENT_H__983A7073_36A9_4E9E_A46C_E1144091F242__INCLUDED_)
#define AFX_POPUPCLIENT_H__983A7073_36A9_4E9E_A46C_E1144091F242__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CPopupClientApp:
// See PopupClient.cpp for the implementation of this class
//

class CPopupClientApp : public CWinApp
{
public:
	CPopupClientApp();

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CPopupClientApp)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

// Implementation

	//{{AFX_MSG(CPopupClientApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_POPUPCLIENT_H__983A7073_36A9_4E9E_A46C_E1144091F242__INCLUDED_)
