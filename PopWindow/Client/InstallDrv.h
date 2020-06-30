// InstallDrv.h : main header file for the INSTALLDRV application
//

#if !defined(AFX_INSTALLDRV_H__BADC9736_6B3D_44BE_B851_D137B8EBB9C5__INCLUDED_)
#define AFX_INSTALLDRV_H__BADC9736_6B3D_44BE_B851_D137B8EBB9C5__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CInstallDrvApp:
// See InstallDrv.cpp for the implementation of this class
//

class CInstallDrvApp : public CWinApp
{
public:
	CInstallDrvApp();

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CInstallDrvApp)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

// Implementation

	//{{AFX_MSG(CInstallDrvApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_INSTALLDRV_H__BADC9736_6B3D_44BE_B851_D137B8EBB9C5__INCLUDED_)
