// stdafx.h : include file for standard system include files,
//  or project specific include files that are used frequently, but
//      are changed infrequently
//

#if !defined(AFX_STDAFX_H__72C01CF0_9A71_44F1_A1A4_DF3458CE2160__INCLUDED_)
#define AFX_STDAFX_H__72C01CF0_9A71_44F1_A1A4_DF3458CE2160__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define VC_EXTRALEAN		// Exclude rarely-used stuff from Windows headers

#include <afxwin.h>         // MFC core and standard components
#include <afxext.h>         // MFC extensions
#include <afxdisp.h>        // MFC Automation classes
#include <afxdtctl.h>		// MFC support for Internet Explorer 4 Common Controls
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>			// MFC support for Windows Common Controls
#endif // _AFX_NO_AFXCMN_SUPPORT
#include <windows.h>

#include <shlwapi.h>

#include <winsvc.h>			//加载驱动的服务
#include <winioctl.h>		//IOCTRL API

#include <strsafe.h>		//shlwapi.h与strsafe.h需要在fltuser.h与dontuse.h之前，否则有编译问题

#include <fltuser.h>
#include <dontuse.h>

#include <assert.h>

#pragma warning(disable:4996)
#pragma warning(disable:4995)


//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__72C01CF0_9A71_44F1_A1A4_DF3458CE2160__INCLUDED_)
