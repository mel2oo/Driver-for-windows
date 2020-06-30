#include "StdAfx.h"

BOOL LoadDeviceDriver( const TCHAR * Name, const TCHAR * Path, 
					  HANDLE * lphDevice, PDWORD Error );
BOOL UnloadDeviceDriver( const TCHAR * Name );