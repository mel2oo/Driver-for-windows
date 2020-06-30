// MinifilterInstall.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <winioctl.h>
#include <winsvc.h>
#include <stdio.h>
#include <conio.h>

//#include <fltuser.h>
//#include <dontuse.h>


#define DRIVER_NAME "nullfilter"
#define DRIVER_PATH ".\\nullfilter.sys"
#define DRIVER_ALTITUDE	 "370020" //有同学反馈，他这里没有使用UNICODE编码，导致安装不生效

// SYS文件跟程序放在同个目录下
// InstallDriver(DRIVER_NAME,DRIVER_PATH,DRIVER_ALTITUDE);
// 启动驱动服务 StartDriver(DRIVER_NAME);
// 停止驱动服务 StopDriver(DRIVER_NAME);
// 卸载服务 DeleteDriver(DRIVER_NAME);

BOOL InstallDriver(const char* lpszDriverName,const char* lpszDriverPath,const char* lpszAltitude)
{
    char    szTempStr[MAX_PATH];
    HKEY    hKey;
    DWORD    dwData;
    char    szDriverImagePath[MAX_PATH];    

    if( NULL==lpszDriverName || NULL==lpszDriverPath )
    {
        return FALSE;
    }
    //得到完整的驱动路径
    GetFullPathName(lpszDriverPath, MAX_PATH, szDriverImagePath, NULL);

    SC_HANDLE hServiceMgr=NULL;// SCM管理器的句柄
    SC_HANDLE hService=NULL;// NT驱动程序的服务句柄

    //打开服务控制管理器
    hServiceMgr = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
    if( hServiceMgr == NULL ) 
    {
        // OpenSCManager失败
        CloseServiceHandle(hServiceMgr);
        return FALSE;        
    }

    // OpenSCManager成功  

    //创建驱动所对应的服务
    hService = CreateService( hServiceMgr,
        lpszDriverName,             // 驱动程序的在注册表中的名字
        lpszDriverName,             // 注册表驱动程序的DisplayName 值
        SERVICE_ALL_ACCESS,         // 加载驱动程序的访问权限
        SERVICE_FILE_SYSTEM_DRIVER, // 表示加载的服务是文件系统驱动程序
        SERVICE_DEMAND_START,       // 注册表驱动程序的Start 值
        SERVICE_ERROR_IGNORE,       // 注册表驱动程序的ErrorControl 值
        szDriverImagePath,          // 注册表驱动程序的ImagePath 值
        "FSFilter Activity Monitor",// 注册表驱动程序的Group 值
        NULL, 
        "FltMgr",                   // 注册表驱动程序的DependOnService 值
        NULL, 
        NULL);

    if( hService == NULL ) 
    {        
        if( GetLastError() == ERROR_SERVICE_EXISTS ) 
        {
            //服务创建失败，是由于服务已经创立过
            CloseServiceHandle(hService);       // 服务句柄
            CloseServiceHandle(hServiceMgr);    // SCM句柄
            return TRUE; 
        }
        else 
        {
            CloseServiceHandle(hService);       // 服务句柄
            CloseServiceHandle(hServiceMgr);    // SCM句柄
            return FALSE;
        }
    }
    CloseServiceHandle(hService);       // 服务句柄
    CloseServiceHandle(hServiceMgr);    // SCM句柄

    //-------------------------------------------------------------------------------------------------------
    // SYSTEM\\CurrentControlSet\\Services\\DriverName\\Instances子健下的键值项 
    //-------------------------------------------------------------------------------------------------------
    strcpy(szTempStr,"SYSTEM\\CurrentControlSet\\Services\\");
    strcat(szTempStr,lpszDriverName);
    strcat(szTempStr,"\\Instances");
    if(RegCreateKeyEx(HKEY_LOCAL_MACHINE,szTempStr,0,"",REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,NULL,&hKey,(LPDWORD)&dwData)!=ERROR_SUCCESS)
    {
        return FALSE;
    }
    // 注册表驱动程序的DefaultInstance 值 
    strcpy(szTempStr,lpszDriverName);
    strcat(szTempStr," Instance");
    if(RegSetValueEx(hKey,"DefaultInstance",0,REG_SZ,(CONST BYTE*)szTempStr,(DWORD)strlen(szTempStr))!=ERROR_SUCCESS)
    {
        return FALSE;
    }
    RegFlushKey(hKey);//刷新注册表
    RegCloseKey(hKey);
 

    //-------------------------------------------------------------------------------------------------------
    // SYSTEM\\CurrentControlSet\\Services\\DriverName\\Instances\\DriverName Instance子健下的键值项 
    //-------------------------------------------------------------------------------------------------------
    strcpy(szTempStr,"SYSTEM\\CurrentControlSet\\Services\\");
    strcat(szTempStr,lpszDriverName);
    strcat(szTempStr,"\\Instances\\");
    strcat(szTempStr,lpszDriverName);
    strcat(szTempStr," Instance");
    if(RegCreateKeyEx(HKEY_LOCAL_MACHINE,szTempStr,0,"",REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,NULL,&hKey,(LPDWORD)&dwData)!=ERROR_SUCCESS)
    {
        return FALSE;
    }
    // 注册表驱动程序的Altitude 值
    strcpy(szTempStr,lpszAltitude);
    if(RegSetValueEx(hKey,"Altitude",0,REG_SZ,(CONST BYTE*)szTempStr,(DWORD)strlen(szTempStr))!=ERROR_SUCCESS)
    {
        return FALSE;
    }
    // 注册表驱动程序的Flags 值
    dwData=0x0;
    if(RegSetValueEx(hKey,"Flags",0,REG_DWORD,(CONST BYTE*)&dwData,sizeof(DWORD))!=ERROR_SUCCESS)
    {
        return FALSE;
    }
    RegFlushKey(hKey);//刷新注册表
    RegCloseKey(hKey);

    return TRUE;
}

BOOL StartDriver(const char* lpszDriverName)
{
    SC_HANDLE        schManager;
    SC_HANDLE        schService;

    if(NULL==lpszDriverName)
    {
        return FALSE;
    }

    schManager=OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if(NULL==schManager)
    {
        CloseServiceHandle(schManager);
        return FALSE;
    }
    schService=OpenService(schManager,lpszDriverName,SERVICE_ALL_ACCESS);
    if(NULL==schService)
    {
        CloseServiceHandle(schService);
        CloseServiceHandle(schManager);
        return FALSE;
    }

    if(!StartService(schService,0,NULL))
    {
        CloseServiceHandle(schService);
        CloseServiceHandle(schManager);
        if( GetLastError() == ERROR_SERVICE_ALREADY_RUNNING ) 
        {             
            // 服务已经开启
            return TRUE;
        } 
        return FALSE;
    }
    
    CloseServiceHandle(schService);
    CloseServiceHandle(schManager);

    return TRUE;
}

BOOL StopDriver(const char* lpszDriverName)
{
    SC_HANDLE        schManager;
    SC_HANDLE        schService;
    SERVICE_STATUS    svcStatus;
    bool            bStopped=false;

    schManager=OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if(NULL==schManager)
    {
        return FALSE;
    }
    schService=OpenService(schManager,lpszDriverName,SERVICE_ALL_ACCESS);
    if(NULL==schService)
    {
        CloseServiceHandle(schManager);
        return FALSE;
    }    
    if(!ControlService(schService,SERVICE_CONTROL_STOP,&svcStatus) && (svcStatus.dwCurrentState!=SERVICE_STOPPED))
    {
        CloseServiceHandle(schService);
        CloseServiceHandle(schManager);
        return FALSE;
    }
    
    CloseServiceHandle(schService);
    CloseServiceHandle(schManager);

    return TRUE;
}

BOOL DeleteDriver(const char* lpszDriverName)
{
    SC_HANDLE        schManager;
    SC_HANDLE        schService;
    SERVICE_STATUS    svcStatus;

    schManager=OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if(NULL==schManager)
    {
        return FALSE;
    }
    schService=OpenService(schManager,lpszDriverName,SERVICE_ALL_ACCESS);
    if(NULL==schService)
    {
        CloseServiceHandle(schManager);
        return FALSE;
    }
    ControlService(schService,SERVICE_CONTROL_STOP,&svcStatus);
    if(!DeleteService(schService))
    {
        CloseServiceHandle(schService);
        CloseServiceHandle(schManager);
        return FALSE;
    }
    CloseServiceHandle(schService);
    CloseServiceHandle(schManager);

    return TRUE;
}

int main(int argc, char* argv[])
{
	printf("Print any key to install driver\n");
	getch();
	DeleteDriver(DRIVER_NAME);
	//安装驱动调用这个函数
	BOOL bRet = InstallDriver(DRIVER_NAME, DRIVER_PATH, DRIVER_ALTITUDE);
	if (bRet == FALSE)
	{
		printf("Driver install failed\n");
		return -1;
	}
	printf("Print any key to start driver\n");
	getch();
	//启动驱动调用这个函数
	bRet = StartDriver(DRIVER_NAME);
	if (bRet == FALSE)
	{
		printf("StartDriver failed\n");
		return -1;
	}
	printf("Print any key to stop driver\n");
	getch();
	//停止驱动调用这个
	StopDriver(DRIVER_NAME);
	//删除服务调用这个
	DeleteDriver(DRIVER_NAME);

	
	return 0;
}
