# Microsoft Developer Studio Project File - Name="vchelloworld" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

CFG=vchelloworld - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "vchelloworld.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "vchelloworld.mak" CFG="vchelloworld - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "vchelloworld - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "vchelloworld - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "vchelloworld - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x804 /d "NDEBUG"
# ADD RSC /l 0x804 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /machine:I386

!ELSEIF  "$(CFG)" == "vchelloworld - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /YX /FD /GZ /c
# ADD CPP /nologo /Gz /MT /W3 /Gm /Zi /Oi /Gy /I "C:\WinDDK\7600.16385.0\inc" /I "C:\WinDDK\7600.16385.0\inc\api" /I "C:\WinDDK\7600.16385.0\inc\ddk" /I "C:\WinDDK\7600.16385.0\inc\crt" /D _X86_=1 /D i386=1 /D "STD_CALL" /D CONDITION_HANDLING=1 /D NT_INST=0 /D WIN32=100 /D _NT1X_=100 /D WINNT=1 /D _WIN32_WINNT=0x0501 /D WINVER=0x0501 /D _WIN32_IE=0x0603 /D WIN32_LEAN_AND_MEAN=1 /D DEVL=1 /D DBG=1 /D __BUILDMACHINE__=WinDDK /D FPO=0 /D _DLL=1 /D "NDEBUG" /D "MSC_NOOPT" /D NTDDI_VERSION=0x05010200 /Zl /FD /D /Zc:wchar_t- -cbstring /hotpatch /EHs-c- /GF /GS /GS /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x804 /d "_DEBUG"
# ADD RSC /l 0x804 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /debug /machine:I386 /pdbtype:sept
# ADD LINK32 c:\winddk\7600.16385.0\lib\wxp\i386\BufferOverflowK.lib c:\winddk\7600.16385.0\lib\wxp\i386\ntoskrnl.lib c:\winddk\7600.16385.0\lib\wxp\i386\hal.lib c:\winddk\7600.16385.0\lib\wxp\i386\wmilib.lib c:\winddk\7600.16385.0\lib\wxp\i386\fltMgr.lib c:\winddk\7600.16385.0\lib\wxp\i386\ndis.lib c:\winddk\7600.16385.0\lib\wxp\i386\ntstrsafe.lib c:\winddk\7600.16385.0\lib\wxp\i386\sehupd.lib /base:"0x10000" /version:6.1 /stack:0x40000,0x1000 /entry:"DriverEntry" /incremental:no /debug /machine:IX86 /nodefaultlib /out:"Debug/sandbox.sys" /MERGE:_PAGE=PAGE /MERGE:_TEXT=.text /SECTION:INIT,d /OPT:REF /OPT:ICF /IGNORE:4198,4010,4037,4039,4065,4070,4078,4087,4089,4221 /WX /debugtype:cv,fixup,pdata /osversion:6.1 /functionpadmin:5 /safeseh /pdbcompress /driver /align:0x80 /subsystem:native,5.01
# SUBTRACT LINK32 /pdb:none

!ENDIF 

# Begin Target

# Name "vchelloworld - Win32 Release"
# Name "vchelloworld - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\IPC.c
# End Source File
# Begin Source File

SOURCE=.\main.c
# End Source File
# Begin Source File

SOURCE=.\MiniMon.c
# End Source File
# Begin Source File

SOURCE=.\sandbox.c
# End Source File
# Begin Source File

SOURCE=.\sbtoolApi.c
# End Source File
# Begin Source File

SOURCE=.\utilApi.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\ioctlcmd.h
# End Source File
# Begin Source File

SOURCE=.\IPC.h
# End Source File
# Begin Source File

SOURCE=.\main.h
# End Source File
# Begin Source File

SOURCE=.\MiniMon.h
# End Source File
# Begin Source File

SOURCE=.\pedef.h
# End Source File
# Begin Source File

SOURCE=.\precom.h
# End Source File
# Begin Source File

SOURCE=.\sandbox.h
# End Source File
# Begin Source File

SOURCE=.\sbtoolApi.h
# End Source File
# Begin Source File

SOURCE=.\utilApi.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
