# Driver

# Build vs2017+WDK1809

# 2020.6  0x07 Backup Driver Frame

# 2019.3.29    0x06 RegisterMonitor

# 2019.3.29    0x05 MonitorProcessAndImage

  Use PsSetCreateProcessNotifyRoutineEx	\ PsSetLoadImageNotifyRoutine 

		to monitor Process Create or destruction.

# 2019.3.25    0x04 MiniVTx86 \ MiniVTx64 \ MiniVT_Multicore

  MiniVT on windows XP、windows7 x86+x64.

             from https://bbs.pediy.com/thread-211973.htm

# 2019.3.21    0x03 HideDriver

  HideDriver by MiProcessLoaderEntry. support win7  win8  win10

             from  @zhuhuibeishadiao https://github.com/ZhuHuiBeiShaDiao/NewHideDriverEx

# 2019.3.20    0x02 KeyBoardFilter

  Catch your keyboard operation.

# 2019.3.19    0x01 CheckTime

  If you want to add a license to your driver,you can use LockTimeCheck set deadline and confirm whether it expires.
