#ifndef __IPC_H__
#define __IPC_H__

// 60 seconds
extern PFLT_PORT g_pServerPort;
extern PFLT_PORT g_pClientPort;


extern PEPROCESS g_pProcessObject;


VOID closeIPC( );

NTSTATUS initIPC( );
VOID freeIPC();

#endif /* __IPC_H__ */

