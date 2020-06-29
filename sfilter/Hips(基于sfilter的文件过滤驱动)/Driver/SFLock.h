#ifndef _SFLOCK_H_
#define _SFLOCK_H_

VOID __stdcall LockWrite(ERESOURCE *lpLock);
VOID __stdcall UnLockWrite(ERESOURCE *lpLock);
VOID __stdcall LockRead(ERESOURCE *lpLock);

VOID __stdcall LockReadStarveWriter(ERESOURCE *lpLock);
VOID __stdcall UnLockRead(ERESOURCE *lpLock);
VOID __stdcall InitLock(ERESOURCE *lpLock);
VOID __stdcall InitList(LIST_ENTRY *list);

#endif