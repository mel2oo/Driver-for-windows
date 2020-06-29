#include "precomp.h"
#include "SFLock.h"

VOID __stdcall LockWrite(ERESOURCE *lpLock)
{
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(lpLock, TRUE);
}


VOID __stdcall UnLockWrite(ERESOURCE *lpLock)
{
    ExReleaseResourceLite(lpLock);
    KeLeaveCriticalRegion();
}


VOID __stdcall LockRead(ERESOURCE *lpLock)
{
    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(lpLock, TRUE);
}


VOID __stdcall LockReadStarveWriter(ERESOURCE *lpLock)
{
    KeEnterCriticalRegion();
    ExAcquireSharedStarveExclusive(lpLock, TRUE);
}


VOID __stdcall UnLockRead(ERESOURCE *lpLock)
{
    ExReleaseResourceLite(lpLock);
    KeLeaveCriticalRegion();
}


VOID __stdcall InitLock(ERESOURCE *lpLock)
{
    ExInitializeResourceLite(lpLock);
}

VOID __stdcall InitList(LIST_ENTRY *list)
{
    InitializeListHead(list);
}
