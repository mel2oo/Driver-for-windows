#ifndef _Hash_H
#define _Hash_H

#include "namelookup.h"

typedef unsigned char BYTE;
typedef unsigned long DWORD;
typedef unsigned short WORD;


#define DRIVERTAG1 'HSAH'
#define MAX_PATH	260


typedef struct _HashData
{
    PNAME_CONTROL lpNameControl;
} HASHDATA, *PHASHDATA;

typedef struct _ELEMENT
{
    PNAME_CONTROL lpNameControl;

} ELEMENT, *PELEMENT;

typedef struct _TWOWAY
{
	DWORD key;
	ELEMENT data;
	LIST_ENTRY linkfield;
} TWOWAY, *PTWOWAY;

typedef struct _HASHTABLE
{
	ULONG tableSize;
	PLIST_ENTRY *pListHeads;
} HASHTABLE, *PHASHTABLE;

typedef struct _HASHTABLE HASHTABLE, *PHASHTABLE;

//声明函数的时候，不要忘记带;，否则会有很怪异的编译错误。切记
PHASHTABLE InitializeTable(unsigned int tableSize);
PTWOWAY Find(DWORD key, PHASHTABLE pHashTable); 
void Insert(DWORD key, PHASHDATA pData, PHASHTABLE pHashTable);
void Remove(DWORD key, PHASHTABLE pHashTable);
void DestroyTable(PHASHTABLE pHashTable);
ULONG DumpTable(PHASHTABLE pHashTable);

#endif // _Hash_H
