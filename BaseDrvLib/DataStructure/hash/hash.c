// Functions that implement the separate chaining hashtable algorithms.
// The skeletons for these algorithms was taken from the book
// "Data Structures and Algorithm Analysis in C, Second Edition" by
// Mark Allen Weiss.
//
// Kimmo

#include "ntddk.h"
#include "hash.h"

PNPAGED_LOOKASIDE_LIST pLookasideList_TWOWAY = NULL;

/* Return next prime; assume N >= 10 */
static unsigned int NextPrime(int N)
{
    int i = 0;

    if( N % 2 == 0 )
        N++;
    for( ; ; N += 2 )
    {
        for( i = 3; i * i <= N; i += 2 )
            if( N % i == 0 )
                goto ContOuter;  /* Sorry about this! */
        return N;
        ContOuter: ;
    }
}

unsigned int Hash(DWORD key, unsigned int tableSize)
{
	return key % tableSize;
}

PHASHTABLE InitializeTable(unsigned int tableSize)
{
	PHASHTABLE			pHashTable	= NULL;
	PTWOWAY				pNode		= NULL;
	ULONG				i			= 0;

	// Allocate space for the hashtable
	pHashTable = 
		ExAllocatePoolWithTag(NonPagedPool, sizeof(HASHTABLE), DRIVERTAG1);
	if (pHashTable == NULL)
	{
		DbgPrint("ExAllocatePoolWithTag returned NULL!\n");
		return NULL;
	}

	pHashTable->tableSize = NextPrime(tableSize);

	// Allocate array of pointers to linkedlists 
	pHashTable->pListHeads = 
		ExAllocatePoolWithTag(NonPagedPool, 
		sizeof(PLIST_ENTRY) * pHashTable->tableSize, DRIVERTAG1);
	if (pHashTable->pListHeads == NULL)
	{
		DbgPrint("ExAllocatePoolWithTag returned NULL!\n");
		return NULL;
	}

	// Allocate space for the lookaside list for the TWOWAY-structures.
	pLookasideList_TWOWAY = 
		ExAllocatePoolWithTag(NonPagedPool, sizeof(NPAGED_LOOKASIDE_LIST), DRIVERTAG1);
	if (pLookasideList_TWOWAY == NULL)
	{
		DbgPrint("ExAllocatePoolWithTag returned NULL!\n");
		return NULL;
	}

	// Initialize the lookaside list.
	ExInitializeNPagedLookasideList(
		pLookasideList_TWOWAY,
		NULL,
		NULL,
		0,
		sizeof(TWOWAY),
		DRIVERTAG1,
		0);

	// Allocate empty nodes for the each linked list.
	for (i = 0; i < pHashTable->tableSize; i++)
	{
		pNode = ExAllocateFromNPagedLookasideList(pLookasideList_TWOWAY);
		if (pNode == NULL)
		{
			DbgPrint("ExAllocateFromNPagedLookasideList returned NULL!\n");
			return NULL;
		}
		else
		{
			pNode->key = 0x00000000;
			RtlZeroMemory(&pNode->data, sizeof(ELEMENT));
			InitializeListHead(&pNode->linkfield);
		}
		pHashTable->pListHeads[i] = &pNode->linkfield;
	}
	return pHashTable;
}

PTWOWAY Find(DWORD key, PHASHTABLE pHashTable)
{
	PTWOWAY			pNode		= NULL;
	PLIST_ENTRY		pListHead	= NULL;
	PLIST_ENTRY		pListLink	= NULL;

	pListHead = pHashTable->pListHeads[Hash(key, pHashTable->tableSize)];
	pListLink = pHashTable->pListHeads[Hash(key, pHashTable->tableSize)];

	if (pListHead == NULL)
	{
		DbgPrint("pListHead is NULL!\n");
		return NULL;
	}

	if (!IsListEmpty(pListHead))
	{
		do
		{
			pNode = CONTAINING_RECORD(pListLink, TWOWAY, linkfield);
			if (pNode->key == key)
			{
				return pNode;
			}
			pListLink = pListLink->Flink;
		} while (pListLink != pListHead);
	}

	return NULL;
}

void Insert(DWORD key, PHASHDATA pData, PHASHTABLE pHashTable)
{
	PTWOWAY			pNode		= NULL; 
	PTWOWAY			pNewNode	= NULL;
	PLIST_ENTRY		pListHead	= NULL;

	pNode = Find(key, pHashTable);
	// The node with the given key was not found.
	if (pNode == NULL)
	{
		pNewNode = ExAllocateFromNPagedLookasideList(pLookasideList_TWOWAY);
		if (pNewNode == NULL)
		{
			DbgPrint("ExAllocateFromNPagedLookasideList returned NULL!\n");
			return;
		}
		
		// Insert the data to the node.
		pNewNode->key = key;
		pNewNode->data.lpNameControl = pData->lpNameControl;

		// Insert the node to the doubly-linked list.
		pListHead = pHashTable->pListHeads[Hash(key, pHashTable->tableSize)];
		InsertTailList(pListHead, &pNewNode->linkfield);
	}
}

void Remove(DWORD key, PHASHTABLE pHashTable)
{
	PTWOWAY			pNode		= NULL; 
	PLIST_ENTRY		pListHead	= NULL;

	pNode = Find(key, pHashTable);

	// The node with the given key was found.
	if (pNode != NULL)
	{
		RemoveEntryList(&pNode->linkfield);
		ExFreeToNPagedLookasideList(pLookasideList_TWOWAY, pNode);
	}
}

void DestroyTable(PHASHTABLE pHashTable)
{
	PTWOWAY				pNode		= NULL; 
	PTWOWAY				pTmpNode	= NULL;
	PLIST_ENTRY			pListHead	= NULL;
	PLIST_ENTRY			pListLink	= NULL;
    unsigned int		i			= 0;

	for (i = 0; i < pHashTable->tableSize; i++)
	{
		pListHead = pListLink = pHashTable->pListHeads[i];
		if (pListHead == NULL)
		{
			DbgPrint("pListHead is NULL!\n");
			continue;
		}
		if (!IsListEmpty(pListHead))
		{
			do
			{
				pNode = CONTAINING_RECORD(pListLink, TWOWAY, linkfield);
				pListLink = pListLink->Flink;
				ExFreeToNPagedLookasideList(pLookasideList_TWOWAY, pNode);
			} while (pListLink != pListHead);
		}
		else
		{
			pNode = CONTAINING_RECORD(pListHead, TWOWAY, linkfield);
			ExFreeToNPagedLookasideList(pLookasideList_TWOWAY, pNode);
		}
	}

	ExDeleteNPagedLookasideList(pLookasideList_TWOWAY);
	ExFreePoolWithTag(pLookasideList_TWOWAY, DRIVERTAG1);
	ExFreePoolWithTag(pHashTable->pListHeads, DRIVERTAG1);
	ExFreePoolWithTag(pHashTable, DRIVERTAG1);
}

ULONG  DumpTable(PHASHTABLE pHashTable)
{
	PTWOWAY				pNode		= NULL;
	PLIST_ENTRY			pListHead	= NULL;
	PLIST_ENTRY			pListLink	= NULL;
    ULONG				i			= 0;
	ULONG				total		= 0;

	for (i = 0; i < pHashTable->tableSize; i++)
	{
		pListHead = pListLink = pHashTable->pListHeads[i];
		if (pListHead == NULL)
		{
			DbgPrint("pListHead is NULL!\n");
			continue;
		}
		if (!IsListEmpty(pListHead))
		{
			do
			{
				pNode = CONTAINING_RECORD(pListLink, TWOWAY, linkfield);
				pListLink = pListLink->Flink;
				if (pNode->key != 0)
				{
				    total++;
				}
			} while (pListLink != pListHead);
		}
	}
	return total;
}
