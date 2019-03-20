#include <ntddk.h>

#define SECOND_OF_DAY 86400

UINT8 DayOfMon[12] = { 31,28,31,30,31,30,31,31,30,31,30,31 };

ULONG BanedTime = 1552380987;

extern POBJECT_TYPE *PsThreadType;

NTSTATUS Unload(PDRIVER_OBJECT driver)
{
	return STATUS_SUCCESS;
}

BOOLEAN CheckLocalTime()
{
	LARGE_INTEGER snow, now, tickcount;
	TIME_FIELDS now_fields;

	KeQuerySystemTime(&snow);

	ExSystemTimeToLocalTime(&snow, &now);

	RtlTimeToTimeFields(&now, &now_fields);

	UINT16 iYear, iMon, iDay, iHour, iMin, iSec;
	iYear = now_fields.Year;
	iMon = now_fields.Month;
	iDay = now_fields.Day;
	iHour = now_fields.Hour;
	iMin = now_fields.Minute;
	iSec = now_fields.Second;

	SHORT i, Cyear = 0;
	ULONG CountDay = 0;
	
	for (i = 1970; i < iYear; i++)
	{
		if (((i % 4 == 0) && (i % 100 != 0)) || (i % 400 == 0))
			Cyear++;
	}

	CountDay = Cyear * 366 + (iYear - 1970 - Cyear) * 365;

	for (i = 1; i < iMon; i++)
	{
		if ((i == 2) && (((iYear % 4 == 0) && (iYear % 100 != 0)) || (iYear % 400 == 0)))
		{
			CountDay += 29;
		}
		else
		{
			CountDay += DayOfMon[i - 1];
		}
	}

	CountDay += (iDay - 1);

	CountDay = CountDay * SECOND_OF_DAY + (unsigned long)iHour * 3600 + (unsigned long)iMin * 60 + iSec;

	if (CountDay < BanedTime)
	{
		return TRUE;
	}

	return FALSE;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path)
{
	driver->DriverUnload = Unload;

	KdBreakPoint();

	if (!CheckLocalTime())
	{
		return STATUS_NOT_SUPPORTED;
	}

	return STATUS_SUCCESS;
}