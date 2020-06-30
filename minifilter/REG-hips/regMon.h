#ifndef __REGMON_H__
#define __REGMON_H__

typedef enum _OBJECT_INFO_CLASS {
    ObjectBasicInfo,
		ObjectNameInfo,
		ObjectTypeInfo,
		ObjectAllTypesInfo,
		ObjectProtectionInfo
} OBJECT_INFO_CLASS;


PGENERIC_MAPPING IoGetKeyGenericMapping( );

NTSTATUS 
MyRegCallback
(
	PVOID CallbackContext, 
	PVOID Argument1, 
	PVOID Argument2
);


NTSTATUS startRegMon(PDRIVER_OBJECT driverObject);
VOID stopRegMon( );


#endif



