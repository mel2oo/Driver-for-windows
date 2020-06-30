#include "precomp.h"

#define		DEVICE_NAME					L"\\device\\HipsRegDrv"
#define		LINK_NAME					L"\\dosDevices\\HipsRegDrv"


// function to dispatch the IRPs
NTSTATUS DispatchOK(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
   Irp->IoStatus.Status = STATUS_SUCCESS;
   IoCompleteRequest(Irp,IO_NO_INCREMENT);
   return STATUS_SUCCESS;
}

VOID DriverUnload (
    IN PDRIVER_OBJECT	pDriverObject) 
{
	UNICODE_STRING strLink;
	RtlInitUnicodeString(&strLink, LINK_NAME);
	stopRegMon();

	IoDeleteSymbolicLink(&strLink);
	IoDeleteDevice(pDriverObject->DeviceObject);

	DbgPrint(" Unloaded\n"); 
}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
    UNICODE_STRING 	DeviceName;
    UNICODE_STRING 	LinkName;  
    NTSTATUS 		status; 
    PDEVICE_OBJECT 	pDriverDeviceObject;  
	ULONG i;
    
    //DbgPrint("Driver loaded.");
    pDriverObject->DriverUnload = DriverUnload;   
    
    // init strings
    RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
    RtlInitUnicodeString(&LinkName, LINK_NAME);
    
    // to communicate with usermode, we need a device
    status = IoCreateDevice(
           pDriverObject,        // ptr to caller object
           0,  // extension device allocated byte number
           &DeviceName,         // device name 
           FILE_DEVICE_UNKNOWN, 
           0,                   // no special caracteristics
           FALSE,               // we can open many handles in same time
           &pDriverDeviceObject); // [OUT] ptr to the created object
           
    if ( !NT_SUCCESS(status) ) 
       return STATUS_NO_SUCH_DEVICE;
    
	pDriverDeviceObject-> Flags |= DO_BUFFERED_IO;

    // we also need a symbolic link
    status = IoCreateSymbolicLink(&LinkName,&DeviceName);
    if( !NT_SUCCESS(status) ) 
    {
		IoDeleteDevice( pDriverDeviceObject );
        return STATUS_NO_SUCH_DEVICE;
    }  

    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		pDriverObject->MajorFunction[i] = DispatchOK; 
    

    startRegMon(pDriverObject);
    //Do other things...   
    
    return STATUS_SUCCESS;
}
