
#include "precom.h"

PFLT_PORT g_pServerPort = NULL;
PFLT_PORT g_pClientPort = NULL;


PEPROCESS g_pProcessObject = NULL;

extern PFLT_FILTER gp_Filter;

NTSTATUS
HandleMessageFromClient(
      IN PVOID PortCookie,
      IN PVOID InputBuffer OPTIONAL,
      IN ULONG InputBufferLength,
      OUT PVOID OutputBuffer OPTIONAL,
      IN ULONG OutputBufferLength,
      OUT PULONG ReturnOutputBufferLength
      )
{


	__try
	{
		ProbeForRead(InputBuffer, InputBufferLength, sizeof(ULONG));
		//GET InputBuffer
		//Do something
		ProbeForWrite(OutputBuffer, OutputBufferLength, sizeof(ULONG));
		//Copy Result to Outputbuffer
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_NOT_IMPLEMENTED;
	}

	return STATUS_SUCCESS;

}

NTSTATUS
HandleConnectFromClient (
    PFLT_PORT ClientPort,
    PVOID ServerPortCookie,
    PVOID ConnectionContext,
    ULONG SizeOfContext,
    PVOID *ConnectionCookie
    )
{
	PAGED_CODE();

	g_pProcessObject = PsGetCurrentProcess();
	g_pClientPort = ClientPort;

	return STATUS_SUCCESS;
}

VOID
HandleDisconnectFromClient (
    PVOID ConnectionCookie
    )
{
	PAGED_CODE();

	FltCloseClientPort( gp_Filter, &g_pClientPort );
	g_pClientPort = NULL;
	g_pProcessObject = NULL;
}

NTSTATUS initIPC( )
{
	OBJECT_ATTRIBUTES oa;
    UNICODE_STRING strPortName;
    PSECURITY_DESCRIPTOR sd = NULL;
    NTSTATUS status;

	if(gp_Filter == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;



    status = FltBuildDefaultSecurityDescriptor( &sd, FLT_PORT_ALL_ACCESS );

    if (NT_SUCCESS( status )) 
	{



		RtlSetDaclSecurityDescriptor( sd, TRUE, NULL, FALSE );

		RtlInitUnicodeString( &strPortName, L"\\SandboxPortGUI" );

        InitializeObjectAttributes( &oa,
                                    &strPortName,
                                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                    NULL,
                                    sd );

        status = FltCreateCommunicationPort( gp_Filter,
                                             &g_pServerPort,
                                             &oa,
                                             NULL,
                                             HandleConnectFromClient,
                                             HandleDisconnectFromClient,
                                             HandleMessageFromClient,
                                             1 );


		FltFreeSecurityDescriptor( sd );

	}

    return status;
}

VOID closeIPC( )
{

	if(g_pServerPort)
	{
		FltCloseCommunicationPort( g_pServerPort );
		g_pServerPort = NULL;
	}


}
#ifdef DBG
VOID freeIPC()
{
	closeIPC();
	
	return;
}
#endif
