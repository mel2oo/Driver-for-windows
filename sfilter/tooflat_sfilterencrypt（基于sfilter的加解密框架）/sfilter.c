/*++

Copyright (c) 1989-1993  Microsoft Corporation

Module Name:

	sfilter.c

Abstract:

	This module contains the code that implements the general purpose sample
	file system filter driver.

	As of the Windows XP SP1 IFS Kit version of this sample and later, this
	sample can be built for each build environment released with the IFS Kit
	with no additional modifications.  To provide this capability, additional
	compile-time logic was added -- see the '#if WINVER' locations.  Comments
	tagged with the 'VERSION NOTE' header have also been added as appropriate to
	describe how the logic must change between versions.

	If this sample is built in the Windows XP environment or later, it will run
	on Windows 2000 or later.  This is done by dynamically loading the routines
	that are only available on Windows XP or later and making run-time decisions
	to determine what code to execute.  Comments tagged with 'MULTIVERISON NOTE'
	mark the locations where such logic has been added.

Environment:

	Kernel mode

--*/

#ifndef _WIN2K_COMPAT_SLIST_USAGE
#define _WIN2K_COMPAT_SLIST_USAGE
#endif

#include "ntifs.h"
#include "ntdddisk.h"

#include <ntverp.h>
#include "rc4.h" 

// 
// Enable these warnings in the code.
// 

#pragma warning(error:4100)	// Unreferenced formal parameter
#pragma warning(error:4101)	// Unreferenced local variable

// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
// 
//				 Macro and Structure Definitions
// 
// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /

// 
// VERSION NOTE:
// 
// The following useful macros are defined in NTIFS.H in Windows XP and later.
// We will define them locally if we are building for the Windows 2000 
// environment.
// 

#if WINVER == 0x0500

// 
// These macros are used to test, set and clear flags respectively
// 

#ifndef FlagOn
#define FlagOn(_F, _SF)			((_F) & (_SF))
#endif

#ifndef BooleanFlagOn
#define BooleanFlagOn(F, SF)	((BOOLEAN) (((F) & (SF)) != 0))
#endif

#ifndef SetFlag
#define SetFlag(_F, _SF)		((_F) |= (_SF))
#endif

#ifndef ClearFlag
#define ClearFlag(_F, _SF)		((_F) &= ~(_SF))
#endif

#define RtlInitEmptyUnicodeString(_ucStr, _buf, _bufSize) \
	((_ucStr)->Buffer = (_buf), \
	 (_ucStr)->Length = 0, \
	 (_ucStr)->MaximumLength = (USHORT)(_bufSize))

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

// 
// We want ASSERT defined as an expression, which was fixed after Windows 2000
// 

#ifdef ASSERT
#undef ASSERT
#if DBG
#define ASSERT(exp) \
	((!(exp)) ? \
		(RtlAssert(#exp, __FILE__, __LINE__, NULL),FALSE) : \
		TRUE)
#else
#define ASSERT(exp) ((void) 0)
#endif
#endif		

#define ExFreePoolWithTag(a, b) ExFreePool((a))

#endif /* WINVER == 0x0500 */

#ifndef Add2Ptr
#define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#endif

// 
// Buffer size for local names on the stack
// 

#define MAX_DEVNAME_LENGTH				64
#define MAX_PATH						512

#define ENCRYPT_BIT_SIZE				(128 * 8)

#define SF_ENCRYPT_POSTFIX				L".$encrypt$"
#define SF_ENCRYPT_POSTFIX_LENGTH		10

#define RULE_FILE_NAME					L"\\SystemRoot\\xefs.dat"

#if DBG
#define DEBUG_VOLUME					L'H'   //min yongming
#endif

typedef struct _FILE_CONTEXT_HDR
{
	PVOID FsContext;
} FILE_CONTEXT_HDR, *PFILE_CONTEXT_HDR;

typedef struct _FILE_CONTEXT
{
	FILE_CONTEXT_HDR;

	ULONG RefCount;
	BOOLEAN DecryptOnRead;
	BOOLEAN EncryptOnWrite;
	BOOLEAN EncryptFlagExist; // if encrypt flag file exists, then the file is encrypted
	BOOLEAN NeedEncrypt;
	BOOLEAN DeleteOnClose;
	KEVENT Event;
	WCHAR Name[MAX_PATH];
	UCHAR EncryptExtData[ENCRYPT_BIT_SIZE / sizeof(UCHAR)];
} FILE_CONTEXT, *PFILE_CONTEXT;

// 
// Device extension definition for our driver.  Note that the same extension
// is used for the following types of device objects:
//	- File system device object we attach to
//	- Mounted volume device objects we attach to
// 
typedef struct _SFILTER_DEVICE_EXTENSION
{
	// 
	// Pointer to the file system device object we are attached to
	// 
	PDEVICE_OBJECT AttachedToDeviceObject;

	// 
	// Pointer to the real (disk) device object that is associated with
	// the file system device object we are attached to
	// 
	PDEVICE_OBJECT StorageStackDeviceObject;

	// 
	// Name for this device.  If attached to a Volume Device Object it is the
	// name of the physical disk drive.  If attached to a Control Device
	// Object it is the name of the Control Device Object.
	// 
	UNICODE_STRING DeviceName;

	// 
	// Buffer used to hold the above unicode strings
	// 
	WCHAR DeviceNameBuffer[MAX_DEVNAME_LENGTH];

	WCHAR DriveLetter;

	RTL_GENERIC_TABLE FsCtxTable;
	FAST_MUTEX FsCtxTableMutex;
} SFILTER_DEVICE_EXTENSION, *PSFILTER_DEVICE_EXTENSION;

// 
// This structure contains the information we need to pass to the completion
// processing for FSCTRLs.
// 
typedef struct _FSCTRL_COMPLETION_CONTEXT
{
	// 
	// The workitem that will be initialized with our context and 
	// worker routine if this completion processing needs to be completed
	// in a worker thread.
	// 
	WORK_QUEUE_ITEM WorkItem;

	// 
	// The device object to which this device is currently directed.
	// 
	PDEVICE_OBJECT DeviceObject;

	// 
	// The IRP for this FSCTRL operation.
	// 
	PIRP Irp;

	// 
	// For mount operations, the new device object that we have allocated
	// and partially initialized that we will attach to the mounted volume
	// if the mount is successful.
	// 
	PDEVICE_OBJECT NewDeviceObject;
} FSCTRL_COMPLETION_CONTEXT, *PFSCTRL_COMPLETION_CONTEXT;

typedef struct _POST_CREATE_WORKER_CONTEXT
{
	WORK_QUEUE_ITEM WorkItem;
	KEVENT Event;
	PDEVICE_OBJECT DeviceObject;
	PFILE_OBJECT FileObject;
	PFILE_CONTEXT FileContext;
	BOOLEAN NewElement;
} POST_CREATE_WORKER_CONTEXT, *PPOST_CREATE_WORKER_CONTEXT;

typedef struct _READ_WRITE_COMPLETION_CONTEXT
{
	PMDL OldMdl;
	PVOID OldUserBuffer;
	PVOID OldSystemBuffer;

	PMDL MdlForUserBuffer;
	
	PVOID OldBuffer;
	PVOID MyBuffer;
	ULONG Length;
} READ_WRITE_COMPLETION_CONTEXT, *PREAD_WRITE_COMPLETION_CONTEXT;

typedef struct _POST_SET_INFORMATION_WORKER_CONTEXT
{
	WORK_QUEUE_ITEM WorkItem;
	KEVENT Event;
	PDEVICE_OBJECT DeviceObject;
	PFILE_OBJECT FileObject;
	PFILE_CONTEXT FileContext;
	PWCHAR FileName;
	PWCHAR TargetFileName;
 } POST_SET_INFORMATION_WORKER_CONTEXT, *PPOST_SET_INFORMATION_WORKER_CONTEXT;

#define POLICY_NONE			0x0
#define POLICY_ENCRYPT		0x1
#define POLICY_END			0xFFFFFFFF

typedef struct _RULE
{
	ULONG Policy;
	WCHAR Pattern[MAX_PATH];
} RULE, *PRULE;

// 
// Macro to test if this is my device object
// 
#define IS_MY_DEVICE_OBJECT(_devObj) \
	(((_devObj) != NULL) && \
	 ((_devObj)->DriverObject == gSFilterDriverObject) && \
	  ((_devObj)->DeviceExtension != NULL))

// 
// Macro to test if this is my control device object
// 
#define IS_MY_CONTROL_DEVICE_OBJECT(_devObj) \
	(((_devObj) == gSFilterControlDeviceObject) ? \
			(ASSERT(((_devObj)->DriverObject == gSFilterDriverObject) && \
					((_devObj)->DeviceExtension == NULL)), TRUE) : \
			FALSE)

// 
// Macro to test for device types we want to attach to
// 
#define IS_DESIRED_DEVICE_TYPE(_type) \
	(((_type) == FILE_DEVICE_DISK_FILE_SYSTEM) || \
	 ((_type) == FILE_DEVICE_CD_ROM_FILE_SYSTEM) || \
	 ((_type) == FILE_DEVICE_NETWORK_FILE_SYSTEM))

// 
// Macro to test if FAST_IO_DISPATCH handling routine is valid
// 
#define VALID_FAST_IO_DISPATCH_HANDLER(_FastIoDispatchPtr, _FieldName) \
	(((_FastIoDispatchPtr) != NULL) && \
	 (((_FastIoDispatchPtr)->SizeOfFastIoDispatch) >= \
			(FIELD_OFFSET(FAST_IO_DISPATCH, _FieldName) + sizeof(void *))) && \
	 ((_FastIoDispatchPtr)->_FieldName != NULL))


#if WINVER >= 0x0501
// 
// MULTIVERSION NOTE:
// 
// If built in the Windows XP environment or later, we will dynamically import
// the function pointers for routines that were not supported on Windows 2000
// so that we can build a driver that will run, with modified logic, on 
// Windows 2000 or later.
// 
// Below are the prototypes for the function pointers that we need to 
// dynamically import because not all OS versions support these routines.
// 

typedef
NTSTATUS
(* PSF_REGISTER_FILE_SYSTEM_FILTER_CALLBACKS)(
	IN PDRIVER_OBJECT DriverObject,
	IN PFS_FILTER_CALLBACKS Callbacks
	);

typedef
NTSTATUS
(* PSF_ENUMERATE_DEVICE_OBJECT_LIST)(
	IN PDRIVER_OBJECT DriverObject,
	IN PDEVICE_OBJECT *DeviceObjectList,
	IN ULONG DeviceObjectListSize,
	OUT PULONG ActualNumberDeviceObjects
	);

typedef
NTSTATUS
(* PSF_ATTACH_DEVICE_TO_DEVICE_STACK_SAFE)(
	IN PDEVICE_OBJECT SourceDevice,
	IN PDEVICE_OBJECT TargetDevice,
	OUT PDEVICE_OBJECT *AttachedToDeviceObject
	);

typedef	
PDEVICE_OBJECT
(* PSF_GET_LOWER_DEVICE_OBJECT)(
	IN PDEVICE_OBJECT DeviceObject
	);

typedef
PDEVICE_OBJECT
(* PSF_GET_DEVICE_ATTACHMENT_BASE_REF)(
	IN PDEVICE_OBJECT DeviceObject
	);

typedef
NTSTATUS
(* PSF_GET_DISK_DEVICE_OBJECT)(
	IN PDEVICE_OBJECT FileSystemDeviceObject,
	OUT PDEVICE_OBJECT *DiskDeviceObject
	);

typedef
PDEVICE_OBJECT
(* PSF_GET_ATTACHED_DEVICE_REFERENCE)(
	IN PDEVICE_OBJECT DeviceObject
	);

typedef
NTSTATUS
(* PSF_GET_VERSION)(
	IN OUT PRTL_OSVERSIONINFOW VersionInformation
	);

typedef struct _SF_DYNAMIC_FUNCTION_POINTERS
{
	// 
	// The following routines should all be available on Windows XP (5.1) and
	// later.
	// 
	PSF_REGISTER_FILE_SYSTEM_FILTER_CALLBACKS RegisterFileSystemFilterCallbacks;
	PSF_ATTACH_DEVICE_TO_DEVICE_STACK_SAFE AttachDeviceToDeviceStackSafe;
	PSF_ENUMERATE_DEVICE_OBJECT_LIST EnumerateDeviceObjectList;
	PSF_GET_LOWER_DEVICE_OBJECT GetLowerDeviceObject;
	PSF_GET_DEVICE_ATTACHMENT_BASE_REF GetDeviceAttachmentBaseRef;
	PSF_GET_DISK_DEVICE_OBJECT GetDiskDeviceObject;
	PSF_GET_ATTACHED_DEVICE_REFERENCE GetAttachedDeviceReference;
	PSF_GET_VERSION GetVersion;
} SF_DYNAMIC_FUNCTION_POINTERS, *PSF_DYNAMIC_FUNCTION_POINTERS;

SF_DYNAMIC_FUNCTION_POINTERS gSfDynamicFunctions = {NULL};

// 
// MULTIVERSION NOTE: For this version of the driver, we need to know the
// current OS version while we are running to make decisions regarding what
// logic to use when the logic cannot be the same for all platforms.  We
// will look up the OS version in DriverEntry and store the values
// in these global variables.
// 
ULONG gSfOsMajorVersion = 0;
ULONG gSfOsMinorVersion = 0;

// 
// Here is what the major and minor versions should be for the various OS versions:
// 
// OS Name								 MajorVersion	MinorVersion
// ---------------------------------------------------------------------
// Windows 2000							 5				 0
// Windows XP							 5				 1
// Windows Server 2003					 5				 2
// 

#define IS_WINDOWS2000() \
	((gSfOsMajorVersion == 5) && (gSfOsMinorVersion == 0))

#define IS_WINDOWSXP() \
	((gSfOsMajorVersion == 5) && (gSfOsMinorVersion == 1))

#define IS_WINDOWSXP_OR_LATER() \
	(((gSfOsMajorVersion == 5) && (gSfOsMinorVersion >= 1)) || \
	 (gSfOsMajorVersion > 5))

#define IS_WINDOWSSRV2003_OR_LATER() \
	(((gSfOsMajorVersion == 5) && (gSfOsMinorVersion >= 2)) || \
	 (gSfOsMajorVersion > 5))

#endif


// 
// TAG identifying memory SFilter allocates
// 

#define SFLT_POOL_TAG			'tlFS'

// 
// This structure and these routines are used to retrieve the name of a file
// object.  To prevent allocating memory every time we get a name this
// structure contains a small buffer (which should handle 90+% of all names).
// If we do overflow this buffer we will allocate a buffer big enough
// for the name.
// 

typedef struct _GET_NAME_CONTROL
{
	PCHAR allocatedBuffer;
	CHAR smallBuffer[256];
} GET_NAME_CONTROL, *PGET_NAME_CONTROL;


PUNICODE_STRING
SfGetFileName(
	IN PFILE_OBJECT FileObject,
	IN NTSTATUS CreateStatus,
	IN OUT PGET_NAME_CONTROL NameControl
	);

VOID
SfGetFileNameCleanup(
	IN OUT PGET_NAME_CONTROL NameControl
	);

// 
// Macros for SFilter DbgPrint levels.
// 
#define SF_LOG_PRINT(_dbgLevel, _string)				  \
	(FlagOn(SfDebug,(_dbgLevel)) ?						  \
		DbgPrint _string  :								 \
		((void)0))

// 
// Delay values for KeDelayExecutionThread()
// (Values are negative to represent relative time)
// 
#define DELAY_ONE_MICROSECOND	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND*1000)
#define DELAY_ONE_SECOND		(DELAY_ONE_MILLISECOND*1000)


// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
// 
//					Global variables
// 
// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /

// 
// Holds pointer to the driver object for this driver
// 
PDRIVER_OBJECT gSFilterDriverObject = NULL;

// 
// Holds pointer to the device object that represents this driver and is used
// by external programs to access this driver.  This is also known as the
// "control device object".
// 
PDEVICE_OBJECT gSFilterControlDeviceObject = NULL;

// 
// This lock is used to synchronize our attaching to a given device object.
// This lock fixes a race condition where we could accidently attach to the
// same device object more then once.  This race condition only occurs if
// a volume is being mounted at the same time as this filter is being loaded.
// This problem will never occur if this filter is loaded at boot time before
// any file systems are loaded.
// 
// This lock is used to atomically test if we are already attached to a given
// device object and if not, do the attach.
// 
FAST_MUTEX gSfilterAttachLock;

PAGED_LOOKASIDE_LIST gFileNameLookAsideList;
PAGED_LOOKASIDE_LIST gFsCtxLookAsideList;
NPAGED_LOOKASIDE_LIST gReadWriteCompletionCtxLookAsideList;

PRULE gRules = NULL;
ERESOURCE gRulesResource;
HANDLE gRuleFileHandle = NULL;

UCHAR gKey[128] = {0};

#define FSCTX_GENERIC_TABLE_POOL_SIZE		sizeof(FILE_CONTEXT) + 32

// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
// 
//					Debug Definitions
// 
// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /

// 
// DEBUG display flags
// 

#define SFDEBUG_DISPLAY_ATTACHMENT_NAMES	0x00000001  // display names of device objects we attach to
#define SFDEBUG_DISPLAY_CREATE_NAMES		0x00000002  // get and display names during create
#define SFDEBUG_GET_CREATE_NAMES			0x00000004  // get name (don't display) during create
#define SFDEBUG_DO_CREATE_COMPLETION		0x00000008  // do create completion routine, don't get names
#define SFDEBUG_ATTACH_TO_FSRECOGNIZER	  0x00000010  // do attach to FSRecognizer device objects
#define SFDEBUG_ATTACH_TO_SHADOW_COPIES	 0x00000020  // do attach to ShadowCopy Volume device objects -- they are only around on Windows XP and later

ULONG SfDebug = 0;


// 
// Given a device type, return a valid name
// 

#define GET_DEVICE_TYPE_NAME(_type) \
			((((_type) > 0) && ((_type) < (sizeof(DeviceTypeNames) / sizeof(PCHAR)))) ? \
				DeviceTypeNames[ (_type) ] : \
				"[Unknown]")

// 
// Known device type names
// 

static const PCHAR DeviceTypeNames[] = {
	"",
	"BEEP",
	"CD_ROM",
	"CD_ROM_FILE_SYSTEM",
	"CONTROLLER",
	"DATALINK",
	"DFS",
	"DISK",
	"DISK_FILE_SYSTEM",
	"FILE_SYSTEM",
	"INPORT_PORT",
	"KEYBOARD",
	"MAILSLOT",
	"MIDI_IN",
	"MIDI_OUT",
	"MOUSE",
	"MULTI_UNC_PROVIDER",
	"NAMED_PIPE",
	"NETWORK",
	"NETWORK_BROWSER",
	"NETWORK_FILE_SYSTEM",
	"NULL",
	"PARALLEL_PORT",
	"PHYSICAL_NETCARD",
	"PRINTER",
	"SCANNER",
	"SERIAL_MOUSE_PORT",
	"SERIAL_PORT",
	"SCREEN",
	"SOUND",
	"STREAMS",
	"TAPE",
	"TAPE_FILE_SYSTEM",
	"TRANSPORT",
	"UNKNOWN",
	"VIDEO",
	"VIRTUAL_DISK",
	"WAVE_IN",
	"WAVE_OUT",
	"8042_PORT",
	"NETWORK_REDIRECTOR",
	"BATTERY",
	"BUS_EXTENDER",
	"MODEM",
	"VDM",
	"MASS_STORAGE",
	"SMB",
	"KS",
	"CHANGER",
	"SMARTCARD",
	"ACPI",
	"DVD",
	"FULLSCREEN_VIDEO",
	"DFS_FILE_SYSTEM",
	"DFS_VOLUME",
	"SERENUM",
	"TERMSRV",
	"KSEC"
};


// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
// 
//						Function Prototypes
// 
// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /


int __cdecl
swprintf(wchar_t *, const wchar_t *, ...);

// 
// Define driver entry routine.
// 

NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath
	);

#if DBG && WINVER >= 0x0501
VOID
DriverUnload(
	IN PDRIVER_OBJECT DriverObject
	);
#endif

// 
// Define the local routines used by this driver module.  This includes a
// a sample of how to filter a create file operation, and then invoke an I/O
// completion routine when the file has successfully been created/opened.
// 

#if WINVER >= 0x0501
VOID
SfLoadDynamicFunctions(
	);

VOID
SfGetCurrentVersion(
	);
#endif

NTSTATUS
SfPassThrough(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

NTSTATUS
SfCreate(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

NTSTATUS
SfCleanup(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

NTSTATUS
SfClose(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

NTSTATUS
SfRead(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

NTSTATUS
SfReadCompletion(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context
	);

NTSTATUS
SfWrite(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

NTSTATUS
SfWriteCompletion(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context
	);

NTSTATUS
SfDirectoryControl (
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

NTSTATUS
SfSetInformation (
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

NTSTATUS
SfFsControl(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

NTSTATUS
SfFsControlMountVolume (
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

VOID
SfFsControlMountVolumeCompleteWorker (
	IN PFSCTRL_COMPLETION_CONTEXT Context
	);

NTSTATUS
SfFsControlMountVolumeComplete (
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PDEVICE_OBJECT NewDeviceObject
	);

NTSTATUS
SfFsControlLoadFileSystem (
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

VOID
SfFsControlLoadFileSystemCompleteWorker (
	IN PFSCTRL_COMPLETION_CONTEXT Context
	);

NTSTATUS
SfFsControlLoadFileSystemComplete (
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

NTSTATUS
SfFsControlCompletion(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context
	);

BOOLEAN
SfFastIoCheckIfPossible(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN ULONG Length,
	IN BOOLEAN Wait,
	IN ULONG LockKey,
	IN BOOLEAN CheckForReadOperation,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	);

BOOLEAN
SfFastIoRead(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN ULONG Length,
	IN BOOLEAN Wait,
	IN ULONG LockKey,
	OUT PVOID Buffer,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	);

BOOLEAN
SfFastIoWrite(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN ULONG Length,
	IN BOOLEAN Wait,
	IN ULONG LockKey,
	IN PVOID Buffer,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	);

BOOLEAN
SfFastIoQueryBasicInfo(
	IN PFILE_OBJECT FileObject,
	IN BOOLEAN Wait,
	OUT PFILE_BASIC_INFORMATION Buffer,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	);

BOOLEAN
SfFastIoQueryStandardInfo(
	IN PFILE_OBJECT FileObject,
	IN BOOLEAN Wait,
	OUT PFILE_STANDARD_INFORMATION Buffer,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	);

BOOLEAN
SfFastIoLock(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN PLARGE_INTEGER Length,
	PEPROCESS ProcessId,
	ULONG Key,
	BOOLEAN FailImmediately,
	BOOLEAN ExclusiveLock,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	);

BOOLEAN
SfFastIoUnlockSingle(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN PLARGE_INTEGER Length,
	PEPROCESS ProcessId,
	ULONG Key,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	);

BOOLEAN
SfFastIoUnlockAll(
	IN PFILE_OBJECT FileObject,
	PEPROCESS ProcessId,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	);

BOOLEAN
SfFastIoUnlockAllByKey(
	IN PFILE_OBJECT FileObject,
	PVOID ProcessId,
	ULONG Key,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	);

BOOLEAN
SfFastIoDeviceControl(
	IN PFILE_OBJECT FileObject,
	IN BOOLEAN Wait,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	IN ULONG IoControlCode,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	);

VOID
SfFastIoDetachDevice(
	IN PDEVICE_OBJECT SourceDevice,
	IN PDEVICE_OBJECT TargetDevice
	);

BOOLEAN
SfFastIoQueryNetworkOpenInfo(
	IN PFILE_OBJECT FileObject,
	IN BOOLEAN Wait,
	OUT PFILE_NETWORK_OPEN_INFORMATION Buffer,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	);

BOOLEAN
SfFastIoMdlRead(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN ULONG Length,
	IN ULONG LockKey,
	OUT PMDL *MdlChain,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	);


BOOLEAN
SfFastIoMdlReadComplete(
	IN PFILE_OBJECT FileObject,
	IN PMDL MdlChain,
	IN PDEVICE_OBJECT DeviceObject
	);

BOOLEAN
SfFastIoPrepareMdlWrite(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN ULONG Length,
	IN ULONG LockKey,
	OUT PMDL *MdlChain,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	);

BOOLEAN
SfFastIoMdlWriteComplete(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN PMDL MdlChain,
	IN PDEVICE_OBJECT DeviceObject
	);

BOOLEAN
SfFastIoReadCompressed(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN ULONG Length,
	IN ULONG LockKey,
	OUT PVOID Buffer,
	OUT PMDL *MdlChain,
	OUT PIO_STATUS_BLOCK IoStatus,
	OUT struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
	IN ULONG CompressedDataInfoLength,
	IN PDEVICE_OBJECT DeviceObject
	);

BOOLEAN
SfFastIoWriteCompressed(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN ULONG Length,
	IN ULONG LockKey,
	IN PVOID Buffer,
	OUT PMDL *MdlChain,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
	IN ULONG CompressedDataInfoLength,
	IN PDEVICE_OBJECT DeviceObject
	);

BOOLEAN
SfFastIoMdlReadCompleteCompressed(
	IN PFILE_OBJECT FileObject,
	IN PMDL MdlChain,
	IN PDEVICE_OBJECT DeviceObject
	);

BOOLEAN
SfFastIoMdlWriteCompleteCompressed(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN PMDL MdlChain,
	IN PDEVICE_OBJECT DeviceObject
	);

BOOLEAN
SfFastIoQueryOpen(
	IN PIRP Irp,
	OUT PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
	IN PDEVICE_OBJECT DeviceObject
	);

#if WINVER >= 0x0501 /* See comment in DriverEntry */
NTSTATUS
SfPreFsFilterPassThrough(
	IN PFS_FILTER_CALLBACK_DATA Data,
	OUT PVOID *CompletionContext
	);

VOID
SfPostFsFilterPassThrough(
	IN PFS_FILTER_CALLBACK_DATA Data,
	IN NTSTATUS OperationStatus,
	IN PVOID CompletionContext
	);
#endif

VOID
SfFsNotification(
	IN PDEVICE_OBJECT DeviceObject,
	IN BOOLEAN FsActive
	);

NTSTATUS
SfAttachDeviceToDeviceStack(
	IN PDEVICE_OBJECT SourceDevice,
	IN PDEVICE_OBJECT TargetDevice,
	IN OUT PDEVICE_OBJECT *AttachedToDeviceObject
	);

NTSTATUS
SfAttachToFileSystemDevice(
	IN PDEVICE_OBJECT DeviceObject,
	IN PUNICODE_STRING DeviceName
	);

VOID
SfDetachFromFileSystemDevice(
	IN PDEVICE_OBJECT DeviceObject
	);

NTSTATUS
SfAttachToMountedDevice(
	IN PDEVICE_OBJECT DeviceObject,
	IN PDEVICE_OBJECT SFilterDeviceObject
	);

VOID
SfCleanupMountedDevice(
	IN PDEVICE_OBJECT DeviceObject
	);

#if WINVER >= 0x0501
NTSTATUS
SfEnumerateFileSystemVolumes(
	IN PDEVICE_OBJECT FSDeviceObject,
	IN PUNICODE_STRING FSName
	);
#endif

VOID
SfGetObjectName(
	IN PVOID Object,
	IN OUT PUNICODE_STRING Name
	);

VOID
SfGetBaseDeviceObjectName(
	IN PDEVICE_OBJECT DeviceObject,
	IN OUT PUNICODE_STRING DeviceName
	);

BOOLEAN
SfIsAttachedToDevice(
	PDEVICE_OBJECT DeviceObject,
	PDEVICE_OBJECT *AttachedDeviceObject OPTIONAL
	);

BOOLEAN
SfIsAttachedToDeviceW2K(
	PDEVICE_OBJECT DeviceObject,
	PDEVICE_OBJECT *AttachedDeviceObject OPTIONAL
	);

BOOLEAN
SfIsAttachedToDeviceWXPAndLater(
	PDEVICE_OBJECT DeviceObject,
	PDEVICE_OBJECT *AttachedDeviceObject OPTIONAL
	);

VOID
SfReadDriverParameters(
	IN PUNICODE_STRING RegistryPath
	);

VOID
SfDriverReinitialization(
    IN PDRIVER_OBJECT DriverObject,
    IN PVOID Context,
    IN ULONG Count
    );

NTSTATUS
SfIsShadowCopyVolume (
	IN PDEVICE_OBJECT StorageStackDeviceObject,
	OUT PBOOLEAN IsShadowCopy
	);

BOOLEAN
SfDissectFileName(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	OUT PWSTR FileName
	);

RTL_GENERIC_COMPARE_RESULTS
SfGenericCompareRoutine(
	IN PRTL_GENERIC_TABLE Table,
	IN PVOID FirstStruct,
	IN PVOID SecondStruct
	);

PVOID
SfGenericAllocateRoutine(
	IN PRTL_GENERIC_TABLE Table,
	IN CLONG ByteSize
	);

VOID
SfGenericFreeRoutine(
	IN PRTL_GENERIC_TABLE Table,
	IN PVOID Buffer
	);

NTSTATUS
SfIsEncryptFlagExist(
	IN PDEVICE_OBJECT DeviceObject,
	IN PCWSTR FileName,
	OUT PBOOLEAN Encrypted,
	OUT PVOID Data,
	IN ULONG DataLength
	);

NTSTATUS
SfIsFileNeedEncrypt(
	IN PDEVICE_OBJECT DeviceObject,
	IN PCWSTR FileName,
	OUT PBOOLEAN NeedEncrypt
	);

NTSTATUS
SfSetFileEncrypted(
	IN PDEVICE_OBJECT DeviceObject,
	IN PCWSTR FileName,
	IN BOOLEAN IsEncrypted,
	IN PVOID Data,
	IN ULONG DataLength	
	);

NTSTATUS
SfUpdateFileByFileObject(
	IN PDEVICE_OBJECT DeviceObject,
	IN PFILE_OBJECT FileObject
	);

NTSTATUS
SfIssueReadWriteIrpSynchronously(
	IN PDEVICE_OBJECT DeviceObject,
	IN PFILE_OBJECT FileObject,
	IN ULONG MajorFunction,
	IN PIO_STATUS_BLOCK IoStatus,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset,
	IN ULONG IrpFlags
	);

NTSTATUS
SfIssueCleanupIrpSynchronously(
	IN PDEVICE_OBJECT NextDeviceObject,
	IN PIRP Irp,
	IN PFILE_OBJECT FileObject
	);

NTSTATUS
SfCreateFile(
	IN PCWSTR FileName,
	IN ULONG FileAttributes,
	IN BOOLEAN IsFile
	);

NTSTATUS
SfRenameFile(
	IN PWSTR SrcFileName,
	IN PWSTR DstFileName
	);

NTSTATUS
SfForwardIrpSyncronously(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);

NTSTATUS
SfLoadRules(
	OUT PHANDLE FileHandle
	);

ULONG 
SfMatchRules(
	IN PCWSTR FileName
	);

BOOLEAN
SfMatchWithPattern(
	IN PCWSTR Pattern,
	IN PCWSTR Name
	);

BOOLEAN
SfMatchOkay(
	IN PCWSTR Pattern
	);

BOOLEAN
SfIsObjectFile(
	IN PFILE_OBJECT FileObject
	);

NTSTATUS
SfQuerySymbolicLink(
    IN  PUNICODE_STRING SymbolicLinkName,
    OUT PUNICODE_STRING LinkTarget
    );

NTSTATUS
SfVolumeDeviceNameToDosName(
    IN PUNICODE_STRING VolumeDeviceName,
    OUT PUNICODE_STRING DosName
    );
    
// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
// 
// Assign text sections for each routine.
// 
// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)

#if DBG && WINVER >= 0x0501
#pragma alloc_text(PAGE, DriverUnload)
#endif

#pragma alloc_text(PAGE, SfFsNotification)
#pragma alloc_text(PAGE, SfCreate)
#pragma alloc_text(PAGE, SfCleanup)
#pragma alloc_text(PAGE, SfClose)
#pragma alloc_text(PAGE, SfFsControl)
#pragma alloc_text(PAGE, SfFsControlMountVolume)
#pragma alloc_text(PAGE, SfFsControlMountVolumeComplete)
#pragma alloc_text(PAGE, SfFsControlLoadFileSystem)
#pragma alloc_text(PAGE, SfFsControlLoadFileSystemComplete)
#pragma alloc_text(PAGE, SfFastIoCheckIfPossible)
#pragma alloc_text(PAGE, SfFastIoRead)
#pragma alloc_text(PAGE, SfFastIoWrite)
#pragma alloc_text(PAGE, SfFastIoQueryBasicInfo)
#pragma alloc_text(PAGE, SfFastIoQueryStandardInfo)
#pragma alloc_text(PAGE, SfFastIoLock)
#pragma alloc_text(PAGE, SfFastIoUnlockSingle)
#pragma alloc_text(PAGE, SfFastIoUnlockAll)
#pragma alloc_text(PAGE, SfFastIoUnlockAllByKey)
#pragma alloc_text(PAGE, SfFastIoDeviceControl)
#pragma alloc_text(PAGE, SfFastIoDetachDevice)
#pragma alloc_text(PAGE, SfFastIoQueryNetworkOpenInfo)
#pragma alloc_text(PAGE, SfFastIoMdlRead)
#pragma alloc_text(PAGE, SfFastIoPrepareMdlWrite)
#pragma alloc_text(PAGE, SfFastIoMdlWriteComplete)
#pragma alloc_text(PAGE, SfFastIoReadCompressed)
#pragma alloc_text(PAGE, SfFastIoWriteCompressed)
#pragma alloc_text(PAGE, SfFastIoQueryOpen)
#pragma alloc_text(PAGE, SfAttachDeviceToDeviceStack)
#pragma alloc_text(PAGE, SfAttachToFileSystemDevice)
#pragma alloc_text(PAGE, SfDetachFromFileSystemDevice)
#pragma alloc_text(PAGE, SfAttachToMountedDevice)
#pragma alloc_text(PAGE, SfIsAttachedToDevice)
#pragma alloc_text(PAGE, SfIsAttachedToDeviceW2K)
#pragma alloc_text(PAGE, SfDriverReinitialization)
#pragma alloc_text(PAGE, SfIsShadowCopyVolume)

#if WINVER >= 0x0501
#pragma alloc_text(INIT, SfLoadDynamicFunctions)
#pragma alloc_text(INIT, SfGetCurrentVersion)
#pragma alloc_text(PAGE, SfEnumerateFileSystemVolumes)
#pragma alloc_text(PAGE, SfIsAttachedToDeviceWXPAndLater)
#endif

#pragma alloc_text(PAGE, SfQuerySymbolicLink)
#pragma alloc_text(PAGE, SfVolumeDeviceNameToDosName)
#endif


// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
// 
//					Functions
// 
// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /

NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath
	)
/*++

Routine Description:

	This is the initialization routine for the SFILTER file system filter
	driver.  This routine creates the device object that represents this
	driver in the system and registers it for watching all file systems that
	register or unregister themselves as active file systems.

Arguments:

	DriverObject - Pointer to driver object created by the system.

Return Value:

	The function value is the final status from the initialization operation.

--*/
{
	PFAST_IO_DISPATCH FastIoDispatch;
	UNICODE_STRING NameString;
	NTSTATUS Status;
	ULONG i=0;

	UNREFERENCED_PARAMETER(RegistryPath);

#if WINVER >= 0x0501
	// 
	// Try to load the dynamic functions that may be available for our use.
	// 
	SfLoadDynamicFunctions();

	// 
	// Now get the current OS version that we will use to determine what logic
	// paths to take when this driver is built to run on various OS version.
	// 
	SfGetCurrentVersion();
#endif

	// 
	// Save our Driver Object, set our UNLOAD routine
	// 

	gSFilterDriverObject = DriverObject;

#if DBG && WINVER >= 0x0501

	// 
	// MULTIVERSION NOTE:
	// 
	// We can only support unload for testing environments if we can enumerate
	// the outstanding device objects that our driver has.
	// 
	
	// 
	// Unload is useful for development purposes. It is not recommended for
	// production versions
	// 
	if (NULL != gSfDynamicFunctions.EnumerateDeviceObjectList)		
		gSFilterDriverObject->DriverUnload = DriverUnload;
#endif

	Status = ExInitializeResourceLite(&gRulesResource);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("SFilter!DriverEntry: ExInitializeResourceLite failed, Status=%08x\n", Status));
		return Status;
	}

	// 
	// Setup other global variables
	// 
	ExInitializeFastMutex(&gSfilterAttachLock);

	ExInitializePagedLookasideList(
		&gFsCtxLookAsideList,
		NULL,
		NULL,
		0,
		FSCTX_GENERIC_TABLE_POOL_SIZE,
		SFLT_POOL_TAG,
		0
		);
		
	ExInitializePagedLookasideList(
		&gFileNameLookAsideList,
		NULL,
		NULL,
		0,
		MAX_PATH * sizeof(WCHAR),
		SFLT_POOL_TAG,
		0
		);

	ExInitializeNPagedLookasideList(
		&gReadWriteCompletionCtxLookAsideList,
		NULL,
		NULL,
		0,
		sizeof(READ_WRITE_COMPLETION_CONTEXT),
		SFLT_POOL_TAG,
		0
		);

	// 
	// Create the Control Device Object (CDO).  This object represents this 
	// driver.  Note that it does not have a device extension.
	// 
	RtlInitUnicodeString(&NameString, L"\\FileSystem\\Filters\\SFilterCDO");

	Status = IoCreateDevice(
		DriverObject,
		0,					  // has no device extension
		&NameString,
		FILE_DEVICE_DISK_FILE_SYSTEM,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&gSFilterControlDeviceObject
		);
	if (Status == STATUS_OBJECT_PATH_NOT_FOUND)
	{
		// 
		// This must be a version of the OS that doesn't have the Filters
		// path in its namespace.  This was added in Windows XP.
		// 
		// We will try just putting our control device object in the \FileSystem
		// portion of the object name space.
		// 

		RtlInitUnicodeString(&NameString, L"\\FileSystem\\SFilterCDO");

		Status = IoCreateDevice(
			DriverObject,
			0,					  // has no device extension
			&NameString,
			FILE_DEVICE_DISK_FILE_SYSTEM,
			FILE_DEVICE_SECURE_OPEN,
			FALSE,
			&gSFilterControlDeviceObject
			);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("SFilter!DriverEntry: Error creating control device object \"%wZ\", Status=%08x\n", &NameString, Status));
			ExDeleteResourceLite(&gRulesResource);
			return Status;
		}
	}
	else if (!NT_SUCCESS(Status))
	{
		KdPrint(("SFilter!DriverEntry: Error creating control device object \"%wZ\", Status=%08x\n", &NameString, Status));
		ExDeleteResourceLite(&gRulesResource);
		return Status;
	}

	// 
	// Initialize the driver object with this device driver's entry points.
	// 
	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = SfPassThrough;
	}

	// 
	// We will use SfCreate for all the create operations
	// 
	DriverObject->MajorFunction[IRP_MJ_CREATE] = SfCreate;
	DriverObject->MajorFunction[IRP_MJ_CREATE_NAMED_PIPE] = SfCreate;
	DriverObject->MajorFunction[IRP_MJ_CREATE_MAILSLOT] = SfCreate;
	
	DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = SfFsControl;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = SfCleanup;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = SfClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = SfRead;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = SfWrite;
	DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] = SfDirectoryControl;
	DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = SfSetInformation;

	// 
	// Allocate fast I/O data structure and fill it in.
	// 
	// NOTE:  The following FastIo Routines are not supported:
	//	AcquireFileForNtCreateSection
	//	ReleaseFileForNtCreateSection
	//	AcquireForModWrite
	//	ReleaseForModWrite
	//	AcquireForCcFlush
	//	ReleaseForCcFlush
	// 
	// For historical reasons these FastIO's have never been sent to filters
	// by the NT I/O system.  Instead, they are sent directly to the base 
	// file system.  On Windows XP and later OS releases, you can use the new 
	// system routine "FsRtlRegisterFileSystemFilterCallbacks" if you need to 
	// intercept these callbacks (see below).
	// 

	FastIoDispatch = ExAllocatePoolWithTag(NonPagedPool, sizeof(FAST_IO_DISPATCH), SFLT_POOL_TAG);
	if (!FastIoDispatch)
	{
		IoDeleteDevice(gSFilterControlDeviceObject);
		ExDeleteResourceLite(&gRulesResource);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(FastIoDispatch, sizeof(FAST_IO_DISPATCH));

	FastIoDispatch->SizeOfFastIoDispatch = sizeof(FAST_IO_DISPATCH);
	FastIoDispatch->FastIoCheckIfPossible = SfFastIoCheckIfPossible;
	FastIoDispatch->FastIoRead = SfFastIoRead;
	FastIoDispatch->FastIoWrite = SfFastIoWrite;
	FastIoDispatch->FastIoQueryBasicInfo = SfFastIoQueryBasicInfo;
	FastIoDispatch->FastIoQueryStandardInfo = SfFastIoQueryStandardInfo;
	FastIoDispatch->FastIoLock = SfFastIoLock;
	FastIoDispatch->FastIoUnlockSingle = SfFastIoUnlockSingle;
	FastIoDispatch->FastIoUnlockAll = SfFastIoUnlockAll;
	FastIoDispatch->FastIoUnlockAllByKey = SfFastIoUnlockAllByKey;
	FastIoDispatch->FastIoDeviceControl = SfFastIoDeviceControl;
	FastIoDispatch->FastIoDetachDevice = SfFastIoDetachDevice;
	FastIoDispatch->FastIoQueryNetworkOpenInfo = SfFastIoQueryNetworkOpenInfo;
	FastIoDispatch->MdlRead = SfFastIoMdlRead;
	FastIoDispatch->MdlReadComplete = SfFastIoMdlReadComplete;
	FastIoDispatch->PrepareMdlWrite = SfFastIoPrepareMdlWrite;
	FastIoDispatch->MdlWriteComplete = SfFastIoMdlWriteComplete;
	FastIoDispatch->FastIoReadCompressed = SfFastIoReadCompressed;
	FastIoDispatch->FastIoWriteCompressed = SfFastIoWriteCompressed;
	FastIoDispatch->MdlReadCompleteCompressed = SfFastIoMdlReadCompleteCompressed;
	FastIoDispatch->MdlWriteCompleteCompressed = SfFastIoMdlWriteCompleteCompressed;
	FastIoDispatch->FastIoQueryOpen = SfFastIoQueryOpen;

	DriverObject->FastIoDispatch = FastIoDispatch;

// 
// VERSION NOTE:
// 
// There are 6 FastIO routines for which file system filters are bypassed as
// the requests are passed directly to the base file system.  These 6 routines
// are AcquireFileForNtCreateSection, ReleaseFileForNtCreateSection,
// AcquireForModWrite, ReleaseForModWrite, AcquireForCcFlush, and 
// ReleaseForCcFlush.
// 
// In Windows XP and later, the FsFilter callbacks were introduced to allow
// filters to safely hook these operations.  See the IFS Kit documentation for
// more details on how these new interfaces work.
// 
// MULTIVERSION NOTE:
// 
// If built for Windows XP or later, this driver is built to run on 
// multiple versions.  When this is the case, we will test
// for the presence of FsFilter callbacks registration API.  If we have it,
// then we will register for those callbacks, otherwise, we will not.
// 

#if WINVER >= 0x0501

	{
		FS_FILTER_CALLBACKS FsFilterCallbacks;

		if (NULL != gSfDynamicFunctions.RegisterFileSystemFilterCallbacks)
		{
			// 
			// Setup the callbacks for the operations we receive through
			// the FsFilter interface.
			// 
			// NOTE:  You only need to register for those routines you really need
			//		to handle.  SFilter is registering for all routines simply to
			//		give an example of how it is done.
			// 
			FsFilterCallbacks.SizeOfFsFilterCallbacks = sizeof(FS_FILTER_CALLBACKS);
			FsFilterCallbacks.PreAcquireForSectionSynchronization = SfPreFsFilterPassThrough;
			FsFilterCallbacks.PostAcquireForSectionSynchronization = SfPostFsFilterPassThrough;
			FsFilterCallbacks.PreReleaseForSectionSynchronization = SfPreFsFilterPassThrough;
			FsFilterCallbacks.PostReleaseForSectionSynchronization = SfPostFsFilterPassThrough;
			FsFilterCallbacks.PreAcquireForCcFlush = SfPreFsFilterPassThrough;
			FsFilterCallbacks.PostAcquireForCcFlush = SfPostFsFilterPassThrough;
			FsFilterCallbacks.PreReleaseForCcFlush = SfPreFsFilterPassThrough;
			FsFilterCallbacks.PostReleaseForCcFlush = SfPostFsFilterPassThrough;
			FsFilterCallbacks.PreAcquireForModifiedPageWriter = SfPreFsFilterPassThrough;
			FsFilterCallbacks.PostAcquireForModifiedPageWriter = SfPostFsFilterPassThrough;
			FsFilterCallbacks.PreReleaseForModifiedPageWriter = SfPreFsFilterPassThrough;
			FsFilterCallbacks.PostReleaseForModifiedPageWriter = SfPostFsFilterPassThrough;

			Status = (gSfDynamicFunctions.RegisterFileSystemFilterCallbacks)(DriverObject, &FsFilterCallbacks);
			if (!NT_SUCCESS(Status))
			{
				DriverObject->FastIoDispatch = NULL;
				ExFreePool(FastIoDispatch);
				IoDeleteDevice(gSFilterControlDeviceObject);
				ExDeleteResourceLite(&gRulesResource);
				return Status;
			}
		}
	}
#endif

	// 
	// The registered callback routine "SfFsNotification" will be called
	// whenever a new file systems is loaded or when any file system is
	// unloaded.
	// 
	// VERSION NOTE:
	// 
	// On Windows XP and later this will also enumerate all existing file
	// systems (except the RAW file systems).  On Windows 2000 this does not
	// enumerate the file systems that were loaded before this filter was
	// loaded.
	// 
	Status = IoRegisterFsRegistrationChange(DriverObject, SfFsNotification);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("SFilter!DriverEntry: Error registering FS change notification, Status=%08x\n", Status));

		DriverObject->FastIoDispatch = NULL;
		ExFreePool(FastIoDispatch);
		IoDeleteDevice(gSFilterControlDeviceObject);
		ExDeleteResourceLite(&gRulesResource);
		return Status;
	}

	// 
	// Attempt to attach to the appropriate RAW file system device objects
	// since they are not enumerated by IoRegisterFsRegistrationChange.
	// 
	{
		PDEVICE_OBJECT RawDeviceObject;
		PFILE_OBJECT FileObject;

		// 
		// Attach to RawDisk device
		// 
		RtlInitUnicodeString(&NameString, L"\\Device\\RawDisk");
		Status = IoGetDeviceObjectPointer(
			&NameString,
			FILE_READ_ATTRIBUTES,
			&FileObject,
			&RawDeviceObject
			);
		if (NT_SUCCESS(Status))
		{
			SfFsNotification(RawDeviceObject, TRUE);
			ObDereferenceObject(FileObject);
		}

		// 
		// Attach to the RawCdRom device
		// 
		RtlInitUnicodeString(&NameString, L"\\Device\\RawCdRom");
		Status = IoGetDeviceObjectPointer(
			&NameString,
			FILE_READ_ATTRIBUTES,
			&FileObject,
			&RawDeviceObject
			);
		if (NT_SUCCESS(Status))
		{
			SfFsNotification(RawDeviceObject, TRUE);
			ObDereferenceObject(FileObject);
		}
	}

	// 
	// Clear the initializing flag on the control device object since we
	// have now successfully initialized everything.
	// 
	ClearFlag(gSFilterControlDeviceObject->Flags, DO_DEVICE_INITIALIZING);

	IoRegisterDriverReinitialization(DriverObject, SfDriverReinitialization, NULL);

	return STATUS_SUCCESS;
}

#if DBG && WINVER >= 0x0501
VOID
DriverUnload(
	IN PDRIVER_OBJECT DriverObject
	)
/*++

Routine Description:

	This routine is called when a driver can be unloaded.  This performs all of
	the necessary cleanup for unloading the driver from memory.  Note that an
	error can NOT be returned from this routine.
	
	When a request is made to unload a driver the IO System will cache that
	information and not actually call this routine until the following states
	have occurred:
	- All device objects which belong to this filter are at the top of their
	  respective attachment chains.
	- All handle counts for all device objects which belong to this filter have
	  gone to zero.

	WARNING: Microsoft does not officially support the unloading of File
			 System Filter Drivers.  This is an example of how to unload
			 your driver if you would like to use it during development.
			 This should not be made available in production code.

Arguments:

	DriverObject - Driver object for this module

Return Value:

	None.

--*/
{
	PSFILTER_DEVICE_EXTENSION DevExt;
	PFAST_IO_DISPATCH FastIoDispatch;
	NTSTATUS Status;
	ULONG NumDevices;
	ULONG i=0;
	LARGE_INTEGER Interval;
#	define DEVOBJ_LIST_SIZE 64
	PDEVICE_OBJECT DevList[DEVOBJ_LIST_SIZE];

	ASSERT(DriverObject == gSFilterDriverObject);

	// 
	// Log we are unloading
	// 
	SF_LOG_PRINT(SFDEBUG_DISPLAY_ATTACHMENT_NAMES,
				  ("SFilter!DriverUnload:						Unloading driver (%p)\n",
					DriverObject));

	// 
	// Don't get anymore file system change notifications
	// 
	IoUnregisterFsRegistrationChange(DriverObject, SfFsNotification);

	// 
	// This is the loop that will go through all of the devices we are attached
	// to and detach from them.  Since we don't know how many there are and
	// we don't want to allocate memory (because we can't return an error)
	// we will free them in chunks using a local array on the stack.
	// 
	for (;;)
	{
		// 
		// Get what device objects we can for this driver.  Quit if there
		// are not any more.  Note that this routine should always be
		// defined since this routine is only compiled for Windows XP and
		// later.
		// 

		ASSERT(NULL != gSfDynamicFunctions.EnumerateDeviceObjectList);
		Status = (gSfDynamicFunctions.EnumerateDeviceObjectList)(
			DriverObject,
			DevList,
			sizeof(DevList),
			&NumDevices
			);

		if (NumDevices <= 0)
			break;

		NumDevices = min(NumDevices, DEVOBJ_LIST_SIZE);

		// 
		// First go through the list and detach each of the devices.
		// Our control device object does not have a DeviceExtension and
		// is not attached to anything so don't detach it.
		// 
		for (i=0; i < NumDevices; i++)
		{
			DevExt = DevList[i]->DeviceExtension;
			if (NULL != DevExt)
				IoDetachDevice(DevExt->AttachedToDeviceObject);
		}

		// 
		// The IO Manager does not currently add a reference count to a device
		// object for each outstanding IRP.  This means there is no way to
		// know if there are any outstanding IRPs on the given device.
		// We are going to wait for a reasonable amount of time for pending
		// irps to complete.  
		// 
		// WARNING: This does not work 100% of the time and the driver may be
		//		 unloaded before all IRPs are completed.  This can easily
		//		 occur under stress situations and if a long lived IRP is
		//		 pending (like oplocks and directory change notifications).
		//		 The system will fault when this Irp actually completes.
		//		 This is a sample of how to do this during testing.  This
		//		 is not recommended for production code.
		// 
		Interval.QuadPart = (5 * DELAY_ONE_SECOND);	  // delay 5 seconds
		KeDelayExecutionThread(KernelMode, FALSE, &Interval);

		// 
		// Now go back through the list and delete the device objects.
		// 
		for (i=0; i < NumDevices; i++)
		{
			// 
			// See if this is our control device object.  If not then cleanup
			// the device extension.  If so then clear the global pointer
			// that references it.
			// 
			if (NULL != DevList[i]->DeviceExtension)
				SfCleanupMountedDevice(DevList[i]);
			else
			{
				ASSERT(DevList[i] == gSFilterControlDeviceObject);
				gSFilterControlDeviceObject = NULL;
			}

			// 
			// Delete the device object, remove reference counts added by
			// IoEnumerateDeviceObjectList.  Note that the delete does
			// not actually occur until the reference count goes to zero.
			// 
			IoDeleteDevice(DevList[i]);
			ObDereferenceObject(DevList[i]);
		}
	}

	// 
	// Free our FastIO table
	// 
	FastIoDispatch = DriverObject->FastIoDispatch;
	DriverObject->FastIoDispatch = NULL;
	ExFreePool(FastIoDispatch);

	ExDeletePagedLookasideList(&gFsCtxLookAsideList);
	ExDeletePagedLookasideList(&gFileNameLookAsideList);
	ExDeleteNPagedLookasideList(&gReadWriteCompletionCtxLookAsideList);

	ZwClose(gRuleFileHandle);
	ExDeleteResourceLite(&gRulesResource);
	if (gRules)
		ExFreePoolWithTag(gRules, SFLT_POOL_TAG);
}
#endif

#if WINVER >= 0x0501
VOID
SfLoadDynamicFunctions (
	)
/*++

Routine Description:

	This routine tries to load the function pointers for the routines that
	are not supported on all versions of the OS.  These function pointers are
	then stored in the global structure SpyDynamicFunctions.

	This support allows for one driver to be built that will run on all 
	versions of the OS Windows 2000 and greater.  Note that on Windows 2000, 
	the functionality may be limited.
	
Arguments:

	None.
	
Return Value:

	None.

--*/
{
	UNICODE_STRING FunctionName;

	RtlZeroMemory(&gSfDynamicFunctions, sizeof(gSfDynamicFunctions));

	// 
	// For each routine that we would want to use, lookup its address in the
	// kernel or hal.  If it is not present, that field in our global
	// SpyDynamicFunctions structure will be set to NULL.
	// 

	RtlInitUnicodeString(&FunctionName, L"FsRtlRegisterFileSystemFilterCallbacks");
	gSfDynamicFunctions.RegisterFileSystemFilterCallbacks = MmGetSystemRoutineAddress(&FunctionName);

	RtlInitUnicodeString(&FunctionName, L"IoAttachDeviceToDeviceStackSafe");
	gSfDynamicFunctions.AttachDeviceToDeviceStackSafe = MmGetSystemRoutineAddress(&FunctionName);
	
	RtlInitUnicodeString(&FunctionName, L"IoEnumerateDeviceObjectList");
	gSfDynamicFunctions.EnumerateDeviceObjectList = MmGetSystemRoutineAddress(&FunctionName);

	RtlInitUnicodeString(&FunctionName, L"IoGetLowerDeviceObject");
	gSfDynamicFunctions.GetLowerDeviceObject = MmGetSystemRoutineAddress(&FunctionName);

	RtlInitUnicodeString(&FunctionName, L"IoGetDeviceAttachmentBaseRef");
	gSfDynamicFunctions.GetDeviceAttachmentBaseRef = MmGetSystemRoutineAddress(&FunctionName);

	RtlInitUnicodeString(&FunctionName, L"IoGetDiskDeviceObject");
	gSfDynamicFunctions.GetDiskDeviceObject = MmGetSystemRoutineAddress(&FunctionName);

	RtlInitUnicodeString(&FunctionName, L"IoGetAttachedDeviceReference");
	gSfDynamicFunctions.GetAttachedDeviceReference = MmGetSystemRoutineAddress(&FunctionName);

	RtlInitUnicodeString(&FunctionName, L"RtlGetVersion");
	gSfDynamicFunctions.GetVersion = MmGetSystemRoutineAddress(&FunctionName);
}

VOID
SfGetCurrentVersion (
	)
/*++

Routine Description:

	This routine reads the current OS version using the correct routine based
	on what routine is available.

Arguments:

	None.
	
Return Value:

	None.

--*/
{
	if (NULL != gSfDynamicFunctions.GetVersion)
	{
		RTL_OSVERSIONINFOW VersionInfo;
		NTSTATUS Status;

		// 
		// VERSION NOTE: RtlGetVersion does a bit more than we need, but
		// we are using it if it is available to show how to use it.  It
		// is available on Windows XP and later.  RtlGetVersion and
		// RtlVerifyVersionInfo (both documented in the IFS Kit docs) allow
		// you to make correct choices when you need to change logic based
		// on the current OS executing your code.
		// 
		VersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

		Status = (gSfDynamicFunctions.GetVersion)(&VersionInfo);

		ASSERT(NT_SUCCESS(Status));

		gSfOsMajorVersion = VersionInfo.dwMajorVersion;
		gSfOsMinorVersion = VersionInfo.dwMinorVersion;
		
	}
	else
	{
		PsGetVersion(&gSfOsMajorVersion,
			&gSfOsMinorVersion,
			NULL,
			NULL
			);
	}
}
#endif

VOID
SfFsNotification(
	IN PDEVICE_OBJECT DeviceObject,
	IN BOOLEAN FsActive
	)
/*++

Routine Description:

	This routine is invoked whenever a file system has either registered or
	unregistered itself as an active file system.

	For the former case, this routine creates a device object and attaches it
	to the specified file system's device object.  This allows this driver
	to filter all requests to that file system.  Specifically we are looking
	for MOUNT requests so we can attach to newly mounted volumes.

	For the latter case, this file system's device object is located,
	detached, and deleted.  This removes this file system as a filter for
	the specified file system.

Arguments:

	DeviceObject - Pointer to the file system's device object.

	FsActive - Boolean indicating whether the file system has registered
		(TRUE) or unregistered (FALSE) itself as an active file system.

Return Value:

	None.

--*/
{
	UNICODE_STRING Name;
	WCHAR NameBuffer[MAX_DEVNAME_LENGTH];

	PAGED_CODE();

	// 
	// Init local Name buffer
	// 
	RtlInitEmptyUnicodeString(&Name, NameBuffer, sizeof(NameBuffer));

	SfGetObjectName(DeviceObject, &Name);

	// 
	// Display the names of all the file system we are notified of
	// 
	SF_LOG_PRINT(SFDEBUG_DISPLAY_ATTACHMENT_NAMES,
		("SFilter!SfFsNotification:					%s	%p \"%wZ\" (%s)\n",
		(FsActive) ? "Activating file system  " : "Deactivating file system",
		DeviceObject,
		&Name,
		GET_DEVICE_TYPE_NAME(DeviceObject->DeviceType))
		);

	// 
	// Handle attaching/detaching from the given file system.
	// 
	if (FsActive)
		SfAttachToFileSystemDevice(DeviceObject, &Name);
	else
		SfDetachFromFileSystemDevice(DeviceObject);
}


// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
// 
//				IRP Handling Routines
// 
// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /


NTSTATUS
SfPassThrough(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
/*++

Routine Description:

	This routine is the main dispatch routine for the general purpose file
	system driver.  It simply passes requests onto the next driver in the
	stack, which is presumably a disk file system.

Arguments:

	DeviceObject - Pointer to the device object for this driver.

	Irp - Pointer to the request packet representing the I/O request.

Return Value:

	The function value is the status of the operation.

Note:

	A note to file system filter implementers:  
		This routine actually "passes" through the request by taking this
		driver out of the IRP stack.  If the driver would like to pass the
		I/O request through, but then also see the result, then rather than
		taking itself out of the loop it could keep itself in by copying the
		caller's parameters to the next stack location and then set its own
		completion routine.  

		Hence, instead of calling:
	
			IoSkipCurrentIrpStackLocation(Irp);

		You could instead call:

			IoCopyCurrentIrpStackLocationToNext(Irp);
			IoSetCompletionRoutine(Irp, NULL, NULL, FALSE, FALSE, FALSE);


		This example actually NULLs out the caller's I/O completion routine, but
		this driver could set its own completion routine so that it would be
		notified when the request was completed (see SfCreate for an example of
		this).

--*/
{
	// 
	// Sfilter doesn't allow handles to its control device object to be created,
	// therefore, no other operation should be able to come through.
	// 
	ASSERT(!IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));
	ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

	// 
	// Get this driver out of the driver stack and get to the next driver as
	// quickly as possible.
	// 
	IoSkipCurrentIrpStackLocation(Irp);
	
	// 
	// Call the appropriate file system driver with the request.
	// 
	return IoCallDriver(((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp);
}

NTSTATUS
SfCreate(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	PSFILTER_DEVICE_EXTENSION DevExt = (PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	PFILE_OBJECT RelatedFileObject = FileObject->RelatedFileObject;
	PWSTR FileName = NULL;
	PFILE_CONTEXT FileCtxPtr = NULL;
	BOOLEAN DeleteOnClose = (BOOLEAN) (IrpSp->Parameters.Create.Options & FILE_DELETE_ON_CLOSE);
	BOOLEAN IsEncryptFlagExist = FALSE;
	BOOLEAN IsNeedEncrypt = FALSE;
	NTSTATUS Status = STATUS_SUCCESS;
	NTSTATUS LocalStatus = STATUS_SUCCESS;

	PAGED_CODE();

	// 
	// If this is for our control device object, don't allow it to be opened.
	// 
	if (IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject))
	{
		// 
		// Sfilter doesn't allow for any communication through its control
		// device object, therefore it fails all requests to open a handle
		// to its control device object.
		// 
		// See the FileSpy sample for an example of how to allow creates to 
		// the filter's control device object and manage communication via
		// that handle.
		// 
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return STATUS_INVALID_DEVICE_REQUEST;
	}

	ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

	// 
	// We only care about volume filter device object
	// 
	if (!DevExt->StorageStackDeviceObject)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}

	if (DevExt->DriveLetter == L'\0') {

		UNICODE_STRING DosName;

		Status = SfVolumeDeviceNameToDosName(&DevExt->DeviceName, &DosName);
		if (NT_SUCCESS(Status)) {

			DevExt->DriveLetter = DosName.Buffer[0];
			ExFreePool(DosName.Buffer);
	
			if ((DevExt->DriveLetter >= L'a') && (DevExt->DriveLetter <= L'z')) {
				DevExt->DriveLetter += L'A' - L'a';
			}
		} else {
			KdPrint(("sfilter!SfCreate: SfVolumeDeviceNameToDosName(%x) failed(%x)\n",
				DevExt->StorageStackDeviceObject, Status));
		}
	}

	// 
	// Open Volume Device directly
	// 
	if ((FileObject->FileName.Length == 0) && !RelatedFileObject)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}

#if DBG
	if (DevExt->DriveLetter != DEBUG_VOLUME)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}
#endif

	do
	{
		// 
		// If the file is opened by id, then we can't get file name directly,
		// But if this case happened, the FsContext must be in GenericTable already.
		// So we just update the RefCount, that's enough
		// 
		if (!(IrpSp->Parameters.Create.Options & FILE_OPEN_BY_FILE_ID))
		{
			FileName = ExAllocateFromPagedLookasideList(&gFileNameLookAsideList);
			if (!FileName)
			{
				KdPrint(("sfilter!SfCreate: ExAllocatePoolWithTag failed\n"));

				Status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			if (!SfDissectFileName(DeviceObject, Irp, FileName))
			{
				KdPrint(("sfilter!SfCreate: SfDissectFileName failed\n"));
				
				Status = STATUS_INVALID_PARAMETER;
				break;
			}

			if (wcslen(FileName) >= SF_ENCRYPT_POSTFIX_LENGTH)
			{
				if (_wcsnicmp(&FileName[wcslen(FileName) - SF_ENCRYPT_POSTFIX_LENGTH],
					SF_ENCRYPT_POSTFIX, SF_ENCRYPT_POSTFIX_LENGTH) == 0)
				{
					// 
					// We deny all create request to our encrypt falg file except kernel mode
					// 
					if (KernelMode == Irp->RequestorMode)
					{
						ExFreeToPagedLookasideList(&gFileNameLookAsideList, FileName);

						IoSkipCurrentIrpStackLocation(Irp);
						return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
					}
					else
					{
						Status = STATUS_SUCCESS;
						break;
					}
				}
			}
		}

		FileCtxPtr = ExAllocatePoolWithTag(PagedPool, sizeof(FILE_CONTEXT), SFLT_POOL_TAG);
		if (FileCtxPtr == NULL)
		{
			Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		Status = SfForwardIrpSyncronously(DevExt->AttachedToDeviceObject, Irp);
		if (NT_SUCCESS(Status) && (STATUS_REPARSE != Status) && SfIsObjectFile(FileObject))
		{
			PFILE_CONTEXT FileCtxPtr2 = NULL;
			BOOLEAN NewElement = FALSE;

			FileCtxPtr->FsContext = FileObject->FsContext;

			ExAcquireFastMutex(&DevExt->FsCtxTableMutex);

			FileCtxPtr2 = RtlLookupElementGenericTable(&DevExt->FsCtxTable, FileCtxPtr);
			if (FileCtxPtr2)
				++FileCtxPtr2->RefCount;
			else
			{
				FileCtxPtr2 = RtlInsertElementGenericTable(
					&DevExt->FsCtxTable,
					FileCtxPtr,
					sizeof(FILE_CONTEXT),
					&NewElement
					);

				FileCtxPtr2->RefCount = 1;

				ASSERT(FileName);
				wcscpy(FileCtxPtr2->Name, FileName);

				KeInitializeEvent(&FileCtxPtr2->Event, SynchronizationEvent, TRUE);
			}

			FileCtxPtr2->DeleteOnClose = DeleteOnClose;

			ExReleaseFastMutex(&DevExt->FsCtxTableMutex);

			IsEncryptFlagExist = FALSE;
			IsNeedEncrypt = FALSE;
			LocalStatus = STATUS_SUCCESS;

			KdPrint(("sfilter!SfCreate: FileName = %ws\n", FileCtxPtr2->Name));

			//
			// we need handle file synchronously
			//
			KeWaitForSingleObject(&FileCtxPtr2->Event, Executive, KernelMode, FALSE, NULL);
			
			LocalStatus = SfIsEncryptFlagExist(DeviceObject, FileCtxPtr2->Name, &IsEncryptFlagExist,
				FileCtxPtr2->EncryptExtData, sizeof(FileCtxPtr2->EncryptExtData));
			if (!NT_SUCCESS(LocalStatus))
				KdPrint(("sfilter!SfPostCreateWorker: SfIsEncryptFlagExist failed, return %x\n", LocalStatus));
			
			LocalStatus = SfIsFileNeedEncrypt(DeviceObject, FileCtxPtr2->Name, &IsNeedEncrypt);
			if (!NT_SUCCESS(LocalStatus))
				KdPrint(("sfilter!SfPostCreateWorker: SfIsFileNeedEncrypt failed, return %x\n", LocalStatus));
		
			FileCtxPtr2->EncryptFlagExist = IsEncryptFlagExist;
			FileCtxPtr2->NeedEncrypt = IsNeedEncrypt;

			KdPrint(("sfilter!SfCreate: IsEncryptFlagExist = %d, IsNeedEncrypt = %d, NewElement = %d\n",
				IsEncryptFlagExist, IsNeedEncrypt, NewElement));

			if (NewElement && ((!IsNeedEncrypt && IsEncryptFlagExist) || (IsNeedEncrypt && !IsEncryptFlagExist)))
			{
				if (!IsNeedEncrypt && IsEncryptFlagExist)
				{
					if (NewElement)
						FileCtxPtr2->DecryptOnRead = TRUE;

					FileCtxPtr2->EncryptOnWrite = FALSE;
					
					KdPrint(("sfilter!SfPostCreateWorker: Decrypt %ws\n", FileCtxPtr2->Name));
					LocalStatus = SfUpdateFileByFileObject(DeviceObject, FileObject);
					if (NT_SUCCESS(LocalStatus))
					{
						FileCtxPtr2->DecryptOnRead = FALSE;
						FileCtxPtr2->EncryptOnWrite = FALSE;
			
						LocalStatus = SfSetFileEncrypted(DeviceObject, FileCtxPtr2->Name, FALSE, NULL, 0);
						if (NT_SUCCESS(LocalStatus))
							FileCtxPtr2->EncryptFlagExist = FALSE;
						else
							KdPrint(("sfilter!SfPostCreateWorker: SfSetFileEncrypted(%ws, FALSE) failed, return %x\n", FileCtxPtr2->Name, LocalStatus));
					}
					else
					{
						KdPrint(("sfilter!SfPostCreateWorker: SfUpdateFileByFileObject failed, return %x\n", LocalStatus));
			
						FileCtxPtr2->DecryptOnRead = TRUE;
						FileCtxPtr2->EncryptOnWrite = TRUE;
					}
				}
				else
				{
					if (NewElement)
						FileCtxPtr2->DecryptOnRead = FALSE;

					FileCtxPtr2->EncryptOnWrite = TRUE;

					KdPrint(("sfilter!SfPostCreateWorker: Encrypt %ws\n", FileCtxPtr2->Name));
					LocalStatus = SfUpdateFileByFileObject(DeviceObject, FileObject);
					if (NT_SUCCESS(LocalStatus))
					{
						FileCtxPtr2->DecryptOnRead = TRUE;
						FileCtxPtr2->EncryptOnWrite = TRUE;
			
						LocalStatus = SfSetFileEncrypted(DeviceObject, FileCtxPtr2->Name, TRUE,
							FileCtxPtr2->EncryptExtData, sizeof(FileCtxPtr2->EncryptExtData));
						if (NT_SUCCESS(LocalStatus))
							FileCtxPtr2->EncryptFlagExist = TRUE;
						else
							KdPrint(("sfilter!SfPostCreateWorker: SfSetFileEncrypted(%ws, TRUE) failed, return %x\n", FileCtxPtr2->Name, LocalStatus));
					}
					else
					{
						KdPrint(("sfilter!SfPostCreateWorker: SfUpdateFileByFileObject failed, return %x\n", LocalStatus));
			
						FileCtxPtr2->DecryptOnRead = FALSE;
						FileCtxPtr2->EncryptOnWrite = FALSE;
					}											
				}
			}
			else
			{
				if (FileCtxPtr2->NeedEncrypt)
				{
					FileCtxPtr2->DecryptOnRead = TRUE;
					FileCtxPtr2->EncryptOnWrite = TRUE;

					if (!FileCtxPtr2->EncryptFlagExist)
					{
						LocalStatus = SfSetFileEncrypted(DeviceObject, FileCtxPtr2->Name, TRUE,
							FileCtxPtr2->EncryptExtData, sizeof(FileCtxPtr2->EncryptExtData));
						if (NT_SUCCESS(LocalStatus))
							FileCtxPtr2->EncryptFlagExist = TRUE;
						else
							KdPrint(("sfilter!SfPostCreateWorker: SfSetFileEncrypted(%ws, TRUE) failed, return %x\n", FileCtxPtr2->Name, LocalStatus));
					}					
				}
				else
				{
					FileCtxPtr2->DecryptOnRead = FALSE;
					FileCtxPtr2->EncryptOnWrite = FALSE;

					if (FileCtxPtr2->EncryptFlagExist)
					{
						LocalStatus = SfSetFileEncrypted(DeviceObject, FileCtxPtr2->Name, FALSE,
							NULL, 0);
						if (NT_SUCCESS(LocalStatus))
							FileCtxPtr2->EncryptFlagExist = FALSE;
						else
							KdPrint(("sfilter!SfPostCreateWorker: SfSetFileEncrypted(%ws, TRUE) failed, return %x\n", FileCtxPtr2->Name, LocalStatus));
					}					
				}
			}
			
			KeSetEvent(&FileCtxPtr2->Event, IO_NO_INCREMENT, FALSE);
		}
	} while (FALSE);

	if (FileName)
		ExFreeToPagedLookasideList(&gFileNameLookAsideList, FileName);

	if (FileCtxPtr)
		ExFreePool(FileCtxPtr);

	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

NTSTATUS
SfCleanup(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	PSFILTER_DEVICE_EXTENSION DevExt = (PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	FILE_CONTEXT_HDR FileCtxHdr;
	PFILE_CONTEXT FileCtxPtr = NULL;
	BOOLEAN DeletePending = FileObject->DeletePending;
	BOOLEAN DeleteOnClose = FALSE;
	NTSTATUS Status;

	PAGED_CODE();

	// 
	// Sfilter doesn't allow handles to its control device object to be created,
	// therefore, no other operation should be able to come through.
	//  
	ASSERT(!IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));
	ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

#if DBG
	if (DevExt->DriveLetter != DEBUG_VOLUME)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}
#endif

	// 
	// We only care about volume filter device object
	// 
	if (!DevExt->StorageStackDeviceObject)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}


	FileCtxHdr.FsContext = FileObject->FsContext;

	ExAcquireFastMutex(&DevExt->FsCtxTableMutex);
	FileCtxPtr = RtlLookupElementGenericTable(&DevExt->FsCtxTable, &FileCtxHdr);
	ExReleaseFastMutex(&DevExt->FsCtxTableMutex);

	if (!FileCtxPtr)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}

	KeWaitForSingleObject(&FileCtxPtr->Event, Executive, KernelMode, FALSE, NULL);

	Status = SfForwardIrpSyncronously(DevExt->AttachedToDeviceObject, Irp);
	if (!NT_SUCCESS(Status))
	{
		KeSetEvent(&FileCtxPtr->Event, IO_NO_INCREMENT, FALSE);
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return Status;
	}

	DeleteOnClose = FileCtxPtr->DeleteOnClose;
	FileCtxPtr->DeleteOnClose = FALSE;

	if (DeletePending || DeleteOnClose)
	{
		if (FileCtxPtr->EncryptFlagExist)
		{
			NTSTATUS LocalStatus;

			LocalStatus = SfSetFileEncrypted(DeviceObject, FileCtxPtr->Name, FALSE, NULL, 0);
			if (NT_SUCCESS(LocalStatus))
			{
				FileCtxPtr->EncryptFlagExist = FALSE;
			}
			else
			{
				KdPrint(("sfilter!SfClose: SfSetFileEncrypted failed, return %x\n", LocalStatus));
			}
		}
	}

	KeSetEvent(&FileCtxPtr->Event, IO_NO_INCREMENT, FALSE);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

NTSTATUS
SfClose(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	PSFILTER_DEVICE_EXTENSION DevExt = (PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	FILE_CONTEXT_HDR FileCtxHdr;
	PFILE_CONTEXT FileCtxPtr = NULL;

	PAGED_CODE();

	// 
	// Sfilter doesn't allow handles to its control device object to be created,
	// therefore, no other operation should be able to come through.
	//  
	ASSERT(!IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));
	ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

#if DBG
	if (DevExt->DriveLetter != DEBUG_VOLUME)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}
#endif

	// 
	// We only care about volume filter device object
	// 
	if (!DevExt->StorageStackDeviceObject)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}

	if (((FileObject->Flags & FO_STREAM_FILE) == FO_STREAM_FILE) ||
		(FileObject->SectionObjectPointer &&
		(CcGetFileObjectFromSectionPtrs(FileObject->SectionObjectPointer) == FileObject)))
	{
	}
	else
	{
		FileCtxHdr.FsContext = FileObject->FsContext;

		ExAcquireFastMutex(&DevExt->FsCtxTableMutex);
		FileCtxPtr = RtlLookupElementGenericTable(&DevExt->FsCtxTable, &FileCtxHdr);
		if (FileCtxPtr)
		{
			if (FileCtxPtr->RefCount > 0)
				--FileCtxPtr->RefCount;

			if ((0 == FileCtxPtr->RefCount) &&
				(!FileObject->SectionObjectPointer ||
				(!FileObject->SectionObjectPointer->DataSectionObject &&
				!FileObject->SectionObjectPointer->ImageSectionObject)))
			{
				RtlDeleteElementGenericTable(&DevExt->FsCtxTable, &FileCtxHdr);
			}
		}
		ExReleaseFastMutex(&DevExt->FsCtxTableMutex);
	}

	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
}

NTSTATUS
SfRead(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	PSFILTER_DEVICE_EXTENSION DevExt = (PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	PREAD_WRITE_COMPLETION_CONTEXT CompletionCtx = NULL;
	PVOID OldBuffer = NULL;
	PMDL Mdl = NULL;
	PVOID MyBuffer = NULL;
	ULONG Length = 0;
	FILE_CONTEXT_HDR FileCtxHdr;
	PFILE_CONTEXT FileCtxPtr = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	

	PAGED_CODE();

	// 
	// Sfilter doesn't allow handles to its control device object to be created,
	// therefore, no other operation should be able to come through.
	//  
	ASSERT(!IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));
	ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

	// 
	// We only care about volume filter device object
	// 
	if (!DevExt->StorageStackDeviceObject)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}

#if DBG
	if (DevExt->DriveLetter != DEBUG_VOLUME)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}
#endif
	
	if (!(Irp->Flags & (IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)))
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}

	ExAcquireFastMutex(&DevExt->FsCtxTableMutex);
	
	FileCtxHdr.FsContext = FileObject->FsContext;
	FileCtxPtr = RtlLookupElementGenericTable(&DevExt->FsCtxTable, &FileCtxHdr);
	
	ExReleaseFastMutex(&DevExt->FsCtxTableMutex);
	
	if (!FileCtxPtr || !FileCtxPtr->DecryptOnRead)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}		

	do
	{
		Length = IrpSp->Parameters.Read.Length;

		if (Irp->MdlAddress)
		{
			OldBuffer = MmGetSystemAddressForMdl(Irp->MdlAddress);
		}
		else
		{
			Mdl = IoAllocateMdl(Irp->UserBuffer, Length, FALSE, FALSE, NULL);
			if (Mdl == NULL)
			{
				KdPrint(("sfilter!SfRead: IoAllocateMdl failed\n"));
				Status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

	        __try
	        {
	            MmProbeAndLockPages(Mdl, Irp->RequestorMode, IoWriteAccess);
	        }
	        __except (EXCEPTION_EXECUTE_HANDLER)
	        {
				KdPrint(("sfilter!SfRead: STATUS_INVALID_USER_BUFFER\n"));
				IoFreeMdl(Mdl);
				Status = STATUS_INVALID_USER_BUFFER;
				break;
	        }

	        OldBuffer = MmGetSystemAddressForMdl(Mdl);
		}

		if (!OldBuffer)
		{
			KdPrint(("sfilter!SfRead: STATUS_INVALID_PARAMETER\n"));
			if (Mdl)
			{
				MmUnlockPages(Mdl);
				IoFreeMdl(Mdl);
			}
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		CompletionCtx = ExAllocateFromNPagedLookasideList(&gReadWriteCompletionCtxLookAsideList);
		if (!CompletionCtx)
		{
			KdPrint(("sfilter!SfRead: STATUS_INSUFFICIENT_RESOURCES\n"));
			if (Mdl)
			{
				MmUnlockPages(Mdl);
				IoFreeMdl(Mdl);
			}
			Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		MyBuffer = ExAllocatePoolWithTag(NonPagedPool, IrpSp->Parameters.Write.Length, SFLT_POOL_TAG);
		if (!MyBuffer)
		{
			KdPrint(("sfilter!SfRead: STATUS_INSUFFICIENT_RESOURCES\n"));
			if (Mdl)
			{
				MmUnlockPages(Mdl);
				IoFreeMdl(Mdl);
			}
			ExFreePool(CompletionCtx);
			Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		CompletionCtx->OldMdl = Irp->MdlAddress;
		CompletionCtx->OldUserBuffer = Irp->UserBuffer;
		CompletionCtx->OldSystemBuffer = Irp->AssociatedIrp.SystemBuffer;

		CompletionCtx->MdlForUserBuffer = Mdl;

		CompletionCtx->OldBuffer = OldBuffer;
		CompletionCtx->MyBuffer = MyBuffer;
		CompletionCtx->Length = Length;

		Irp->MdlAddress = IoAllocateMdl(MyBuffer, IrpSp->Parameters.Write.Length, FALSE, TRUE, NULL);
		if (!Irp->MdlAddress)
		{
			KdPrint(("sfilter!SfRead: STATUS_INSUFFICIENT_RESOURCES\n"));
			Irp->MdlAddress = CompletionCtx->OldMdl;
			if (Mdl)
			{
				MmUnlockPages(Mdl);
				IoFreeMdl(Mdl);
			}
			ExFreePool(CompletionCtx);
			ExFreePool(MyBuffer);
			Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		KdPrint(("sfilter!SfRead: Decrypt %ws\n", FileCtxPtr->Name));
		
		MmBuildMdlForNonPagedPool(Irp->MdlAddress);
		Irp->UserBuffer = MmGetMdlVirtualAddress(Irp->MdlAddress);

		IoCopyCurrentIrpStackLocationToNext(Irp);
		IoSetCompletionRoutine(Irp, SfReadCompletion, CompletionCtx, TRUE, TRUE,TRUE);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);

	} while (FALSE);

	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	
	return Status;
}

NTSTATUS
SfReadCompletion(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context
	)
{
	PREAD_WRITE_COMPLETION_CONTEXT CompletionCtx = (PREAD_WRITE_COMPLETION_CONTEXT) Context;
	ULONG Offset = 0;

	ULONG i=0;
  struct rc4_state *s;
  UCHAR buffer[1024];	
	UCHAR keys[8]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
	
	
	
	UNREFERENCED_PARAMETER(DeviceObject);	
	
	if (Irp->PendingReturned)
		IoMarkIrpPending(Irp);

	IoFreeMdl(Irp->MdlAddress);

	Irp->MdlAddress = CompletionCtx->OldMdl;
	Irp->UserBuffer = CompletionCtx->OldUserBuffer;
	Irp->AssociatedIrp.SystemBuffer = CompletionCtx->OldSystemBuffer;
	
  
	//decrypt: aida@tom.com 2006-03-04
	
  s =ExAllocatePool(NonPagedPool, sizeof(struct rc4_state)); 
  rc4_setup(s, keys,8);
	for (Offset = 0; Offset < CompletionCtx->Length; Offset+=1024)
	{
        i=(int)memcpy(buffer,((PCHAR)CompletionCtx->MyBuffer)+Offset,1024); 
        rc4_crypt( s, buffer, i);
        i=(int)memcpy( ((PCHAR)CompletionCtx->OldBuffer)+Offset,buffer, i);	
	}
  /* tooflat
	for (Offset = 0; Offset < CompletionCtx->Length; Offset+=1024)
	{
		((PUCHAR) CompletionCtx->OldBuffer)[Offset] = ~((PUCHAR) CompletionCtx->MyBuffer)[Offset];
        	
	}
  */
	if (CompletionCtx->MdlForUserBuffer)
	{
		MmUnlockPages(CompletionCtx->MdlForUserBuffer);
		IoFreeMdl(CompletionCtx->MdlForUserBuffer);
	}

	ExFreePoolWithTag(CompletionCtx->MyBuffer, SFLT_POOL_TAG);
	ExFreeToNPagedLookasideList(&gReadWriteCompletionCtxLookAsideList, CompletionCtx);

	return STATUS_SUCCESS;
}

NTSTATUS
SfWrite(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	PSFILTER_DEVICE_EXTENSION DevExt = (PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	FILE_CONTEXT_HDR FileCtxHdr;
	PFILE_CONTEXT FileCtxPtr = NULL;
	PREAD_WRITE_COMPLETION_CONTEXT CompletionCtx = NULL;
	PVOID OldBuffer = NULL;
	PVOID MyBuffer = NULL;
	ULONG Length = 0;
	ULONG Offset = 0;
	NTSTATUS Status = STATUS_SUCCESS;
	
	ULONG i=0;
  struct rc4_state *s;
  unsigned char buffer[1024];
	UCHAR keys[8]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};

	PAGED_CODE();

	// 
	// Sfilter doesn't allow handles to its control device object to be created,
	// therefore, no other operation should be able to come through.
	// 
	ASSERT(!IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));
	ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

	// 
	// We only care about volume filter device object
	// 
	if (!DevExt->StorageStackDeviceObject)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}

#if DBG
	if (DevExt->DriveLetter != DEBUG_VOLUME)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}
#endif

	if (!(Irp->Flags & (IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)))
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}

	ExAcquireFastMutex(&DevExt->FsCtxTableMutex);
	
	FileCtxHdr.FsContext = FileObject->FsContext;
	FileCtxPtr = RtlLookupElementGenericTable(&DevExt->FsCtxTable, &FileCtxHdr);
	
	ExReleaseFastMutex(&DevExt->FsCtxTableMutex);
	
	if (!FileCtxPtr || !FileCtxPtr->EncryptOnWrite)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}

	do
	{
		Length = IrpSp->Parameters.Write.Length;

		if (Irp->MdlAddress)
		{
			OldBuffer = MmGetSystemAddressForMdl(Irp->MdlAddress);
		}
		else
		{
			PMDL Mdl;

			Mdl = IoAllocateMdl(Irp->UserBuffer, Length, FALSE, FALSE, NULL);
			if (Mdl == NULL)
			{
				KdPrint(("sfilter!SfWrite: IoAllocateMdl failed\n"));
				Status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

	        __try
	        {
	            MmProbeAndLockPages(Mdl, Irp->RequestorMode, IoReadAccess);
	        }
	        __except (EXCEPTION_EXECUTE_HANDLER)
	        {
				KdPrint(("sfilter!SfWrite: STATUS_INVALID_USER_BUFFER\n"));
				IoFreeMdl(Mdl);
				Status = STATUS_INVALID_USER_BUFFER;
				break;
	        }

			MmUnlockPages(Mdl);
			IoFreeMdl(Mdl);

	        OldBuffer = Irp->UserBuffer;
		}

		if (!OldBuffer)
		{
			KdPrint(("sfilter!SfWrite: STATUS_INVALID_PARAMETER\n"));
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		CompletionCtx = ExAllocateFromNPagedLookasideList(&gReadWriteCompletionCtxLookAsideList);
		if (!CompletionCtx)
		{
			KdPrint(("sfilter!SfWrite: STATUS_INSUFFICIENT_RESOURCES\n"));
			Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		MyBuffer = ExAllocatePoolWithTag(NonPagedPool, IrpSp->Parameters.Write.Length, SFLT_POOL_TAG);
		if (!MyBuffer)
		{
			KdPrint(("sfilter!SfWrite: STATUS_INSUFFICIENT_RESOURCES\n"));
			ExFreePool(CompletionCtx);
			Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		CompletionCtx->OldMdl = Irp->MdlAddress;
		CompletionCtx->OldUserBuffer = Irp->UserBuffer;
		CompletionCtx->OldSystemBuffer = Irp->AssociatedIrp.SystemBuffer;

		CompletionCtx->MdlForUserBuffer = NULL;

		CompletionCtx->OldBuffer = OldBuffer;
		CompletionCtx->MyBuffer = MyBuffer;
		CompletionCtx->Length = Length;

		Irp->MdlAddress = IoAllocateMdl(MyBuffer, IrpSp->Parameters.Write.Length, FALSE, TRUE, NULL);
		if (!Irp->MdlAddress)
		{
			KdPrint(("sfilter!SfWrite: STATUS_INSUFFICIENT_RESOURCES\n"));
			Irp->MdlAddress = CompletionCtx->OldMdl;
			ExFreePool(CompletionCtx);
			ExFreePool(MyBuffer);
			Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		KdPrint(("sfilter!SfWrite: Encrypt %ws\n", FileCtxPtr->Name));
		
  //decrypt: aida@tom.com 2006-03-04
  s =ExAllocatePool(NonPagedPool, sizeof(struct rc4_state));
  rc4_setup( s, keys,8);
	for (Offset = 0; Offset < Length; Offset+=1024)
	{
        i=(int)memcpy(buffer,((PCHAR)OldBuffer)+Offset,1024); 
        rc4_crypt( s, buffer, i);
        i=(int)memcpy( ((PCHAR)MyBuffer)+Offset,buffer, i);	 
	}		
		/* tooflat
		for (Offset = 0; Offset < Length; ++Offset)
		{
			((PUCHAR) MyBuffer)[Offset] = ~((PUCHAR) OldBuffer)[Offset];
		}
    */
		MmBuildMdlForNonPagedPool(Irp->MdlAddress);
		Irp->UserBuffer = MmGetMdlVirtualAddress(Irp->MdlAddress);

		IoCopyCurrentIrpStackLocationToNext(Irp);
		IoSetCompletionRoutine(Irp, SfWriteCompletion, CompletionCtx, TRUE, TRUE,TRUE);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);

	} while (FALSE);

	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	
	return Status;
}

NTSTATUS
SfWriteCompletion(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context
	)
{
	PREAD_WRITE_COMPLETION_CONTEXT CompletionCtx = (PREAD_WRITE_COMPLETION_CONTEXT) Context;
	ULONG Offset = 0;

	UNREFERENCED_PARAMETER(DeviceObject);

	if (Irp->PendingReturned)
		IoMarkIrpPending(Irp);

	IoFreeMdl(Irp->MdlAddress);

	Irp->MdlAddress = CompletionCtx->OldMdl;
	Irp->UserBuffer = CompletionCtx->OldUserBuffer;
	Irp->AssociatedIrp.SystemBuffer = CompletionCtx->OldSystemBuffer;

	ExFreePoolWithTag(CompletionCtx->MyBuffer, SFLT_POOL_TAG);
	ExFreeToNPagedLookasideList(&gReadWriteCompletionCtxLookAsideList, CompletionCtx);

	return STATUS_SUCCESS;
}

NTSTATUS
SfDirectoryControl(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	PSFILTER_DEVICE_EXTENSION DevExt = (PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	NTSTATUS Status = STATUS_SUCCESS;
	PFILE_BOTH_DIR_INFORMATION DirInfo = NULL;
	PFILE_BOTH_DIR_INFORMATION PreDirInfo = NULL;
	ULONG Length = 0;
	ULONG NewLength = 0;
	ULONG Offset = 0;
	ULONG CurPos = 0; 

	// 
	// We only care about volume filter device object
	// 
	if (!DevExt->StorageStackDeviceObject)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}

#if DBG
	if (DevExt->DriveLetter != DEBUG_VOLUME)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}
#endif

	if (IrpSp->MinorFunction != IRP_MN_QUERY_DIRECTORY)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}

	if (IrpSp->Parameters.QueryDirectory.FileInformationClass != FileBothDirectoryInformation)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}
	
	Status = SfForwardIrpSyncronously(DevExt->AttachedToDeviceObject, Irp);

	while (TRUE)
	{
		if (!NT_SUCCESS(Status))
			break;

		Length = IrpSp->Parameters.QueryDirectory.Length;
		NewLength = Length;
		CurPos = 0;
		DirInfo = (PFILE_BOTH_DIR_INFORMATION) Irp->UserBuffer;
		PreDirInfo = DirInfo;

		// 
		// There is no entry, so just complete the request
		// 
		if (Length == 0)
			break;

		// 
		// Sanity check
		// 
		if ((!DirInfo) || (DirInfo->NextEntryOffset > Length))
			break;
		
		do
		{
			Offset = DirInfo->NextEntryOffset;

			if ((DirInfo->FileNameLength > SF_ENCRYPT_POSTFIX_LENGTH * sizeof(WCHAR)) &&
				(_wcsnicmp(&DirInfo->FileName[DirInfo->FileNameLength / sizeof(WCHAR) - SF_ENCRYPT_POSTFIX_LENGTH],
					SF_ENCRYPT_POSTFIX, SF_ENCRYPT_POSTFIX_LENGTH) == 0))
			{
				if (0 == Offset) // the last one
				{
					PreDirInfo->NextEntryOffset = 0;
					NewLength = CurPos;
				}
				else
				{
					if (PreDirInfo != DirInfo)
					{
						PreDirInfo->NextEntryOffset += DirInfo->NextEntryOffset;
						DirInfo = (PFILE_BOTH_DIR_INFORMATION) ((PUCHAR) DirInfo + Offset);
					}
					else
					{
						RtlMoveMemory((PUCHAR) DirInfo,(PUCHAR) DirInfo + Offset, Length - CurPos - Offset); 
						NewLength -= Offset; 
					}
				}
 			}
 			else
 			{
				CurPos += Offset; 
				PreDirInfo = DirInfo;
				DirInfo = (PFILE_BOTH_DIR_INFORMATION) ((PUCHAR) DirInfo + Offset);
			}
		} while (0 != Offset);

		if (0 == NewLength) // All entry is filtered
		{
			Status = SfForwardIrpSyncronously(DevExt->AttachedToDeviceObject, Irp);

			// 
			// If no entry returned, just complete the request,
			// else we must continue to filter
			// 
			if (0 == Irp->IoStatus.Information)
				break;
		}
		else
		{
			Irp->IoStatus.Information = NewLength;
			break;
		}

		// continue to filter
	}

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

NTSTATUS
SfSetInformation(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	PSFILTER_DEVICE_EXTENSION DevExt = (PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	PFILE_RENAME_INFORMATION RenameInfo = (PFILE_RENAME_INFORMATION) Irp->AssociatedIrp.SystemBuffer;
	FILE_CONTEXT_HDR FileCtxHdr;
	PFILE_CONTEXT FileCtxPtr = NULL;
	PWSTR FileName = NULL;
	PWSTR TargetFileName = NULL;
	BOOLEAN DecryptOnRead = FALSE;
	BOOLEAN EncryptOnWrite = FALSE;
	BOOLEAN IsEncryptFlagExist = FALSE;
	BOOLEAN IsTargetNeedEncrypt = FALSE;
	NTSTATUS Status = STATUS_SUCCESS;
	NTSTATUS LocalStatus = STATUS_SUCCESS;

	// 
	// We only care about volume filter device object
	// 
	if (!DevExt->StorageStackDeviceObject)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}

#if DBG
	if (DevExt->DriveLetter != DEBUG_VOLUME)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}
#endif

	if (IrpSp->Parameters.QueryFile.FileInformationClass != FileRenameInformation) 
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}

	FileCtxHdr.FsContext = FileObject->FsContext;

	ExAcquireFastMutex(&DevExt->FsCtxTableMutex);	
	FileCtxPtr = RtlLookupElementGenericTable(&DevExt->FsCtxTable, &FileCtxHdr);
	ExReleaseFastMutex(&DevExt->FsCtxTableMutex);
	
	if (!FileCtxPtr)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}

	do
	{
 		FileName = ExAllocateFromPagedLookasideList(&gFileNameLookAsideList);
		if (!FileName)
		{
			KdPrint(("sfilter!SfSetInformation: STATUS_INSUFFICIENT_RESOURCES\n"));
			Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		TargetFileName = ExAllocateFromPagedLookasideList(&gFileNameLookAsideList);
		if (!TargetFileName)
		{
			KdPrint(("sfilter!SfSetInformation: STATUS_INSUFFICIENT_RESOURCES\n"));
			Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		RtlZeroMemory(FileName, MAX_PATH * sizeof(WCHAR));
		RtlZeroMemory(TargetFileName, MAX_PATH * sizeof(WCHAR));

		wcscpy(FileName, FileCtxPtr->Name);

		if (!IrpSp->Parameters.SetFile.FileObject)
		{
			//
			// Simple rename
			//
			WCHAR OldChar;
			PWCHAR Ptr = NULL;
			
			Ptr = wcsrchr(FileName, L'\\');
			if (!Ptr)
			{
				KdPrint(("sfilter!SfSetInformation: Invalid STATUS_INVALID_PARAMETER\n"));
				Status = STATUS_INVALID_PARAMETER;
				break;
			}

			++Ptr;
			OldChar = *Ptr;
			*Ptr = L'\0';
			wcscpy(TargetFileName, FileName);
			*Ptr = OldChar;
			wcsncat(
				TargetFileName,
				RenameInfo->FileName,
				RenameInfo->FileNameLength / sizeof(WCHAR)
				);
		}
		else
		{
			if (RenameInfo->RootDirectory != NULL)
			{
				//
				// Relative rename
				//
				WCHAR OldChar;
				PWCHAR Ptr = NULL;
				
				Ptr = wcsrchr(FileName, L'\\');
				if (!Ptr)
				{
					KdPrint(("sfilter!SfSetInformation: Invalid STATUS_INVALID_PARAMETER\n"));
					Status = STATUS_INVALID_PARAMETER;
					break;
				}

				++Ptr;
				OldChar = *Ptr;
				*Ptr = L'\0';
				wcscpy(TargetFileName, FileName);
				*Ptr = OldChar;
				wcsncat(
					TargetFileName,
					RenameInfo->FileName,
					RenameInfo->FileNameLength / sizeof(WCHAR)
					);
			}
			else
			{
				//
				// Full qualified rename, \??\ , \DosDevices\
				//
				if (0 == _wcsnicmp(&RenameInfo->FileName[0], L"\\??\\", 4))
				{
					wcsncpy(TargetFileName,
						&RenameInfo->FileName[4],
						(RenameInfo->FileNameLength / sizeof(WCHAR)) - 4
						);
				}
				else if (0 == _wcsnicmp(&RenameInfo->FileName[0], L"\\DosDevices\\", 12))
				{
					wcsncpy(TargetFileName,
						&RenameInfo->FileName[11],
						(RenameInfo->FileNameLength / sizeof(WCHAR)) - 12
						);
				}
				else
				{
					KdPrint(("sfilter!SfSetInformation: RenameInfo->FileName = %ws\n", RenameInfo->FileName));
					ASSERT(FALSE);
				}				
			}
		}

		KdPrint(("sfilter!SfSetInformation: %ws -> %ws\n", FileCtxPtr->Name, TargetFileName));

		KeWaitForSingleObject(&FileCtxPtr->Event, Executive, KernelMode, FALSE, NULL);

		Status = SfForwardIrpSyncronously(DevExt->AttachedToDeviceObject, Irp);
		if (!NT_SUCCESS(Status))
		{
			KeSetEvent(&FileCtxPtr->Event, IO_NO_INCREMENT, FALSE);
			KdPrint(("sfilter!SfSetInformation: SfForwardIrpSyncronously failed, return %x\n", Status));
			break;
		}

		do
		{
			wcscpy(FileCtxPtr->Name, TargetFileName);
		
			LocalStatus = SfSetFileEncrypted(DeviceObject, FileName, FALSE, NULL, 0);
			if (!NT_SUCCESS(LocalStatus))
			{
				KdPrint(("sfilter!SfPostSetInformationWorker: SfSetFileEncrypted(%ws, FALSE) failed, return %x\n", FileName, LocalStatus));
				ASSERT(FALSE);
				break;
			}
		
			LocalStatus = SfIsFileNeedEncrypt(DeviceObject, TargetFileName, &IsTargetNeedEncrypt);
			if (!NT_SUCCESS(LocalStatus))
			{
				KdPrint(("sfilter!SfPostSetInformationWorker: SfIsFileNeedEncrypt failed, return %x\n", LocalStatus));
				ASSERT(FALSE);
				break;
			}
		
			DecryptOnRead = FileCtxPtr->DecryptOnRead;
			EncryptOnWrite = FileCtxPtr->EncryptOnWrite;
			IsEncryptFlagExist = FileCtxPtr->EncryptFlagExist;
		
			FileCtxPtr->NeedEncrypt = IsTargetNeedEncrypt;
		
			if (EncryptOnWrite && !IsTargetNeedEncrypt)
			{
				FileCtxPtr->EncryptOnWrite = FALSE;

				KdPrint(("sfilter!SfPostSetInformationWorker: Decrypt %ws\n", FileCtxPtr->Name));
				LocalStatus = SfUpdateFileByFileObject(DeviceObject, FileObject);
				if (NT_SUCCESS(LocalStatus))
				{
					FileCtxPtr->DecryptOnRead = FALSE;
					FileCtxPtr->EncryptFlagExist = FALSE;
				}
				else
				{
					KdPrint(("sfilter!SfPostSetInformationWorker: SfUpdateFileByFileObject failed, return %x\n", LocalStatus));
					ASSERT(FALSE);
				}
			}
			else if (!EncryptOnWrite && IsTargetNeedEncrypt)
			{
				FileCtxPtr->EncryptOnWrite = TRUE;
				
				KdPrint(("sfilter!SfPostSetInformationWorker: Encrypt %ws\n", FileCtxPtr->Name));
				LocalStatus = SfUpdateFileByFileObject(DeviceObject, FileObject);
				if (NT_SUCCESS(LocalStatus))
				{
					FileCtxPtr->DecryptOnRead = TRUE;
		
					LocalStatus = SfSetFileEncrypted(DeviceObject, TargetFileName, TRUE, FileCtxPtr->EncryptExtData, sizeof(FileCtxPtr->EncryptExtData));
					if (NT_SUCCESS(LocalStatus))
						FileCtxPtr->EncryptFlagExist = TRUE;
					else
					{
						KdPrint(("sfilter!SfPostSetInformationWorker: SfSetFileEncrypted(%ws, TRUE) failed, return %x\n", TargetFileName, LocalStatus));
						ASSERT(FALSE);
					}
				}
				else
				{
					KdPrint(("sfilter!SfPostSetInformationWorker: SfUpdateFileByFileObject failed, return %x\n", LocalStatus));
					ASSERT(FALSE);
				}
			}
			else if (IsTargetNeedEncrypt)
			{
				LocalStatus = SfSetFileEncrypted(DeviceObject, TargetFileName, TRUE, FileCtxPtr->EncryptExtData, sizeof(FileCtxPtr->EncryptExtData));
				if (NT_SUCCESS(LocalStatus))
					FileCtxPtr->EncryptFlagExist = TRUE;
				else
				{
					KdPrint(("sfilter!SfPostSetInformationWorker: SfSetFileEncrypted(%ws, TRUE) failed, return %x\n", TargetFileName, LocalStatus));
					ASSERT(FALSE);
				}
			}
		} while (FALSE);

		KeSetEvent(&FileCtxPtr->Event, IO_NO_INCREMENT, FALSE);

	} while (FALSE);
	
	if (FileName)
		ExFreeToPagedLookasideList(&gFileNameLookAsideList, FileName);

	if (TargetFileName)
		ExFreeToPagedLookasideList(&gFileNameLookAsideList, TargetFileName);

	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

NTSTATUS
SfFsControl(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
/*++

Routine Description:

	This routine is invoked whenever an I/O Request Packet (IRP) w/a major
	function code of IRP_MJ_FILE_SYSTEM_CONTROL is encountered.  For most
	IRPs of this type, the packet is simply passed through.  However, for
	some requests, special processing is required.

Arguments:

	DeviceObject - Pointer to the device object for this driver.

	Irp - Pointer to the request packet representing the I/O request.

Return Value:

	The function value is the status of the operation.

--*/
{
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

	PAGED_CODE();

	// 
	// Sfilter doesn't allow handles to its control device object to be created,
	// therefore, no other operation should be able to come through.
	//  
	ASSERT(!IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject));
	ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

	// 
	// Process the minor function code.
	// 
	switch (irpSp->MinorFunction)
	{
		case IRP_MN_MOUNT_VOLUME:

			return SfFsControlMountVolume(DeviceObject, Irp);

		case IRP_MN_LOAD_FILE_SYSTEM:

			return SfFsControlLoadFileSystem(DeviceObject, Irp);
	}		

	// 
	// Pass all other file system control requests through.
	// 
	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp);
}

NTSTATUS
SfFsControlCompletion(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context
	)
/*++

Routine Description:

	This routine is invoked for the completion of an FsControl request.  It
	signals an event used to re-sync back to the dispatch routine.

Arguments:

	DeviceObject - Pointer to this driver's device object that was attached to
			the file system device object

	Irp - Pointer to the IRP that was just completed.

	Context - Pointer to the event to signal

--*/

{
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));
	ASSERT(Context != NULL);

#if WINVER >= 0x0501
	if (IS_WINDOWSXP_OR_LATER())
	{
		// 
		// On Windows XP or later, the context passed in will be an event
		// to signal.
		// 
		KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
	}
	else
	{
#endif
		// 
		// For Windows 2000, if we are not at passive level, we should 
		// queue this work to a worker thread using the workitem that is in 
		// Context.
		// 
		if (KeGetCurrentIrql() > PASSIVE_LEVEL)
		{
			// 
			// We are not at passive level, but we need to be to do our work,
			// so queue off to the worker thread.
			//		  
			ExQueueWorkItem((PWORK_QUEUE_ITEM) Context, DelayedWorkQueue);
			
		}
		else
		{
			PWORK_QUEUE_ITEM WorkItem = Context;

			// 
			// We are already at passive level, so we will just call our 
			// worker routine directly.
			// 
			(WorkItem->WorkerRoutine)(WorkItem->Parameter);
		}

#if WINVER >= 0x0501
	}
#endif

	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
SfFsControlMountVolume(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
/*++

Routine Description:

	This processes a MOUNT VOLUME request.

	NOTE:  The device object in the MountVolume parameters points
			to the top of the storage stack and should not be used.

Arguments:

	DeviceObject - Pointer to the device object for this driver.

	Irp - Pointer to the request packet representing the I/O request.

Return Value:

	The status of the operation.

--*/
{
	PSFILTER_DEVICE_EXTENSION DevExt = DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	PDEVICE_OBJECT NewDeviceObject;
	PDEVICE_OBJECT StorageStackDeviceObject;
	PSFILTER_DEVICE_EXTENSION NewDevExt;
	NTSTATUS Status;
	BOOLEAN IsShadowCopyVolume;
	PFSCTRL_COMPLETION_CONTEXT CompletionContext;

	PAGED_CODE();

	ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));
	ASSERT(IS_DESIRED_DEVICE_TYPE(DeviceObject->DeviceType));

	// 
	// Get the real device object (also known as the storage stack device
	// object or the disk device object) pointed to by the vpb parameter
	// because this vpb may be changed by the underlying file system.
	// Both FAT and CDFS may change the VPB address if the volume being
	// mounted is one they recognize from a previous mount.
	// 
	StorageStackDeviceObject = IrpSp->Parameters.MountVolume.Vpb->RealDevice;

	// 
	// Determine if this is a shadow copy volume.  If so don't attach to it.
	// NOTE:  There is no reason sfilter shouldn't attach to these volumes,
	//		this is simply a sample of how to not attach if you don't want
	//		to
	// 
	Status = SfIsShadowCopyVolume(StorageStackDeviceObject, 
		&IsShadowCopyVolume
		);
	if (NT_SUCCESS(Status) && IsShadowCopyVolume)
	{
		// 
		// Go to the next driver
		// 
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}

	// 
	// This is a mount request.  Create a device object that can be
	// attached to the file system's volume device object if this request
	// is successful.  We allocate this memory now since we can not return
	// an error in the completion routine.  
	// 
	// Since the device object we are going to attach to has not yet been
	// created (it is created by the base file system) we are going to use
	// the type of the file system control device object.  We are assuming
	// that the file system control device object will have the same type
	// as the volume device objects associated with it.
	// 

	Status = IoCreateDevice(gSFilterDriverObject,
		 sizeof(SFILTER_DEVICE_EXTENSION),
		 NULL,
		 DeviceObject->DeviceType,
		 0,
		 FALSE,
		 &NewDeviceObject
		 );
	if (!NT_SUCCESS(Status))
	{
		// 
		// If we can not attach to the volume, then don't allow the volume
		// to be mounted.
		// 
		KdPrint(("SFilter!SfFsControlMountVolume: Error creating volume device object, Status=%08x\n", Status));

		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = Status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return Status;
	}

	// 
	// We need to save the RealDevice object pointed to by the vpb
	// parameter because this vpb may be changed by the underlying
	// file system.  Both FAT and CDFS may change the VPB address if
	// the volume being mounted is one they recognize from a previous
	// mount.
	// 
	NewDevExt = NewDeviceObject->DeviceExtension;

	RtlZeroMemory(NewDevExt, sizeof(SFILTER_DEVICE_EXTENSION));
	
	NewDevExt->StorageStackDeviceObject = StorageStackDeviceObject;

	// 
	// Get the name of this device
	// 
	RtlInitEmptyUnicodeString(&NewDevExt->DeviceName, 
		NewDevExt->DeviceNameBuffer, 
		sizeof(NewDevExt->DeviceNameBuffer)
		);

	SfGetObjectName(StorageStackDeviceObject, 
		&NewDevExt->DeviceName
		);

	//
	// Initialize some useful variables
	//
	ExInitializeFastMutex(&NewDevExt->FsCtxTableMutex);
	RtlInitializeGenericTable(&NewDevExt->FsCtxTable,
		SfGenericCompareRoutine,
		SfGenericAllocateRoutine,
		SfGenericFreeRoutine,
		NULL
		);

	// 
	// VERSION NOTE:
	// 
	// On Windows 2000, we cannot simply synchronize back to the dispatch
	// routine to do our post-mount processing.  We need to do this work at
	// passive level, so we will queue that work to a worker thread from
	// the completion routine.
	// 
	// For Windows XP and later, we can safely synchronize back to the dispatch
	// routine.  The code below shows both methods.  Admittedly, the code
	// would be simplified if you chose to only use one method or the other, 
	// but you should be able to easily adapt this for your needs.
	// 

#if WINVER >= 0x0501
	if (IS_WINDOWSXP_OR_LATER())
	{
		KEVENT WaitEvent;

		KeInitializeEvent(&WaitEvent, NotificationEvent, FALSE);

		IoCopyCurrentIrpStackLocationToNext(Irp);

		IoSetCompletionRoutine(Irp,
			SfFsControlCompletion,
			&WaitEvent,	 // context parameter
			TRUE,
			TRUE,
			TRUE
			);

		Status = IoCallDriver(DevExt->AttachedToDeviceObject, Irp);

		// 
		// Wait for the operation to complete
		// 
		if (STATUS_PENDING == Status)
		{
			Status = KeWaitForSingleObject(&WaitEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL
				);
			ASSERT(STATUS_SUCCESS == Status);
		}

		// 
		// Verify the IoCompleteRequest was called
		// 
		ASSERT(KeReadStateEvent(&WaitEvent) ||
			!NT_SUCCESS(Irp->IoStatus.Status));

		Status = SfFsControlMountVolumeComplete(
			DeviceObject,
			Irp,
			NewDeviceObject
			);
	}
	else
	{
#endif	
		// 
		// Initialize our completion routine
		// 
		CompletionContext = ExAllocatePoolWithTag(
			NonPagedPool, 
			sizeof(FSCTRL_COMPLETION_CONTEXT),
			SFLT_POOL_TAG
			);
		if (CompletionContext == NULL)
		{
			// 
			// If we cannot allocate our completion context, we will just pass 
			// through the operation.  If your filter must be present for data
			// access to this volume, you should consider failing the operation
			// if memory cannot be allocated here.
			// 

			IoSkipCurrentIrpStackLocation(Irp);
			Status = IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
		}
		else
		{
			ExInitializeWorkItem(&CompletionContext->WorkItem, 
				SfFsControlMountVolumeCompleteWorker, 
				CompletionContext
				);

			CompletionContext->DeviceObject = DeviceObject;
			CompletionContext->Irp = Irp;
			CompletionContext->NewDeviceObject = NewDeviceObject;

			IoCopyCurrentIrpStackLocationToNext(Irp);

			IoSetCompletionRoutine(Irp,
				SfFsControlCompletion,
				&CompletionContext->WorkItem, // context parameter
				TRUE,
				TRUE,
				TRUE
				);

			// 
			// Call the driver
			// 
			Status = IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
		}
#if WINVER >= 0x0501		
	}
#endif

	return Status;
}

VOID
SfFsControlMountVolumeCompleteWorker(
	IN PFSCTRL_COMPLETION_CONTEXT Context
	)
/*++

Routine Description:

	The worker thread routine that will call our common routine to do the
	post-MountVolume work.

Arguments:

	Context - The context passed to this worker thread.
	
Return Value:

	None.

--*/
{
	ASSERT(Context != NULL);

	SfFsControlMountVolumeComplete(
		Context->DeviceObject,
		Context->Irp,
		Context->NewDeviceObject
		);

	ExFreePoolWithTag(Context, SFLT_POOL_TAG);
}

NTSTATUS
SfFsControlMountVolumeComplete(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PDEVICE_OBJECT NewDeviceObject
	)
/*++

Routine Description:

	This does the post-Mount work and must be done at PASSIVE_LEVEL.

Arguments:

	DeviceObject - The device object for this operation,

	Irp - The IRP for this operation that we will complete once we are finished
		with it.
	
Return Value:

	Returns the status of the mount operation.

--*/
{
	PVPB Vpb;
	PSFILTER_DEVICE_EXTENSION NewDevExt;
	PIO_STACK_LOCATION IrpSp;
	PDEVICE_OBJECT AttachedDeviceObject;
	NTSTATUS Status;

	PAGED_CODE();

	NewDevExt = NewDeviceObject->DeviceExtension;
	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	
	// 
	// Get the correct VPB from the real device object saved in our
	// device extension.  We do this because the VPB in the IRP stack
	// may not be the correct VPB when we get here.  The underlying
	// file system may change VPBs if it detects a volume it has
	// mounted previously.
	// 
	Vpb = NewDevExt->StorageStackDeviceObject->Vpb;

	// 
	// Display a message when we detect that the VPB for the given
	// device object has changed.
	// 
	if (Vpb != IrpSp->Parameters.MountVolume.Vpb)
	{
		SF_LOG_PRINT(SFDEBUG_DISPLAY_ATTACHMENT_NAMES,
					  ("SFilter!SfFsControlMountVolume:			  VPB in IRP stack changed	%p IRPVPB=%p VPB=%p\n",
						Vpb->DeviceObject,
						IrpSp->Parameters.MountVolume.Vpb,
						Vpb));
	}

	// 
	// See if the mount was successful.
	// 
	if (NT_SUCCESS(Irp->IoStatus.Status))
	{
		// 
		// Acquire lock so we can atomically test if we area already attached
		// and if not, then attach.  This prevents a double attach race
		// condition.
		// 
		ExAcquireFastMutex(&gSfilterAttachLock);

		// 
		// The mount succeeded.  If we are not already attached, attach to the
		// device object.  Note: one reason we could already be attached is
		// if the underlying file system revived a previous mount.
		// 
		if (!SfIsAttachedToDevice(Vpb->DeviceObject, &AttachedDeviceObject))
		{
			// 
			// Attach to the new mounted volume.  The file system device
			// object that was just mounted is pointed to by the VPB.
			// 
			Status = SfAttachToMountedDevice(Vpb->DeviceObject, NewDeviceObject);
			if (!NT_SUCCESS(Status))
			{ 
				// 
				// The attachment failed, cleanup.  Since we are in the
				// post-mount phase, we can not fail this operation.
				// We simply won't be attached.  The only reason this should
				// ever happen at this point is if somebody already started
				// dismounting the volume therefore not attaching should
				// not be a problem.
				// 
				SfCleanupMountedDevice(NewDeviceObject);
				IoDeleteDevice(NewDeviceObject);
			}

			ASSERT(NULL == AttachedDeviceObject);
		}
		else
		{
			// 
			// We were already attached, handle it
			// 
			SF_LOG_PRINT(SFDEBUG_DISPLAY_ATTACHMENT_NAMES,
						  ("SFilter!SfFsControlMountVolume				Mount volume failure for	%p \"%wZ\", already attached\n", 
							((PSFILTER_DEVICE_EXTENSION)AttachedDeviceObject->DeviceExtension)->AttachedToDeviceObject,
							&NewDevExt->DeviceName));

			// 
			// Cleanup and delete the device object we created
			// 
			SfCleanupMountedDevice(NewDeviceObject);
			IoDeleteDevice(NewDeviceObject);

			// 
			// Dereference the returned attached device object
			// 
			ObDereferenceObject(AttachedDeviceObject);
		}

		// 
		// Release the lock
		// 
		ExReleaseFastMutex(&gSfilterAttachLock);
	}
	else
	{
		// 
		// The mount request failed, handle it.
		// 
		SF_LOG_PRINT(SFDEBUG_DISPLAY_ATTACHMENT_NAMES,
					  ("SFilter!SfFsControlMountVolume:			  Mount volume failure for	%p \"%wZ\", Status=%08x\n", 
						DeviceObject,
						&NewDevExt->DeviceName, 
						Irp->IoStatus.Status));

		// 
		// Cleanup and delete the device object we created
		// 
		SfCleanupMountedDevice(NewDeviceObject);
		IoDeleteDevice(NewDeviceObject);
	}

	// 
	// Complete the request.  
	// NOTE:  We must save the Status before completing because after
	//		completing the IRP we can not longer access it (it might be
	//		freed).
	// 
	Status = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

NTSTATUS
SfFsControlLoadFileSystem(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
/*++

Routine Description:

	This routine is invoked whenever an I/O Request Packet (IRP) w/a major
	function code of IRP_MJ_FILE_SYSTEM_CONTROL is encountered.  For most
	IRPs of this type, the packet is simply passed through.  However, for
	some requests, special processing is required.

Arguments:

	DeviceObject - Pointer to the device object for this driver.

	Irp - Pointer to the request packet representing the I/O request.

Return Value:

	The function value is the status of the operation.

--*/
{
	PSFILTER_DEVICE_EXTENSION DevExt = DeviceObject->DeviceExtension;
	NTSTATUS Status;
	PFSCTRL_COMPLETION_CONTEXT CompletionContext;

	PAGED_CODE();

	// 
	// This is a "load file system" request being sent to a file system
	// recognizer device object.  This IRP_MN code is only sent to 
	// file system recognizers.
	// 
	// NOTE:  Since we no longer are attaching to the standard Microsoft file
	//		system recognizers we will normally never execute this code.
	//		However, there might be 3rd party file systems which have their
	//		own recognizer which may still trigger this IRP.
	// 

	// 
	// VERSION NOTE:
	// 
	// On Windows 2000, we cannot simply synchronize back to the dispatch
	// routine to do our post-load filesystem processing.  We need to do 
	// this work at passive level, so we will queue that work to a worker 
	// thread from the completion routine.
	// 
	// For Windows XP and later, we can safely synchronize back to the dispatch
	// routine.  The code below shows both methods.  Admittedly, the code
	// would be simplified if you chose to only use one method or the other, 
	// but you should be able to easily adapt this for your needs.
	// 

#if WINVER >= 0x0501
	if (IS_WINDOWSXP_OR_LATER())
	{
		KEVENT WaitEvent;
		
		KeInitializeEvent(&WaitEvent, NotificationEvent, FALSE);

		IoCopyCurrentIrpStackLocationToNext(Irp);
		
		IoSetCompletionRoutine(
			Irp,
			SfFsControlCompletion,
			&WaitEvent,	 // context parameter
			TRUE,
			TRUE,
			TRUE
			);

		// 
		// Detach from the recognizer's device object
		// 
		IoDetachDevice(DevExt->AttachedToDeviceObject);

		Status = IoCallDriver(DevExt->AttachedToDeviceObject, Irp);

		// 
		// Wait for the operation to complete
		// 
		if (STATUS_PENDING == Status)
		{
			Status = KeWaitForSingleObject(
				&WaitEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL
				);
			ASSERT(STATUS_SUCCESS == Status);
		}

		if (!NT_SUCCESS(Status))
		{
			// 
			// The load was not successful.  Simply reattach to the recognizer
			// driver in case it ever figures out how to get the driver loaded
			// on a subsequent call.  There is not a lot we can do if this
			// reattach fails.
			// 			
			SfAttachDeviceToDeviceStack(DeviceObject, 
				DevExt->AttachedToDeviceObject,
				&DevExt->AttachedToDeviceObject);

			ASSERT(DevExt->AttachedToDeviceObject != NULL);
		}

		// 
		// Verify the IoCompleteRequest was called
		// 
		ASSERT(KeReadStateEvent(&WaitEvent) ||
			!NT_SUCCESS(Irp->IoStatus.Status));

		Status = SfFsControlLoadFileSystemComplete(DeviceObject, Irp);
	}
	else
	{
#endif	
		// 
		// Set a completion routine so we can delete the device object when
		// the load is complete.
		// 
		CompletionContext = ExAllocatePoolWithTag(
			NonPagedPool, 
			sizeof(FSCTRL_COMPLETION_CONTEXT),
			SFLT_POOL_TAG
			);
		if (CompletionContext == NULL)
		{
			// 
			// If we cannot allocate our completion context, we will just pass 
			// through the operation.  If your filter must be present for data
			// access to this volume, you should consider failing the operation
			// if memory cannot be allocated here.
			// 

			IoSkipCurrentIrpStackLocation(Irp);
			Status = IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
		}
		else
		{
			ExInitializeWorkItem(&CompletionContext->WorkItem,
				SfFsControlLoadFileSystemCompleteWorker,
				CompletionContext
				);
			CompletionContext->DeviceObject = DeviceObject;
			CompletionContext->Irp = Irp;
			CompletionContext->NewDeviceObject = NULL;
			  
			IoCopyCurrentIrpStackLocationToNext(Irp);

			IoSetCompletionRoutine(
				Irp,
				SfFsControlCompletion,
				CompletionContext,
				TRUE,
				TRUE,
				TRUE);

			// 
			// Detach from the file system recognizer device object.
			// 
			IoDetachDevice(DevExt->AttachedToDeviceObject);

			// 
			// Call the driver
			// 
			Status = IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
		}
#if WINVER >= 0x0501		
	}
#endif	
	
	return Status;
}

VOID
SfFsControlLoadFileSystemCompleteWorker(
	IN PFSCTRL_COMPLETION_CONTEXT Context
	)
/*++

Routine Description:

	The worker thread routine that will call our common routine to do the
	post-LoadFileSystem work.

Arguments:

	Context - The context passed to this worker thread.
	
Return Value:

	None.

--*/
{
	ASSERT(NULL != Context);

	SfFsControlLoadFileSystemComplete(Context->DeviceObject, Context->Irp);
	ExFreePoolWithTag(Context, SFLT_POOL_TAG);
}

NTSTATUS
SfFsControlLoadFileSystemComplete(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
/*++

Routine Description:

	This does the post-LoadFileSystem work and must be done as PASSIVE_LEVEL.

Arguments:

	DeviceObject - The device object for this operation,

	Irp - The IRP for this operation that we will complete once we are finished
		with it.
	
Return Value:

	Returns the status of the load file system operation.

--*/
{
	PSFILTER_DEVICE_EXTENSION DevExt;
	NTSTATUS Status;

	PAGED_CODE();

	DevExt = DeviceObject->DeviceExtension;
	
	// 
	// Display the name if requested
	// 
	SF_LOG_PRINT(SFDEBUG_DISPLAY_ATTACHMENT_NAMES,
		("SFilter!SfFsControlLoadFileSystem:			Detaching from recognizer  %p \"%wZ\", Status=%08x\n", 
		DeviceObject,
		&DevExt->DeviceName,
		Irp->IoStatus.Status)
		);

	// 
	// Check Status of the operation
	// 
	if (!NT_SUCCESS(Irp->IoStatus.Status) && 
		(Irp->IoStatus.Status != STATUS_IMAGE_ALREADY_LOADED))
	{
		// 
		// The load was not successful.  Simply reattach to the recognizer
		// driver in case it ever figures out how to get the driver loaded
		// on a subsequent call.  There is not a lot we can do if this
		// reattach fails.
		// 

		SfAttachDeviceToDeviceStack(DeviceObject, 
			DevExt->AttachedToDeviceObject,
			&DevExt->AttachedToDeviceObject);

		ASSERT(DevExt->AttachedToDeviceObject != NULL);

	}
	else
	{
		// 
		// The load was successful, so cleanup this device and delete the 
		// Device object
		// 
		SfCleanupMountedDevice(DeviceObject);
		IoDeleteDevice(DeviceObject);
	}

	// 
	// Continue processing the operation
	// 
	Status = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
// 
//					FastIO Handling routines
// 
// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /

BOOLEAN
SfFastIoCheckIfPossible(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN ULONG Length,
	IN BOOLEAN Wait,
	IN ULONG LockKey,
	IN BOOLEAN CheckForReadOperation,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for checking to see
	whether fast I/O is possible for this file.

	This function simply invokes the file system's corresponding routine, or
	returns FALSE if the file system does not implement the function.

Arguments:

	FileObject - Pointer to the file object to be operated on.

	FileOffset - Byte offset in the file for the operation.

	Length - Length of the operation to be performed.

	Wait - Indicates whether or not the caller is willing to wait if the
		appropriate locks, etc. cannot be acquired

	LockKey - Provides the caller's key for file locks.

	CheckForReadOperation - Indicates whether the caller is checking for a
		read (TRUE) or a write operation.

	IoStatus - Pointer to a variable to receive the I/O status of the
		operation.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE based on whether or not fast I/O
	is possible for this file.

--*/
{
	PDEVICE_OBJECT NextDeviceObject;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE();

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		NextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(NextDeviceObject);

		FastIoDispatch = NextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatch, FastIoCheckIfPossible))
		{
			return (FastIoDispatch->FastIoCheckIfPossible)(
				FileObject,
				FileOffset,
				Length,
				Wait,
				LockKey,
				CheckForReadOperation,
				IoStatus,
				NextDeviceObject
				);
		}
	}

	return FALSE;
}

BOOLEAN
SfFastIoRead(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN ULONG Length,
	IN BOOLEAN Wait,
	IN ULONG LockKey,
	OUT PVOID Buffer,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for reading from a
	file.

	This function simply invokes the file system's corresponding routine, or
	returns FALSE if the file system does not implement the function.

Arguments:

	FileObject - Pointer to the file object to be read.

	FileOffset - Byte offset in the file of the read.

	Length - Length of the read operation to be performed.

	Wait - Indicates whether or not the caller is willing to wait if the
		appropriate locks, etc. cannot be acquired

	LockKey - Provides the caller's key for file locks.

	Buffer - Pointer to the caller's buffer to receive the data read.

	IoStatus - Pointer to a variable to receive the I/O status of the
		operation.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE based on whether or not fast I/O
	is possible for this file.

--*/
{
	PDEVICE_OBJECT NextDeviceObject;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE();

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		NextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(NextDeviceObject);

		FastIoDispatch = NextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatch, FastIoRead))
		{
			return (FastIoDispatch->FastIoRead)(
				FileObject,
				FileOffset,
				Length,
				Wait,
				LockKey,
				Buffer,
				IoStatus,
				NextDeviceObject
				);
		}
	}
	return FALSE;
}

BOOLEAN
SfFastIoWrite(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN ULONG Length,
	IN BOOLEAN Wait,
	IN ULONG LockKey,
	IN PVOID Buffer,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for writing to a
	file.

	This function simply invokes the file system's corresponding routine, or
	returns FALSE if the file system does not implement the function.

Arguments:

	FileObject - Pointer to the file object to be written.

	FileOffset - Byte offset in the file of the write operation.

	Length - Length of the write operation to be performed.

	Wait - Indicates whether or not the caller is willing to wait if the
		appropriate locks, etc. cannot be acquired

	LockKey - Provides the caller's key for file locks.

	Buffer - Pointer to the caller's buffer that contains the data to be
		written.

	IoStatus - Pointer to a variable to receive the I/O status of the
		operation.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE based on whether or not fast I/O
	is possible for this file.

--*/

{
	PDEVICE_OBJECT NextDeviceObject;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE();
	
	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		NextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(NextDeviceObject);

		FastIoDispatch = NextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatch, FastIoWrite))
		{
			return (FastIoDispatch->FastIoWrite)(
				FileObject,
				FileOffset,
				Length,
				Wait,
				LockKey,
				Buffer,
				IoStatus,
				NextDeviceObject
				);
		}
	}

	return FALSE;
}

BOOLEAN
SfFastIoQueryBasicInfo(
	IN PFILE_OBJECT FileObject,
	IN BOOLEAN Wait,
	OUT PFILE_BASIC_INFORMATION Buffer,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for querying basic
	information about the file.

	This function simply invokes the file system's corresponding routine, or
	returns FALSE if the file system does not implement the function.

Arguments:

	FileObject - Pointer to the file object to be queried.

	Wait - Indicates whether or not the caller is willing to wait if the
		appropriate locks, etc. cannot be acquired

	Buffer - Pointer to the caller's buffer to receive the information about
		the file.

	IoStatus - Pointer to a variable to receive the I/O status of the
		operation.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE based on whether or not fast I/O
	is possible for this file.

--*/
{
	PDEVICE_OBJECT NextDeviceObject;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE();

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		NextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(NextDeviceObject);

		FastIoDispatch = NextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatch, FastIoQueryBasicInfo))
		{
			return (FastIoDispatch->FastIoQueryBasicInfo)(
				FileObject,
				Wait,
				Buffer,
				IoStatus,
				NextDeviceObject
				);
		}
	}

	return FALSE;
}

BOOLEAN
SfFastIoQueryStandardInfo(
	IN PFILE_OBJECT FileObject,
	IN BOOLEAN Wait,
	OUT PFILE_STANDARD_INFORMATION Buffer,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for querying standard
	information about the file.

	This function simply invokes the file system's corresponding routine, or
	returns FALSE if the file system does not implement the function.

Arguments:

	FileObject - Pointer to the file object to be queried.

	Wait - Indicates whether or not the caller is willing to wait if the
		appropriate locks, etc. cannot be acquired

	Buffer - Pointer to the caller's buffer to receive the information about
		the file.

	IoStatus - Pointer to a variable to receive the I/O status of the
		operation.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE based on whether or not fast I/O
	is possible for this file.

--*/
{
	PDEVICE_OBJECT NextDeviceObject;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE();

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		NextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(NextDeviceObject);

		FastIoDispatch = NextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatch, FastIoQueryStandardInfo))
		{
			return (FastIoDispatch->FastIoQueryStandardInfo)(
				FileObject,
				Wait,
				Buffer,
				IoStatus,
				NextDeviceObject
				);
		}
	}

	return FALSE;
}

BOOLEAN
SfFastIoLock(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN PLARGE_INTEGER Length,
	PEPROCESS ProcessId,
	ULONG Key,
	BOOLEAN FailImmediately,
	BOOLEAN ExclusiveLock,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for locking a byte
	range within a file.

	This function simply invokes the file system's corresponding routine, or
	returns FALSE if the file system does not implement the function.

Arguments:

	FileObject - Pointer to the file object to be locked.

	FileOffset - Starting byte offset from the base of the file to be locked.

	Length - Length of the byte range to be locked.

	ProcessId - ID of the process requesting the file lock.

	Key - Lock key to associate with the file lock.

	FailImmediately - Indicates whether or not the lock request is to fail
		if it cannot be immediately be granted.

	ExclusiveLock - Indicates whether the lock to be taken is exclusive (TRUE)
		or shared.

	IoStatus - Pointer to a variable to receive the I/O status of the
		operation.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE based on whether or not fast I/O
	is possible for this file.

--*/

{
	PDEVICE_OBJECT NextDeviceObject;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE();

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		NextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(NextDeviceObject);

		FastIoDispatch = NextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatch, FastIoLock))
		{
			return (FastIoDispatch->FastIoLock)(
				FileObject,
				FileOffset,
				Length,
				ProcessId,
				Key,
				FailImmediately,
				ExclusiveLock,
				IoStatus,
				NextDeviceObject
				);
		}
	}

	return FALSE;
}


BOOLEAN
SfFastIoUnlockSingle(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN PLARGE_INTEGER Length,
	PEPROCESS ProcessId,
	ULONG Key,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for unlocking a byte
	range within a file.

	This function simply invokes the file system's corresponding routine, or
	returns FALSE if the file system does not implement the function.

Arguments:

	FileObject - Pointer to the file object to be unlocked.

	FileOffset - Starting byte offset from the base of the file to be
		unlocked.

	Length - Length of the byte range to be unlocked.

	ProcessId - ID of the process requesting the unlock operation.

	Key - Lock key associated with the file lock.

	IoStatus - Pointer to a variable to receive the I/O status of the
		operation.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE based on whether or not fast I/O
	is possible for this file.

--*/

{
	PDEVICE_OBJECT NextDeviceObject;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE();

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		NextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(NextDeviceObject);

		FastIoDispatch = NextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatch, FastIoUnlockSingle))
		{
			return (FastIoDispatch->FastIoUnlockSingle)(
				FileObject,
				FileOffset,
				Length,
				ProcessId,
				Key,
				IoStatus,
				NextDeviceObject
				);
		}
	}

	return FALSE;
}

BOOLEAN
SfFastIoUnlockAll(
	IN PFILE_OBJECT FileObject,
	PEPROCESS ProcessId,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for unlocking all
	locks within a file.

	This function simply invokes the file system's corresponding routine, or
	returns FALSE if the file system does not implement the function.

Arguments:

	FileObject - Pointer to the file object to be unlocked.

	ProcessId - ID of the process requesting the unlock operation.

	IoStatus - Pointer to a variable to receive the I/O status of the
		operation.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE based on whether or not fast I/O
	is possible for this file.

--*/
{
	PDEVICE_OBJECT NextDeviceObject;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE();

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		NextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		if (NextDeviceObject)
		{
			FastIoDispatch = NextDeviceObject->DriverObject->FastIoDispatch;
			if (VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatch, FastIoUnlockAll))
			{
				return (FastIoDispatch->FastIoUnlockAll)(
					FileObject,
					ProcessId,
					IoStatus,
					NextDeviceObject
					);
			}
		}
	}

	return FALSE;
}

BOOLEAN
SfFastIoUnlockAllByKey(
	IN PFILE_OBJECT FileObject,
	PVOID ProcessId,
	ULONG Key,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for unlocking all
	locks within a file based on a specified key.

	This function simply invokes the file system's corresponding routine, or
	returns FALSE if the file system does not implement the function.

Arguments:

	FileObject - Pointer to the file object to be unlocked.

	ProcessId - ID of the process requesting the unlock operation.

	Key - Lock key associated with the locks on the file to be released.

	IoStatus - Pointer to a variable to receive the I/O status of the
		operation.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE based on whether or not fast I/O
	is possible for this file.

--*/
{
	PDEVICE_OBJECT NextDeviceObject;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE();

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		NextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(NextDeviceObject);

		FastIoDispatch = NextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatch, FastIoUnlockAllByKey))
		{
			return (FastIoDispatch->FastIoUnlockAllByKey)(
				FileObject,
				ProcessId,
				Key,
				IoStatus,
				NextDeviceObject
				);
		}
	}

	return FALSE;
}

BOOLEAN
SfFastIoDeviceControl(
	IN PFILE_OBJECT FileObject,
	IN BOOLEAN Wait,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	IN ULONG IoControlCode,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for device I/O control
	operations on a file.

	This function simply invokes the file system's corresponding routine, or
	returns FALSE if the file system does not implement the function.

Arguments:

	FileObject - Pointer to the file object representing the device to be
		serviced.

	Wait - Indicates whether or not the caller is willing to wait if the
		appropriate locks, etc. cannot be acquired

	InputBuffer - Optional pointer to a buffer to be passed into the driver.

	InputBufferLength - Length of the optional InputBuffer, if one was
		specified.

	OutputBuffer - Optional pointer to a buffer to receive data from the
		driver.

	OutputBufferLength - Length of the optional OutputBuffer, if one was
		specified.

	IoControlCode - I/O control code indicating the operation to be performed
		on the device.

	IoStatus - Pointer to a variable to receive the I/O status of the
		operation.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE based on whether or not fast I/O
	is possible for this file.

--*/
{
	PDEVICE_OBJECT NextDeviceObject;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE();

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		NextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(NextDeviceObject);

		FastIoDispatch = NextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatch, FastIoDeviceControl))
		{
			return (FastIoDispatch->FastIoDeviceControl)(
				FileObject,
				Wait,
				InputBuffer,
				InputBufferLength,
				OutputBuffer,
				OutputBufferLength,
				IoControlCode,
				IoStatus,
				NextDeviceObject
				);
		}
	}

	return FALSE;
}

VOID
SfFastIoDetachDevice(
	IN PDEVICE_OBJECT SourceDevice,
	IN PDEVICE_OBJECT TargetDevice
	)
/*++

Routine Description:

	This routine is invoked on the fast path to detach from a device that
	is being deleted.  This occurs when this driver has attached to a file
	system volume device object, and then, for some reason, the file system
	decides to delete that device (it is being dismounted, it was dismounted
	at some point in the past and its last reference has just gone away, etc.)

Arguments:

	SourceDevice - Pointer to my device object, which is attached
		to the file system's volume device object.

	TargetDevice - Pointer to the file system's volume device object.

Return Value:

	None

--*/
{
	PSFILTER_DEVICE_EXTENSION DevExt;

	PAGED_CODE();

	ASSERT(IS_MY_DEVICE_OBJECT(SourceDevice));

	DevExt = SourceDevice->DeviceExtension;

	// 
	// Display name information
	// 
	SF_LOG_PRINT(SFDEBUG_DISPLAY_ATTACHMENT_NAMES,
				  ("SFilter!SfFastIoDetachDevice:				Detaching from volume	  %p \"%wZ\"\n",
					TargetDevice,
					&DevExt->DeviceName));

	// 
	// Detach from the file system's volume device object.
	// 
	SfCleanupMountedDevice(SourceDevice);
	IoDetachDevice(TargetDevice);
	IoDeleteDevice(SourceDevice);
}

BOOLEAN
SfFastIoQueryNetworkOpenInfo(
	IN PFILE_OBJECT FileObject,
	IN BOOLEAN Wait,
	OUT PFILE_NETWORK_OPEN_INFORMATION Buffer,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for querying network
	information about a file.

	This function simply invokes the file system's corresponding routine, or
	returns FALSE if the file system does not implement the function.

Arguments:

	FileObject - Pointer to the file object to be queried.

	Wait - Indicates whether or not the caller can handle the file system
		having to wait and tie up the current thread.

	Buffer - Pointer to a buffer to receive the network information about the
		file.

	IoStatus - Pointer to a variable to receive the final status of the query
		operation.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE based on whether or not fast I/O
	is possible for this file.

--*/

{
	PDEVICE_OBJECT NextDeviceObject;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE();

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		NextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(NextDeviceObject);

		FastIoDispatch = NextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatch, FastIoQueryNetworkOpenInfo))
		{
			return (FastIoDispatch->FastIoQueryNetworkOpenInfo)(
				FileObject,
				Wait,
				Buffer,
				IoStatus,
				NextDeviceObject
				);
		}
	}

	return FALSE;
}

BOOLEAN
SfFastIoMdlRead(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN ULONG Length,
	IN ULONG LockKey,
	OUT PMDL *MdlChain,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for reading a file
	using MDLs as buffers.

	This function simply invokes the file system's corresponding routine, or
	returns FALSE if the file system does not implement the function.

Arguments:

	FileObject - Pointer to the file object that is to be read.

	FileOffset - Supplies the offset into the file to begin the read operation.

	Length - Specifies the number of bytes to be read from the file.

	LockKey - The key to be used in byte range lock checks.

	MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
		chain built to describe the data read.

	IoStatus - Variable to receive the final status of the read operation.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE based on whether or not fast I/O
	is possible for this file.

--*/
{
	PDEVICE_OBJECT NextDeviceObject;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE();

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		NextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(NextDeviceObject);

		FastIoDispatch = NextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatch, MdlRead))
		{
			return (FastIoDispatch->MdlRead)(
				FileObject,
				FileOffset,
				Length,
				LockKey,
				MdlChain,
				IoStatus,
				NextDeviceObject
				);
		}
	}

	return FALSE;
}

BOOLEAN
SfFastIoMdlReadComplete(
	IN PFILE_OBJECT FileObject,
	IN PMDL MdlChain,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for completing an
	MDL read operation.

	This function simply invokes the file system's corresponding routine, if
	it has one.  It should be the case that this routine is invoked only if
	the MdlRead function is supported by the underlying file system, and
	therefore this function will also be supported, but this is not assumed
	by this driver.

Arguments:

	FileObject - Pointer to the file object to complete the MDL read upon.

	MdlChain - Pointer to the MDL chain used to perform the read operation.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE, depending on whether or not it is
	possible to invoke this function on the fast I/O path.

--*/
{
	PDEVICE_OBJECT NextDeviceObject;
	PFAST_IO_DISPATCH FastIoDispatch;

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		NextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(NextDeviceObject);

		FastIoDispatch = NextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatch, MdlReadComplete))
		{
			return (FastIoDispatch->MdlReadComplete)(
				FileObject,
				MdlChain,
				NextDeviceObject
				);
		}
	}

	return FALSE;
}

BOOLEAN
SfFastIoPrepareMdlWrite(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN ULONG Length,
	IN ULONG LockKey,
	OUT PMDL *MdlChain,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for preparing for an
	MDL write operation.

	This function simply invokes the file system's corresponding routine, or
	returns FALSE if the file system does not implement the function.

Arguments:

	FileObject - Pointer to the file object that will be written.

	FileOffset - Supplies the offset into the file to begin the write operation.

	Length - Specifies the number of bytes to be write to the file.

	LockKey - The key to be used in byte range lock checks.

	MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
		chain built to describe the data written.

	IoStatus - Variable to receive the final status of the write operation.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE based on whether or not fast I/O
	is possible for this file.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	PAGED_CODE();

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		nextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(nextDeviceObject);

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, PrepareMdlWrite))
		{
			return (fastIoDispatch->PrepareMdlWrite)(
				FileObject,
				FileOffset,
				Length,
				LockKey,
				MdlChain,
				IoStatus,
				nextDeviceObject
				);
		}
	}

	return FALSE;
}

BOOLEAN
SfFastIoMdlWriteComplete(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN PMDL MdlChain,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for completing an
	MDL write operation.

	This function simply invokes the file system's corresponding routine, if
	it has one.  It should be the case that this routine is invoked only if
	the PrepareMdlWrite function is supported by the underlying file system,
	and therefore this function will also be supported, but this is not
	assumed by this driver.

Arguments:

	FileObject - Pointer to the file object to complete the MDL write upon.

	FileOffset - Supplies the file offset at which the write took place.

	MdlChain - Pointer to the MDL chain used to perform the write operation.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE, depending on whether or not it is
	possible to invoke this function on the fast I/O path.

--*/
{
	PDEVICE_OBJECT NextDeviceObject;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE();

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		NextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(NextDeviceObject);

		FastIoDispatch = NextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatch, MdlWriteComplete))
		{
			return (FastIoDispatch->MdlWriteComplete)(
				FileObject,
				FileOffset,
				MdlChain,
				NextDeviceObject
				);
		}
	}

	return FALSE;
}


/*********************************************************************************
		UNIMPLEMENTED FAST IO ROUTINES
		
		The following four Fast IO routines are for compression on the wire
		which is not yet implemented in NT.  
		
		NOTE:  It is highly recommended that you include these routines (which
				do a pass-through call) so your filter will not need to be
				modified in the future when this functionality is implemented in
				the OS.
		
		FastIoReadCompressed, FastIoWriteCompressed, 
		FastIoMdlReadCompleteCompressed, FastIoMdlWriteCompleteCompressed
**********************************************************************************/

BOOLEAN
SfFastIoReadCompressed(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN ULONG Length,
	IN ULONG LockKey,
	OUT PVOID Buffer,
	OUT PMDL *MdlChain,
	OUT PIO_STATUS_BLOCK IoStatus,
	OUT struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
	IN ULONG CompressedDataInfoLength,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for reading compressed
	data from a file.

	This function simply invokes the file system's corresponding routine, or
	returns FALSE if the file system does not implement the function.

Arguments:

	FileObject - Pointer to the file object that will be read.

	FileOffset - Supplies the offset into the file to begin the read operation.

	Length - Specifies the number of bytes to be read from the file.

	LockKey - The key to be used in byte range lock checks.

	Buffer - Pointer to a buffer to receive the compressed data read.

	MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
		chain built to describe the data read.

	IoStatus - Variable to receive the final status of the read operation.

	CompressedDataInfo - A buffer to receive the description of the compressed
		data.

	CompressedDataInfoLength - Specifies the size of the buffer described by
		the CompressedDataInfo parameter.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE based on whether or not fast I/O
	is possible for this file.

--*/
{
	PDEVICE_OBJECT NextDeviceObject;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE();

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		NextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(NextDeviceObject);

		FastIoDispatch = NextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatch, FastIoReadCompressed))
		{
			return (FastIoDispatch->FastIoReadCompressed)(
				FileObject,
				FileOffset,
				Length,
				LockKey,
				Buffer,
				MdlChain,
				IoStatus,
				CompressedDataInfo,
				CompressedDataInfoLength,
				NextDeviceObject
				);
		}
	}

	return FALSE;
}

BOOLEAN
SfFastIoWriteCompressed(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN ULONG Length,
	IN ULONG LockKey,
	IN PVOID Buffer,
	OUT PMDL *MdlChain,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
	IN ULONG CompressedDataInfoLength,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for writing compressed
	data to a file.

	This function simply invokes the file system's corresponding routine, or
	returns FALSE if the file system does not implement the function.

Arguments:

	FileObject - Pointer to the file object that will be written.

	FileOffset - Supplies the offset into the file to begin the write operation.

	Length - Specifies the number of bytes to be write to the file.

	LockKey - The key to be used in byte range lock checks.

	Buffer - Pointer to the buffer containing the data to be written.

	MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
		chain built to describe the data written.

	IoStatus - Variable to receive the final status of the write operation.

	CompressedDataInfo - A buffer to containing the description of the
		compressed data.

	CompressedDataInfoLength - Specifies the size of the buffer described by
		the CompressedDataInfo parameter.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE based on whether or not fast I/O
	is possible for this file.

--*/

{
	PDEVICE_OBJECT NextDeviceObject;
	PFAST_IO_DISPATCH FastIoDispatch;

	PAGED_CODE();

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		NextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(NextDeviceObject);

		FastIoDispatch = NextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatch, FastIoWriteCompressed))
		{
			return (FastIoDispatch->FastIoWriteCompressed)(
				FileObject,
				FileOffset,
				Length,
				LockKey,
				Buffer,
				MdlChain,
				IoStatus,
				CompressedDataInfo,
				CompressedDataInfoLength,
				NextDeviceObject
				);
		}
	}
	return FALSE;
}

BOOLEAN
SfFastIoMdlReadCompleteCompressed(
	IN PFILE_OBJECT FileObject,
	IN PMDL MdlChain,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for completing an
	MDL read compressed operation.

	This function simply invokes the file system's corresponding routine, if
	it has one.  It should be the case that this routine is invoked only if
	the read compressed function is supported by the underlying file system,
	and therefore this function will also be supported, but this is not assumed
	by this driver.

Arguments:

	FileObject - Pointer to the file object to complete the compressed read
		upon.

	MdlChain - Pointer to the MDL chain used to perform the read operation.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE, depending on whether or not it is
	possible to invoke this function on the fast I/O path.

--*/
{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		nextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(nextDeviceObject);

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, MdlReadCompleteCompressed))
		{
			return (fastIoDispatch->MdlReadCompleteCompressed)(
				FileObject,
				MdlChain,
				nextDeviceObject
				);
		}
	}
	return FALSE;
}

BOOLEAN
SfFastIoMdlWriteCompleteCompressed(
	IN PFILE_OBJECT FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN PMDL MdlChain,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for completing a
	write compressed operation.

	This function simply invokes the file system's corresponding routine, if
	it has one.  It should be the case that this routine is invoked only if
	the write compressed function is supported by the underlying file system,
	and therefore this function will also be supported, but this is not assumed
	by this driver.

Arguments:

	FileObject - Pointer to the file object to complete the compressed write
		upon.

	FileOffset - Supplies the file offset at which the file write operation
		began.

	MdlChain - Pointer to the MDL chain used to perform the write operation.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE, depending on whether or not it is
	possible to invoke this function on the fast I/O path.

--*/
{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		nextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(nextDeviceObject);

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, MdlWriteCompleteCompressed))
		{
			return (fastIoDispatch->MdlWriteCompleteCompressed)(
				FileObject,
				FileOffset,
				MdlChain,
				nextDeviceObject
				);
		}
	}

	return FALSE;
}

BOOLEAN
SfFastIoQueryOpen(
	IN PIRP Irp,
	OUT PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This routine is the fast I/O "pass through" routine for opening a file
	and returning network information for it.

	This function simply invokes the file system's corresponding routine, or
	returns FALSE if the file system does not implement the function.

Arguments:

	Irp - Pointer to a create IRP that represents this open operation.  It is
		to be used by the file system for common open/create code, but not
		actually completed.

	NetworkInformation - A buffer to receive the information required by the
		network about the file being opened.

	DeviceObject - Pointer to this driver's device object, the device on
		which the operation is to occur.

Return Value:

	The function value is TRUE or FALSE based on whether or not fast I/O
	is possible for this file.

--*/

{
	PDEVICE_OBJECT NextDeviceObject;
	PFAST_IO_DISPATCH FastIoDispatch;
	BOOLEAN Result;

	PAGED_CODE();

	if (DeviceObject->DeviceExtension)
	{
		ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

		// 
		// Pass through logic for this type of Fast I/O
		// 
		NextDeviceObject = ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;
		ASSERT(NextDeviceObject);

		FastIoDispatch = NextDeviceObject->DriverObject->FastIoDispatch;
		if (VALID_FAST_IO_DISPATCH_HANDLER(FastIoDispatch, FastIoQueryOpen))
		{
			PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

			// 
			// Before calling the next filter, we must make sure their device
			// object is in the current stack entry for the given IRP
			// 
			IrpSp->DeviceObject = NextDeviceObject;

			Result = (FastIoDispatch->FastIoQueryOpen)(
				Irp,
				NetworkInformation,
				NextDeviceObject
				);

			// 
			// Always restore the IRP back to our device object
			// 
			IrpSp->DeviceObject = DeviceObject;
			return Result;
		}
	}

	return FALSE;
}

#if WINVER >= 0x0501 /* See comment in DriverEntry */
// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
// 
//				FSFilter callback handling routines
// 
// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /

NTSTATUS
SfPreFsFilterPassThrough(
	IN PFS_FILTER_CALLBACK_DATA Data,
	OUT PVOID *CompletionContext
	)
/*++

Routine Description:

	This routine is the FS Filter pre-operation "pass through" routine.

Arguments:

	Data - The FS_FILTER_CALLBACK_DATA structure containing the information
		about this operation.
		
	CompletionContext - A context set by this operation that will be passed
		to the corresponding SfPostFsFilterOperation call.
		
Return Value:

	Returns STATUS_SUCCESS if the operation can continue or an appropriate
	error code if the operation should fail.

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(CompletionContext);

	ASSERT(IS_MY_DEVICE_OBJECT(Data->DeviceObject));

	return STATUS_SUCCESS;
}

VOID
SfPostFsFilterPassThrough(
	IN PFS_FILTER_CALLBACK_DATA Data,
	IN NTSTATUS OperationStatus,
	IN PVOID CompletionContext
	)
/*++

Routine Description:

	This routine is the FS Filter post-operation "pass through" routine.

Arguments:

	Data - The FS_FILTER_CALLBACK_DATA structure containing the information
		about this operation.
		
	OperationStatus - The status of this operation.		
	
	CompletionContext - A context that was set in the pre-operation 
		callback by this driver.
		
Return Value:

	None.
	
--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(OperationStatus);
	UNREFERENCED_PARAMETER(CompletionContext);

	ASSERT(IS_MY_DEVICE_OBJECT(Data->DeviceObject));
}
#endif

// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
// 
//				Support routines
// 
// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /

NTSTATUS
SfAttachDeviceToDeviceStack(
	IN PDEVICE_OBJECT SourceDevice,
	IN PDEVICE_OBJECT TargetDevice,
	IN OUT PDEVICE_OBJECT *AttachedToDeviceObject
	)
/*++

Routine Description:

	This routine attaches the SourceDevice to the TargetDevice's stack and
	returns the device object SourceDevice was directly attached to in 
	AttachedToDeviceObject.  Note that the SourceDevice does not necessarily
	get attached directly to TargetDevice.  The SourceDevice will get attached
	to the top of the stack of which TargetDevice is a member.

	VERSION NOTE:

	In Windows XP, a new API was introduced to close a rare timing window that 
	can cause IOs to start being sent to a device before its 
	AttachedToDeviceObject is set in its device extension.  This is possible
	if a filter is attaching to a device stack while the system is actively
	processing IOs.  The new API closes this timing window by setting the
	device extension field that holds the AttachedToDeviceObject while holding
	the IO Manager's lock that protects the device stack.

	A sufficient work around for earlier versions of the OS is to set the
	AttachedToDeviceObject to the device object that the SourceDevice is most
	likely to attach to.  While it is possible that another filter will attach
	in between the SourceDevice and TargetDevice, this will prevent the
	system from bug checking if the SourceDevice receives IOs before the 
	AttachedToDeviceObject is correctly set.

	For a driver built in the Windows 2000 build environment, we will always 
	use the work-around code to attach.  For a driver that is built in the 
	Windows XP or later build environments (therefore you are building a 
	multiversion driver), we will determine which method of attachment to use 
	based on which APIs are available.

Arguments:

	SourceDevice - The device object to be attached to the stack.

	TargetDevice - The device that we currently think is the top of the stack
		to which SourceDevice should be attached.

	AttachedToDeviceObject - This is set to the device object to which 
		SourceDevice is attached if the attach is successful.
		
Return Value:

	Return STATUS_SUCCESS if the device is successfully attached.  If 
	TargetDevice represents a stack to which devices can no longer be attached,
	STATUS_NO_SUCH_DEVICE is returned.

--*/
{

	PAGED_CODE();

#if WINVER >= 0x0501

	if (IS_WINDOWSXP_OR_LATER()) {

		ASSERT(NULL != gSfDynamicFunctions.AttachDeviceToDeviceStackSafe);
		return (gSfDynamicFunctions.AttachDeviceToDeviceStackSafe)(SourceDevice,
																	TargetDevice,
																	AttachedToDeviceObject);

	} else {

		ASSERT(NULL == gSfDynamicFunctions.AttachDeviceToDeviceStackSafe);
#endif

		*AttachedToDeviceObject = TargetDevice;
		*AttachedToDeviceObject = IoAttachDeviceToDeviceStack(SourceDevice,
																TargetDevice);

		if (*AttachedToDeviceObject == NULL) {

			return STATUS_NO_SUCH_DEVICE;
		}

		return STATUS_SUCCESS;

#if WINVER >= 0x0501
	}
#endif
}
	
NTSTATUS
SfAttachToFileSystemDevice(
	IN PDEVICE_OBJECT DeviceObject,
	IN PUNICODE_STRING DeviceName
	)
/*++

Routine Description:

	This will attach to the given file system device object.  We attach to
	these devices so we will know when new volumes are mounted.

Arguments:

	DeviceObject - The device to attach to

	Name - An already initialized unicode string used to retrieve names.
			This is passed in to reduce the number of strings buffers on
			the stack.

Return Value:

	Status of the operation

--*/
{
	PDEVICE_OBJECT NewDeviceObject;
	PSFILTER_DEVICE_EXTENSION DevExt;
	UNICODE_STRING FsRecName;
	NTSTATUS Status;
	UNICODE_STRING FsName;
	WCHAR TempNameBuffer[MAX_DEVNAME_LENGTH];

	PAGED_CODE();

	// 
	// See if this is a file system type we care about.  If not, return.
	// 
	if (!IS_DESIRED_DEVICE_TYPE(DeviceObject->DeviceType))
		return STATUS_SUCCESS;

	// 
	// always init NAME buffer
	// 
	RtlInitEmptyUnicodeString(&FsName,
		TempNameBuffer,
		sizeof(TempNameBuffer)
		);

	// 
	// See if we should attach to the standard file system recognizer device
	// or not
	// 
	if (!FlagOn(SfDebug,SFDEBUG_ATTACH_TO_FSRECOGNIZER))
	{
		// 
		// See if this is one of the standard Microsoft file system recognizer
		// devices (see if this device is in the FS_REC driver).  If so skip
		// it.  We no longer attach to file system recognizer devices, we
		// simply wait for the real file system driver to load.
		// 
		RtlInitUnicodeString(&FsRecName, L"\\FileSystem\\Fs_Rec");

		SfGetObjectName(DeviceObject->DriverObject, &FsName);

		if (RtlCompareUnicodeString(&FsName, &FsRecName, TRUE) == 0)
			return STATUS_SUCCESS;
	}

	// 
	// We want to attach to this file system.  Create a new device object we
	// can attach with.
	// 
	Status = IoCreateDevice(gSFilterDriverObject,
		 sizeof(SFILTER_DEVICE_EXTENSION),
		 NULL,
		 DeviceObject->DeviceType,
		 0,
		 FALSE,
		 &NewDeviceObject
		 );
	if (!NT_SUCCESS(Status))
		return Status;

	// 
	// Propagate flags from Device Object we are trying to attach to.
	// Note that we do this before the actual attachment to make sure
	// the flags are properly set once we are attached (since an IRP
	// can come in immediately after attachment but before the flags would
	// be set).
	// 

	if (FlagOn(DeviceObject->Flags, DO_BUFFERED_IO)) {

		SetFlag(NewDeviceObject->Flags, DO_BUFFERED_IO);
	}

	if (FlagOn(DeviceObject->Flags, DO_DIRECT_IO)) {

		SetFlag(NewDeviceObject->Flags, DO_DIRECT_IO);
	}

	if (FlagOn(DeviceObject->Characteristics, FILE_DEVICE_SECURE_OPEN)) {

		SetFlag(NewDeviceObject->Characteristics, FILE_DEVICE_SECURE_OPEN);
	}

	// 
	// Do the attachment
	// 

	DevExt = NewDeviceObject->DeviceExtension;

	RtlZeroMemory(DevExt, sizeof(SFILTER_DEVICE_EXTENSION));

	Status = SfAttachDeviceToDeviceStack(NewDeviceObject, 
										  DeviceObject, 
										  &DevExt->AttachedToDeviceObject);

	if (!NT_SUCCESS(Status)) {

		goto ErrorCleanupDevice;
	}

	// 
	// Set the name
	// 

	RtlInitEmptyUnicodeString(&DevExt->DeviceName,
								DevExt->DeviceNameBuffer,
								sizeof(DevExt->DeviceNameBuffer));

	RtlCopyUnicodeString(&DevExt->DeviceName, DeviceName);		// Save Name

	// 
	// Mark we are done initializing
	// 

	ClearFlag(NewDeviceObject->Flags, DO_DEVICE_INITIALIZING);

	// 
	// Display who we have attached to
	// 

	SF_LOG_PRINT(SFDEBUG_DISPLAY_ATTACHMENT_NAMES,
				  ("SFilter!SfAttachToFileSystemDevice:		  Attaching to file system	%p \"%wZ\" (%s)\n",
					DeviceObject,
					&DevExt->DeviceName,
					GET_DEVICE_TYPE_NAME(NewDeviceObject->DeviceType)));

	// 
	// VERSION NOTE:
	// 
	// In Windows XP, the IO Manager provided APIs to safely enumerate all the
	// device objects for a given driver.  This allows filters to attach to 
	// all mounted volumes for a given file system at some time after the
	// volume has been mounted.  There is no support for this functionality
	// in Windows 2000.
	// 
	// MULTIVERSION NOTE:
	// 
	// If built for Windows XP or later, this driver is built to run on 
	// multiple versions.  When this is the case, we will test
	// for the presence of the new IO Manager routines that allow for volume 
	// enumeration.  If they are not present, we will not enumerate the volumes
	// when we attach to a new file system.
	// 
	
#if WINVER >= 0x0501

	if (IS_WINDOWSXP_OR_LATER())
	{
		ASSERT(NULL != gSfDynamicFunctions.EnumerateDeviceObjectList &&
			NULL != gSfDynamicFunctions.GetDiskDeviceObject &&
			NULL != gSfDynamicFunctions.GetDeviceAttachmentBaseRef &&
			NULL != gSfDynamicFunctions.GetLowerDeviceObject
			);

		// 
		// Enumerate all the mounted devices that currently
		// exist for this file system and attach to them.
		// 
		Status = SfEnumerateFileSystemVolumes(DeviceObject, &FsName);
		if (!NT_SUCCESS(Status))
		{
			IoDetachDevice(DevExt->AttachedToDeviceObject);
			goto ErrorCleanupDevice;
		}
	}
	
#endif

	return STATUS_SUCCESS;

	// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /
	//				Cleanup error handling
	// // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // // /

ErrorCleanupDevice:
	SfCleanupMountedDevice(NewDeviceObject);
	IoDeleteDevice(NewDeviceObject);

	return Status;
}

VOID
SfDetachFromFileSystemDevice(
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	Given a base file system device object, this will scan up the attachment
	chain looking for our attached device object.  If found it will detach
	us from the chain.

Arguments:

	DeviceObject - The file system device to detach from.

Return Value:

--*/ 
{
	PDEVICE_OBJECT ourAttachedDevice;
	PSFILTER_DEVICE_EXTENSION devExt;

	PAGED_CODE();

	// 
	// Skip the base file system device object (since it can't be us)
	// 

	ourAttachedDevice = DeviceObject->AttachedDevice;

	while (NULL != ourAttachedDevice) {

		if (IS_MY_DEVICE_OBJECT(ourAttachedDevice)) {

			devExt = ourAttachedDevice->DeviceExtension;

			// 
			// Display who we detached from
			// 

			SF_LOG_PRINT(SFDEBUG_DISPLAY_ATTACHMENT_NAMES,
						  ("SFilter!SfDetachFromFileSystemDevice:		Detaching from file system %p \"%wZ\" (%s)\n",
							devExt->AttachedToDeviceObject,
							&devExt->DeviceName,
							GET_DEVICE_TYPE_NAME(ourAttachedDevice->DeviceType)));

			// 
			// Detach us from the object just below us
			// Cleanup and delete the object
			// 

			SfCleanupMountedDevice(ourAttachedDevice);
			IoDetachDevice(DeviceObject);
			IoDeleteDevice(ourAttachedDevice);

			return;
		}

		// 
		// Look at the next device up in the attachment chain
		// 

		DeviceObject = ourAttachedDevice;
		ourAttachedDevice = ourAttachedDevice->AttachedDevice;
	}
}

#if WINVER >= 0x0501
NTSTATUS
SfEnumerateFileSystemVolumes(
	IN PDEVICE_OBJECT FSDeviceObject,
	IN PUNICODE_STRING Name
	) 
/*++

Routine Description:

	Enumerate all the mounted devices that currently exist for the given file
	system and attach to them.  We do this because this filter could be loaded
	at any time and there might already be mounted volumes for this file system.

Arguments:

	FSDeviceObject - The device object for the file system we want to enumerate

	Name - An already initialized unicode string used to retrieve names
			This is passed in to reduce the number of strings buffers on
			the stack.

Return Value:

	The status of the operation

--*/
{
	PDEVICE_OBJECT newDeviceObject;
	PSFILTER_DEVICE_EXTENSION newDevExt;
	PDEVICE_OBJECT *devList;
	PDEVICE_OBJECT storageStackDeviceObject;
	NTSTATUS status;
	ULONG numDevices;
	ULONG i=0;
	BOOLEAN isShadowCopyVolume;

	PAGED_CODE();

	// 
	// Find out how big of an array we need to allocate for the
	// mounted device list.
	// 

	status = (gSfDynamicFunctions.EnumerateDeviceObjectList)(
					FSDeviceObject->DriverObject,
					NULL,
					0,
					&numDevices);

	// 
	// We only need to get this list of there are devices.  If we
	// don't get an error there are no devices so go on.
	// 

	if (!NT_SUCCESS(status)) {

		ASSERT(STATUS_BUFFER_TOO_SMALL == status);

		// 
		// Allocate memory for the list of known devices
		// 

		numDevices += 8;		// grab a few extra slots

		devList = ExAllocatePoolWithTag(NonPagedPool, 
										 (numDevices * sizeof(PDEVICE_OBJECT)), 
										 SFLT_POOL_TAG);
		if (NULL == devList) {

			return STATUS_INSUFFICIENT_RESOURCES;
		}

		// 
		// Now get the list of devices.  If we get an error again
		// something is wrong, so just fail.
		// 

		ASSERT(NULL != gSfDynamicFunctions.EnumerateDeviceObjectList);
		status = (gSfDynamicFunctions.EnumerateDeviceObjectList)(
						FSDeviceObject->DriverObject,
						devList,
						(numDevices * sizeof(PDEVICE_OBJECT)),
						&numDevices);

		if (!NT_SUCCESS(status))  {

			ExFreePool(devList);
			return status;
		}

		// 
		// Walk the given list of devices and attach to them if we should.
		// 

		for (i=0; i < numDevices; i++) {

			// 
			// Initialize state so we can cleanup properly
			// 

			storageStackDeviceObject = NULL;

			__try {

				// 
				// Do not attach if:
				//	- This is the control device object (the one passed in)
				//	- The device type does not match
				//	- We are already attached to it.
				// 

				if ((devList[i] == FSDeviceObject) ||
					(devList[i]->DeviceType != FSDeviceObject->DeviceType) ||
					SfIsAttachedToDevice(devList[i], NULL)) {

					__leave;
				}

				// 
				// See if this device has a name.  If so, then it must
				// be a control device so don't attach to it.  This handles
				// drivers with more then one control device (like FastFat).
				// 

				SfGetBaseDeviceObjectName(devList[i], Name);

				if (Name->Length > 0) {

					__leave;
				}

				// 
				// Get the real (disk,storage stack) device object associated
				// with this file system device object.  Only try to attach
				// if we have a disk device object.
				// 

				ASSERT(NULL != gSfDynamicFunctions.GetDiskDeviceObject);
				status = (gSfDynamicFunctions.GetDiskDeviceObject)(devList[i], 
																	&storageStackDeviceObject);

				if (!NT_SUCCESS(status)) {

					__leave;
				}

				// 
				// Determine if this is a shadow copy volume.  If so don't
				// attach to it.
				// NOTE:  There is no reason sfilter shouldn't attach to these
				//		volumes, this is simply a sample of how to not
				//		attach if you don't want to
				// 

				status = SfIsShadowCopyVolume (storageStackDeviceObject, 
												&isShadowCopyVolume);

				if (NT_SUCCESS(status) &&
					isShadowCopyVolume &&
					!FlagOn(SfDebug,SFDEBUG_ATTACH_TO_SHADOW_COPIES)) {

					UNICODE_STRING shadowDeviceName;
					WCHAR shadowNameBuffer[MAX_DEVNAME_LENGTH];

					// 
					// Get the name for the debug display
					// 

					RtlInitEmptyUnicodeString(&shadowDeviceName, 
												shadowNameBuffer, 
												sizeof(shadowNameBuffer));

					SfGetObjectName(storageStackDeviceObject, 
									 &shadowDeviceName);

					SF_LOG_PRINT(SFDEBUG_DISPLAY_ATTACHMENT_NAMES,
								  ("SFilter!SfEnumerateFileSystemVolumes		 Not attaching to Volume	%p \"%wZ\", shadow copy volume\n", 
									storageStackDeviceObject,
									&shadowDeviceName));

					__leave;
				}

				// 
				// Allocate a new device object to attach with
				// 

				status = IoCreateDevice(gSFilterDriverObject,
										 sizeof(SFILTER_DEVICE_EXTENSION),
										 NULL,
										 devList[i]->DeviceType,
										 0,
										 FALSE,
										 &newDeviceObject);

				if (!NT_SUCCESS(status)) {

					__leave;
				}

				// 
				// Set disk device object
				// 

				newDevExt = newDeviceObject->DeviceExtension;

				RtlZeroMemory(newDevExt, sizeof(SFILTER_DEVICE_EXTENSION));
				
				newDevExt->StorageStackDeviceObject = storageStackDeviceObject;
		
				// 
				// Set storage stack device name
				// 

				RtlInitEmptyUnicodeString(&newDevExt->DeviceName,
										  newDevExt->DeviceNameBuffer,
										  sizeof(newDevExt->DeviceNameBuffer));

				SfGetObjectName(storageStackDeviceObject, 
								&newDevExt->DeviceName);

				ExInitializeFastMutex(&newDevExt->FsCtxTableMutex);
				RtlInitializeGenericTable(&newDevExt->FsCtxTable,
					SfGenericCompareRoutine,
					SfGenericAllocateRoutine,
					SfGenericFreeRoutine,
					NULL
					);

				// 
				// We have done a lot of work since the last time
				// we tested to see if we were already attached
				// to this device object.  Test again, this time
				// with a lock, and attach if we are not attached.
				// The lock is used to atomically test if we are
				// attached, and then do the attach.
				// 

				ExAcquireFastMutex(&gSfilterAttachLock);

				if (!SfIsAttachedToDevice(devList[i], NULL)) {

					// 
					// Attach to volume.
					// 

					status = SfAttachToMountedDevice(devList[i], 
													  newDeviceObject);
					
					if (!NT_SUCCESS(status)) { 

						// 
						// The attachment failed, cleanup.  Note that
						// we continue processing so we will cleanup
						// the reference counts and try to attach to
						// the rest of the volumes.
						// 
						// One of the reasons this could have failed
						// is because this volume is just being
						// mounted as we are attaching and the
						// DO_DEVICE_INITIALIZING flag has not yet
						// been cleared.  A filter could handle
						// this situation by pausing for a short
						// period of time and retrying the attachment a
						// limited number of times.
						// 

						SfCleanupMountedDevice(newDeviceObject);
						IoDeleteDevice(newDeviceObject);
					}

				} else {

					// 
					// We were already attached, cleanup this
					// device object.
					// 

					SfCleanupMountedDevice(newDeviceObject);
					IoDeleteDevice(newDeviceObject);
				}

				// 
				// Release the lock
				// 

				ExReleaseFastMutex(&gSfilterAttachLock);

			} __finally {

				// 
				// Remove reference added by IoGetDiskDeviceObject.
				// We only need to hold this reference until we are
				// successfully attached to the current volume.  Once
				// we are successfully attached to devList[i], the
				// IO Manager will make sure that the underlying
				// storageStackDeviceObject will not go away until
				// the file system stack is torn down.
				// 

				if (storageStackDeviceObject != NULL) {

					ObDereferenceObject(storageStackDeviceObject);
				}

				// 
				// Dereference the object (reference added by 
				// IoEnumerateDeviceObjectList)
				// 

				ObDereferenceObject(devList[i]);
			}
		}

		// 
		// We are going to ignore any errors received while attaching.  We
		// simply won't be attached to those volumes if we get an error
		// 

		status = STATUS_SUCCESS;

		// 
		// Free the memory we allocated for the list
		// 

		ExFreePool(devList);
	}

	return status;
}
#endif

NTSTATUS
SfAttachToMountedDevice(
	IN PDEVICE_OBJECT DeviceObject,
	IN PDEVICE_OBJECT SFilterDeviceObject
	)
/*++

Routine Description:

	This will attach to a DeviceObject that represents a mounted volume.

Arguments:

	DeviceObject - The device to attach to

	SFilterDeviceObject - Our device object we are going to attach

Return Value:

	Status of the operation

--*/
{		
	PSFILTER_DEVICE_EXTENSION newDevExt = SFilterDeviceObject->DeviceExtension;
	NTSTATUS status;
	ULONG i=0;

	PAGED_CODE();
	ASSERT(IS_MY_DEVICE_OBJECT(SFilterDeviceObject));
#if WINVER >= 0x0501	
	ASSERT(!SfIsAttachedToDevice (DeviceObject, NULL));
#endif

	// 
	// Propagate flags from Device Object we are trying to attach to.
	// Note that we do this before the actual attachment to make sure
	// the flags are properly set once we are attached (since an IRP
	// can come in immediately after attachment but before the flags would
	// be set).
	// 

	if (FlagOn(DeviceObject->Flags, DO_BUFFERED_IO)) {

		SetFlag(SFilterDeviceObject->Flags, DO_BUFFERED_IO);
	}

	if (FlagOn(DeviceObject->Flags, DO_DIRECT_IO)) {

		SetFlag(SFilterDeviceObject->Flags, DO_DIRECT_IO);
	}

	// 
	// It is possible for this attachment request to fail because this device
	// object has not finished initializing.  This can occur if this filter
	// loaded just as this volume was being mounted.
	// 

	for (i=0; i < 8; i++) {
		LARGE_INTEGER interval;

		// 
		// Attach our device object to the given device object
		// The only reason this can fail is if someone is trying to dismount
		// this volume while we are attaching to it.
		// 

		status = SfAttachDeviceToDeviceStack(SFilterDeviceObject, 
											  DeviceObject,
											  &newDevExt->AttachedToDeviceObject);
		if (NT_SUCCESS(status)) {

			// 
			// Finished all initialization of the new device object,  so clear the
			// initializing flag now.  This allows other filters to now attach
			// to our device object.
			// 

			ClearFlag(SFilterDeviceObject->Flags, DO_DEVICE_INITIALIZING);

			// 
			// Display the name
			// 

			SF_LOG_PRINT(SFDEBUG_DISPLAY_ATTACHMENT_NAMES,
						  ("SFilter!SfAttachToMountedDevice:			 Attaching to volume		%p \"%wZ\"\n", 
							newDevExt->AttachedToDeviceObject,
							&newDevExt->DeviceName));

			return STATUS_SUCCESS;
		}

		// 
		// Delay, giving the device object a chance to finish its
		// initialization so we can try again
		// 

		interval.QuadPart = (500 * DELAY_ONE_MILLISECOND);	  // delay 1/2 second
		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}

	return status;
}

VOID
SfCleanupMountedDevice(
	IN PDEVICE_OBJECT DeviceObject
	)
/*++

Routine Description:

	This cleans up any necessary data in the device extension to prepare for
	this memory to be freed.

Arguments:

	DeviceObject - The device we are cleaning up

Return Value:

	None

--*/
{		
	PSFILTER_DEVICE_EXTENSION DevExt = (PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
	
	UNREFERENCED_PARAMETER(DeviceObject);
	ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

	if (DevExt->StorageStackDeviceObject)
	{
		ExAcquireFastMutex(&DevExt->FsCtxTableMutex);

		while (!RtlIsGenericTableEmpty(&DevExt->FsCtxTable))
		{
			PVOID Element = RtlGetElementGenericTable(
				&DevExt->FsCtxTable,
				0
				);
			if (Element)
			{
				RtlDeleteElementGenericTable(
					&DevExt->FsCtxTable,
					Element
					);
			}
		}

		ExReleaseFastMutex(&DevExt->FsCtxTableMutex);
	}
}

VOID
SfGetObjectName(
	IN PVOID Object,
	IN OUT PUNICODE_STRING Name
	)
/*++

Routine Description:

	This routine will return the name of the given object.
	If a name can not be found an empty string will be returned.

Arguments:

	Object - The object whose name we want

	Name - A unicode string that is already initialized with a buffer that
			receives the name of the object.

Return Value:

	None

--*/
{
	NTSTATUS status;
	CHAR nibuf[512];		// buffer that receives NAME information and name
	POBJECT_NAME_INFORMATION nameInfo = (POBJECT_NAME_INFORMATION)nibuf;
	ULONG retLength;

	status = ObQueryNameString(Object, nameInfo, sizeof(nibuf), &retLength);

	Name->Length = 0;
	if (NT_SUCCESS(status)) {

		RtlCopyUnicodeString(Name, &nameInfo->Name);
	}
}

// 
// VERSION NOTE:
// 
// This helper routine is only needed when enumerating all volumes in the
// system, which is only supported on Windows XP and later.
// 

#if WINVER >= 0x0501
VOID
SfGetBaseDeviceObjectName(
	IN PDEVICE_OBJECT DeviceObject,
	IN OUT PUNICODE_STRING Name
	)
/*++

Routine Description:

	This locates the base device object in the given attachment chain and then
	returns the name of that object.

	If no name can be found, an empty string is returned.

Arguments:

	Object - The object whose name we want

	Name - A unicode string that is already initialized with a buffer that
			receives the name of the device object.

Return Value:

	None

--*/
{
	// 
	// Get the base file system device object
	// 

	ASSERT(NULL != gSfDynamicFunctions.GetDeviceAttachmentBaseRef);
	DeviceObject = (gSfDynamicFunctions.GetDeviceAttachmentBaseRef)(DeviceObject);

	// 
	// Get the name of that object
	// 

	SfGetObjectName(DeviceObject, Name);

	// 
	// Remove the reference added by IoGetDeviceAttachmentBaseRef
	// 

	ObDereferenceObject(DeviceObject);
}
#endif

PUNICODE_STRING
SfGetFileName(
	IN PFILE_OBJECT FileObject,
	IN NTSTATUS CreateStatus,
	IN OUT PGET_NAME_CONTROL NameControl
	)
/*++

Routine Description:

	This routine will try and get the name of the given file object.  This
	is guaranteed to always return a printable string (though it may be NULL).
	This will allocate a buffer if it needs to.

Arguments:
	FileObject - the file object we want the name for

	CreateStatus - status of the create operation

	NameControl - control structure used for retrieving the name.  It keeps
		track if a buffer was allocated or if we are using the internal
		buffer.

Return Value:

	Pointer to the unicode string with the name

--*/
{
	POBJECT_NAME_INFORMATION nameInfo;
	NTSTATUS status;
	ULONG size;
	ULONG bufferSize;

	// 
	// Mark we have not allocated the buffer
	// 

	NameControl->allocatedBuffer = NULL;

	// 
	// Use the small buffer in the structure (that will handle most cases)
	// for the name
	// 

	nameInfo = (POBJECT_NAME_INFORMATION)NameControl->smallBuffer;
	bufferSize = sizeof(NameControl->smallBuffer);

	// 
	// If the open succeeded, get the name of the file, if it
	// failed, get the name of the device.
	// 
		
	status = ObQueryNameString(
				  (NT_SUCCESS(CreateStatus) ?
					(PVOID)FileObject :
					(PVOID)FileObject->DeviceObject),
				  nameInfo,
				  bufferSize,
				  &size);

	// 
	// See if the buffer was to small
	// 

	if (status == STATUS_BUFFER_OVERFLOW) {

		// 
		// The buffer was too small, allocate one big enough
		// 

		bufferSize = size + sizeof(WCHAR);

		NameControl->allocatedBuffer = ExAllocatePoolWithTag(
											NonPagedPool,
											bufferSize,
											SFLT_POOL_TAG);

		if (NULL == NameControl->allocatedBuffer) {

			// 
			// Failed allocating a buffer, return an empty string for the name
			// 

			RtlInitEmptyUnicodeString(
				(PUNICODE_STRING)&NameControl->smallBuffer,
				(PWCHAR)(NameControl->smallBuffer + sizeof(UNICODE_STRING)),
				(USHORT)(sizeof(NameControl->smallBuffer) - sizeof(UNICODE_STRING)));

			return (PUNICODE_STRING)&NameControl->smallBuffer;
		}

		// 
		// Set the allocated buffer and get the name again
		// 

		nameInfo = (POBJECT_NAME_INFORMATION)NameControl->allocatedBuffer;

		status = ObQueryNameString(
					  FileObject,
					  nameInfo,
					  bufferSize,
					  &size);
	}

	// 
	// If we got a name and an error opening the file then we
	// just received the device name.  Grab the rest of the name
	// from the FileObject (note that this can only be done if being called
	// from Create).  This only happens if we got an error back from the
	// create.
	// 

	if (NT_SUCCESS(status) && 
					!NT_SUCCESS(CreateStatus)) {

		ULONG newSize;
		PCHAR newBuffer;
		POBJECT_NAME_INFORMATION newNameInfo;

		// 
		// Calculate the size of the buffer we will need to hold
		// the combined names
		// 

		newSize = size + FileObject->FileName.Length;

		// 
		// If there is a related file object add in the length
		// of that plus space for a separator
		// 

		if (NULL != FileObject->RelatedFileObject) {

			newSize += FileObject->RelatedFileObject->FileName.Length + 
						sizeof(WCHAR);
		}

		// 
		// See if it will fit in the existing buffer
		// 

		if (newSize > bufferSize) {

			// 
			// It does not fit, allocate a bigger buffer
			// 

			newBuffer = ExAllocatePoolWithTag(
									NonPagedPool,
									newSize,
									SFLT_POOL_TAG);

			if (NULL == newBuffer) {

				// 
				// Failed allocating a buffer, return an empty string for the name
				// 

				RtlInitEmptyUnicodeString(
					(PUNICODE_STRING)&NameControl->smallBuffer,
					(PWCHAR)(NameControl->smallBuffer + sizeof(UNICODE_STRING)),
					(USHORT)(sizeof(NameControl->smallBuffer) - sizeof(UNICODE_STRING)));

				return (PUNICODE_STRING)&NameControl->smallBuffer;
			}

			// 
			// Now initialize the new buffer with the information
			// from the old buffer.
			// 

			newNameInfo = (POBJECT_NAME_INFORMATION)newBuffer;

			RtlInitEmptyUnicodeString(
				&newNameInfo->Name,
				(PWCHAR)(newBuffer + sizeof(OBJECT_NAME_INFORMATION)),
				(USHORT)(newSize - sizeof(OBJECT_NAME_INFORMATION)));

			RtlCopyUnicodeString(&newNameInfo->Name, 
								  &nameInfo->Name);

			// 
			// Free the old allocated buffer (if there is one)
			// and save off the new allocated buffer address.  It
			// would be very rare that we should have to free the
			// old buffer because device names should always fit
			// inside it.
			// 

			if (NULL != NameControl->allocatedBuffer) {

				ExFreePool(NameControl->allocatedBuffer);
			}

			// 
			// Readjust our pointers
			// 

			NameControl->allocatedBuffer = newBuffer;
			bufferSize = newSize;
			nameInfo = newNameInfo;

		} else {

			// 
			// The MaximumLength was set by ObQueryNameString to
			// one char larger then the length.  Set it to the
			// true size of the buffer (so we can append the names)
			// 

			nameInfo->Name.MaximumLength = (USHORT)(bufferSize - 
								  sizeof(OBJECT_NAME_INFORMATION));
		}

		// 
		// If there is a related file object, append that name
		// first onto the device object along with a separator
		// character
		// 

		if (NULL != FileObject->RelatedFileObject) {

			RtlAppendUnicodeStringToString(
					&nameInfo->Name,
					&FileObject->RelatedFileObject->FileName);

			RtlAppendUnicodeToString(&nameInfo->Name, L"\\");
		}

		// 
		// Append the name from the file object
		// 

		RtlAppendUnicodeStringToString(
				&nameInfo->Name,
				&FileObject->FileName);

		ASSERT(nameInfo->Name.Length <= nameInfo->Name.MaximumLength);
	}

	// 
	// Return the name
	// 

	return &nameInfo->Name;
}


VOID
SfGetFileNameCleanup(
	IN OUT PGET_NAME_CONTROL NameControl
	)
/*++

Routine Description:

	This will see if a buffer was allocated and will free it if it was

Arguments:

	NameControl - control structure used for retrieving the name.  It keeps
		track if a buffer was allocated or if we are using the internal
		buffer.

Return Value:

	None

--*/
{

	if (NULL != NameControl->allocatedBuffer) {

		ExFreePool(NameControl->allocatedBuffer);
		NameControl->allocatedBuffer = NULL;
	}
}

// 
// VERSION NOTE:
// 
// In Windows 2000, the APIs to safely walk an arbitrary file system device 
// stack were not supported.  If we can guarantee that a device stack won't 
// be torn down during the walking of the device stack, we can walk from
// the base file system's device object up to the top of the device stack
// to see if we are attached.  We know the device stack will not go away if
// we are in the process of processing a mount request OR we have a file object
// open on this device.
// 
// In Windows XP and later, the IO Manager provides APIs that will allow us to
// walk through the chain safely using reference counts to protect the device 
// object from going away while we are inspecting it.  This can be done at any
// time.
// 
// MULTIVERSION NOTE:
// 
// If built for Windows XP or later, this driver is built to run on 
// multiple versions.  When this is the case, we will test for the presence of
// the new IO Manager routines that allow for a filter to safely walk the file
// system device stack and use those APIs if they are present to determine if
// we have already attached to this volume.  If these new IO Manager routines
// are not present, we will assume that we are at the bottom of the file
// system stack and walk up the stack looking for our device object.
// 

BOOLEAN
SfIsAttachedToDevice(
	PDEVICE_OBJECT DeviceObject,
	PDEVICE_OBJECT *AttachedDeviceObject OPTIONAL
	)
{

	PAGED_CODE();

#if WINVER >= 0x0501
	if (IS_WINDOWSXP_OR_LATER()) {

		ASSERT(NULL != gSfDynamicFunctions.GetLowerDeviceObject &&
				NULL != gSfDynamicFunctions.GetDeviceAttachmentBaseRef);
		
		return SfIsAttachedToDeviceWXPAndLater(DeviceObject, AttachedDeviceObject);
	} else {
#endif

		return SfIsAttachedToDeviceW2K(DeviceObject, AttachedDeviceObject);

#if WINVER >= 0x0501
	}
#endif	
}

BOOLEAN
SfIsAttachedToDeviceW2K(
	PDEVICE_OBJECT DeviceObject,
	PDEVICE_OBJECT *AttachedDeviceObject OPTIONAL
	)
/*++

Routine Description:

	VERSION: Windows 2000

	This routine walks up the device stack from the DeviceObject passed in
	looking for a device object that belongs to our filter.

	Note:  If AttachedDeviceObject is returned with a non-NULL value,
			there is a reference on the AttachedDeviceObject that must
			be cleared by the caller.

Arguments:

	DeviceObject - The device chain we want to look through

	AttachedDeviceObject - Set to the deviceObject which FileSpy
			has previously attached to DeviceObject.

Return Value:

	TRUE if we are attached, FALSE if not

--*/
{
	PDEVICE_OBJECT currentDevice;

	PAGED_CODE();

	for (currentDevice = DeviceObject;
		 currentDevice != NULL;
		 currentDevice = currentDevice->AttachedDevice) {

		if (IS_MY_DEVICE_OBJECT(currentDevice)) {

			// 
			// We are attached.  If requested, return the found device object.
			// 

			if (ARGUMENT_PRESENT(AttachedDeviceObject)) {

				ObReferenceObject(currentDevice);
				*AttachedDeviceObject = currentDevice;
			}

			return TRUE;
		}
	}

	// 
	// We did not find ourselves on the attachment chain.  Return a NULL
	// device object pointer (if requested) and return we did not find
	// ourselves.
	// 
	
	if (ARGUMENT_PRESENT(AttachedDeviceObject)) {

		*AttachedDeviceObject = NULL;
	}

	return FALSE;
}

#if WINVER >= 0x0501
BOOLEAN
SfIsAttachedToDeviceWXPAndLater(
	PDEVICE_OBJECT DeviceObject,
	PDEVICE_OBJECT *AttachedDeviceObject OPTIONAL
	)
/*++

Routine Description:

	VERSION: Windows XP and later

	This walks down the attachment chain looking for a device object that
	belongs to this driver.  If one is found, the attached device object
	is returned in AttachedDeviceObject.

Arguments:

	DeviceObject - The device chain we want to look through

	AttachedDeviceObject - The Sfilter device attached to this device.

Return Value:

	TRUE if we are attached, FALSE if not

--*/
{
	PDEVICE_OBJECT currentDevObj;
	PDEVICE_OBJECT nextDevObj;

	PAGED_CODE();
	
	// 
	// Get the device object at the TOP of the attachment chain
	// 

	ASSERT(NULL != gSfDynamicFunctions.GetAttachedDeviceReference);
	currentDevObj = (gSfDynamicFunctions.GetAttachedDeviceReference)(DeviceObject);

	// 
	// Scan down the list to find our device object.
	// 

	do {
	
		if (IS_MY_DEVICE_OBJECT(currentDevObj)) {

			// 
			// We have found that we are already attached.  If we are
			// returning the device object, leave it referenced else remove
			// the reference.
			// 

			if (ARGUMENT_PRESENT(AttachedDeviceObject)) {

				*AttachedDeviceObject = currentDevObj;

			} else {

				ObDereferenceObject(currentDevObj);
			}

			return TRUE;
		}

		// 
		// Get the next attached object.  This puts a reference on 
		// the device object.
		// 

		ASSERT(NULL != gSfDynamicFunctions.GetLowerDeviceObject);
		nextDevObj = (gSfDynamicFunctions.GetLowerDeviceObject)(currentDevObj);

		// 
		// Dereference our current device object, before
		// moving to the next one.
		// 

		ObDereferenceObject(currentDevObj);

		currentDevObj = nextDevObj;
		
	} while (NULL != currentDevObj);
	
	// 
	// We did not find ourselves on the attachment chain.  Return a NULL
	// device object pointer (if requested) and return we did not find
	// ourselves.
	// 

	if (ARGUMENT_PRESENT(AttachedDeviceObject)) {

		*AttachedDeviceObject = NULL;
	}

	return FALSE;
}	
#endif

VOID
SfDriverReinitialization(
    IN PDRIVER_OBJECT DriverObject,
    IN PVOID Context,
    IN ULONG Count
    )
/*++

Routine Description:

	This routine will load the rules into gRules
	
Arguments:

	DriverObject - pointer to the driver object
	Context - the param passed to IoRegisterDriverReinitialization
	Count - reinitialize count
		
Return Value:

	VOID.

--*/
{
	NTSTATUS Status;

	UNREFERENCED_PARAMETER(Count);

	Status = SfLoadRules(&gRuleFileHandle);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("SFilter!SfDriverReinitialization: SfLoadRules failed, Status=%08x\n", Status));
		IoRegisterDriverReinitialization(DriverObject, SfDriverReinitialization, Context);
	}
}

NTSTATUS
SfIsShadowCopyVolume(
	IN PDEVICE_OBJECT StorageStackDeviceObject,
	OUT PBOOLEAN IsShadowCopy
	)
/*++

Routine Description:

	This routine will determine if the given volume is for a ShadowCopy volume
	or some other type of volume.

	VERSION NOTE:

	ShadowCopy volumes were introduced in Windows XP, therefore, if this
	driver is running on W2K, we know that this is not a shadow copy volume.

	Also note that in Windows XP, we need to test to see if the driver name
	of this device object is \Driver\VolSnap in addition to seeing if this
	device is read-only.  For Windows Server 2003, we can infer that
	this is a ShadowCopy by looking for a DeviceType == FILE_DEVICE_VIRTUAL_DISK
	and read-only volume.
	
Arguments:

	StorageStackDeviceObject - pointer to the disk device object
	IsShadowCopy - returns TRUE if this is a shadow copy, FALSE otherwise
		
Return Value:

	The status of the operation.  If this operation fails IsShadowCopy is
	always set to FALSE.

--*/
{

	PAGED_CODE();

	// 
	// Default to NOT a shadow copy volume
	// 

	*IsShadowCopy = FALSE;

#if WINVER >= 0x0501
	if (IS_WINDOWS2000()) {
#endif		

		UNREFERENCED_PARAMETER(StorageStackDeviceObject);
		return STATUS_SUCCESS;

#if WINVER >= 0x0501		
	}

	if (IS_WINDOWSXP()) {

		UNICODE_STRING volSnapDriverName;
		WCHAR buffer[MAX_DEVNAME_LENGTH];
		PUNICODE_STRING storageDriverName;
		ULONG returnedLength;
		NTSTATUS status;

		// 
		// In Windows XP, all ShadowCopy devices were of type FILE_DISK_DEVICE.
		// If this does not have a device type of FILE_DISK_DEVICE, then
		// it is not a ShadowCopy volume.  Return now.
		// 

		if (FILE_DEVICE_DISK != StorageStackDeviceObject->DeviceType) {

			return STATUS_SUCCESS;
		}

		// 
		// Unfortunately, looking for the FILE_DEVICE_DISK isn't enough.  We
		// need to find out if the name of this driver is \Driver\VolSnap as
		// well.
		// 

		storageDriverName = (PUNICODE_STRING) buffer;
		RtlInitEmptyUnicodeString(storageDriverName, 
									Add2Ptr(storageDriverName, sizeof(UNICODE_STRING)),
									sizeof(buffer) - sizeof(UNICODE_STRING));

		status = ObQueryNameString(StorageStackDeviceObject,
									(POBJECT_NAME_INFORMATION)storageDriverName,
									storageDriverName->MaximumLength,
									&returnedLength);

		if (!NT_SUCCESS(status)) {

			return status;
		}

		RtlInitUnicodeString(&volSnapDriverName, L"\\Driver\\VolSnap");

		if (RtlEqualUnicodeString(storageDriverName, &volSnapDriverName, TRUE)) {

			// 
			// This is a ShadowCopy volume, so set our return parameter to true.
			// 

			*IsShadowCopy = TRUE;

		} else {

			// 
			// This is not a ShadowCopy volume, but IsShadowCopy is already 
			// set to FALSE.  Fall through to return to the caller.
			// 

			NOTHING;
		}

		return STATUS_SUCCESS;
		
	} else {

		PIRP irp;
		KEVENT event;
		IO_STATUS_BLOCK iosb;
		NTSTATUS status;

		// 
		// For Windows Server 2003 and later, it is sufficient to test for a
		// device type fo FILE_DEVICE_VIRTUAL_DISK and that the device
		// is read-only to identify a ShadowCopy.
		// 

		// 
		// If this does not have a device type of FILE_DEVICE_VIRTUAL_DISK, then
		// it is not a ShadowCopy volume.  Return now.
		// 

		if (FILE_DEVICE_VIRTUAL_DISK != StorageStackDeviceObject->DeviceType) {

			return STATUS_SUCCESS;
		}

		// 
		// It has the correct device type, see if it is marked as read only.
		// 
		// NOTE:  You need to be careful which device types you do this operation
		//		on.  It is accurate for this type but for other device
		//		types it may return misleading information.  For example the
		//		current microsoft cdrom driver always returns CD media as
		//		readonly, even if the media may be writable.  On other types
		//		this state may change.
		// 

		KeInitializeEvent(&event, NotificationEvent, FALSE);

		irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_IS_WRITABLE,
											 StorageStackDeviceObject,
											 NULL,
											 0,
											 NULL,
											 0,
											 FALSE,
											 &event,
											 &iosb);

		// 
		// If we could not allocate an IRP, return an error
		// 

		if (irp == NULL) {

			return STATUS_INSUFFICIENT_RESOURCES;
		}

		// 
		// Call the storage stack and see if this is readonly
		// 

		status = IoCallDriver(StorageStackDeviceObject, irp);

		if (status == STATUS_PENDING) {

			(VOID)KeWaitForSingleObject(&event,
										 Executive,
										 KernelMode,
										 FALSE,
										 NULL);

			status = iosb.Status;
		}

		// 
		// If the media is write protected then this is a shadow copy volume
		// 

		if (STATUS_MEDIA_WRITE_PROTECTED == status) {

			*IsShadowCopy = TRUE;
			status = STATUS_SUCCESS;
		}

		// 
		// Return the status of the IOCTL.  IsShadowCopy is already set to FALSE
		// which is what we want if STATUS_SUCCESS was returned or if an error
		// was returned.
		// 

		return status;
	}
#endif	
}

BOOLEAN
SfDissectFileName(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	OUT PWSTR FileName
	)
/*++
Arguments:

	DeviceObject - Pointer to the device object for this driver.

	Irp - Pointer to the request packet representing the I/O request.

	FileName - Copy valid file name.

Return Value:

	return TRUE file is valid,otherwize return FALSE.

--*/
{
	PSFILTER_DEVICE_EXTENSION DeviceExtension = (PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	PFILE_OBJECT RelatedFileObject = FileObject->RelatedFileObject;
	ULONG Length;
	
	if (!FileObject->FileName.Buffer || (FileObject->FileName.Length == 0))
	{
		return FALSE;
	}

	RelatedFileObject = FileObject->RelatedFileObject;
		
	// file format: 123.txt
	FileName[0] = DeviceExtension->DriveLetter;
	FileName[1] = L':';
	if (FileObject->FileName.Buffer[0] != L'\\' && RelatedFileObject && RelatedFileObject->FileName.Length)
	{
		if ((RelatedFileObject->FileName.Length + FileObject->FileName.Length) > MAX_PATH * sizeof(WCHAR))
		{
			return FALSE;
		}

		RtlCopyMemory(FileName + 2, RelatedFileObject->FileName.Buffer, RelatedFileObject->FileName.Length);
		
		Length = 2 + (RelatedFileObject->FileName.Length >> 1);
		if (FileName[Length - 1] != L'\\')
		{
			FileName[Length] = L'\\';
			Length ++;
		}
		
		RtlCopyMemory(FileName + Length, FileObject->FileName.Buffer, FileObject->FileName.Length);
		Length = (FileObject->FileName.Length >> 1) + Length;
	}
	else
	{
		// file format: \123.txt
		RtlCopyMemory(FileName + 2, FileObject->FileName.Buffer, FileObject->FileName.Length);
		Length = (FileObject->FileName.Length >> 1) + 2;
	}

	FileName[Length] = L'\0';

	// trim right '\'
	while ((Length > 3) && (FileName[Length - 1] == L'\\') && (FileName[Length - 2] != L':'))
	{
		FileName[Length] = L'\0';
		-- Length;
	}
	
	return TRUE;
}

RTL_GENERIC_COMPARE_RESULTS
SfGenericCompareRoutine(
	IN PRTL_GENERIC_TABLE Table,
	IN PVOID FirstStruct,
	IN PVOID SecondStruct
	)
{
	PFILE_CONTEXT FirstFileCtx = (PFILE_CONTEXT) FirstStruct;
	PFILE_CONTEXT SecondFileCtx = (PFILE_CONTEXT) SecondStruct;

	UNREFERENCED_PARAMETER(Table);

	if (FirstFileCtx->FsContext < SecondFileCtx->FsContext)
		return GenericLessThan;
	else if (FirstFileCtx->FsContext > SecondFileCtx->FsContext)
		return GenericGreaterThan;
	else
		return GenericEqual;
}

PVOID
SfGenericAllocateRoutine(
	IN PRTL_GENERIC_TABLE Table,
	IN CLONG ByteSize
	)
{
	PVOID Buffer = NULL;

	UNREFERENCED_PARAMETER(Table);
	UNREFERENCED_PARAMETER(ByteSize);

	ASSERT(ByteSize <= FSCTX_GENERIC_TABLE_POOL_SIZE);

	Buffer = ExAllocateFromPagedLookasideList(&gFsCtxLookAsideList);
	if (Buffer)
		RtlZeroMemory(Buffer, FSCTX_GENERIC_TABLE_POOL_SIZE);
	
	return Buffer;
}

VOID
SfGenericFreeRoutine(
	IN PRTL_GENERIC_TABLE Table,
	IN PVOID Buffer
	)
{
	UNREFERENCED_PARAMETER(Table);

	ExFreeToPagedLookasideList(&gFsCtxLookAsideList, Buffer);
}

NTSTATUS
SfQueryCompletion (
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PKEVENT SynchronizingEvent
	)
/*++

Routine Description:

	This routine does the cleanup necessary once the query request completed
	by the file system.
	
Arguments:

	DeviceObject - This will be NULL since we originated this
		Irp.

	Irp - The io request structure containing the information
		about the current state of our file name query.

	SynchronizingEvent - The event to signal to notify the 
		originator of this request that the operation is
		complete.

Return Value:

	Returns STATUS_MORE_PROCESSING_REQUIRED so that IO Manager
	will not try to free the Irp again.

--*/
{

	UNREFERENCED_PARAMETER(DeviceObject);
	
	// 
	// Make sure that the Irp status is copied over to the user's
	// IO_STATUS_BLOCK so that the originator of this irp will know
	// the final status of this operation.
	// 

	ASSERT(NULL != Irp->UserIosb);
	*Irp->UserIosb = Irp->IoStatus;

	// 
	// Signal SynchronizingEvent so that the originator of this
	// Irp know that the operation is completed.
	// 

	KeSetEvent(SynchronizingEvent, IO_NO_INCREMENT, FALSE);

	// 
	// We are now done, so clean up the irp that we allocated.
	// 

	IoFreeIrp(Irp);

	// 
	// If we return STATUS_SUCCESS here, the IO Manager will
	// perform the cleanup work that it thinks needs to be done
	// for this IO operation.  This cleanup work includes:
	// * Copying data from the system buffer to the user's buffer 
	//  if this was a buffered IO operation.
	// * Freeing any MDLs that are in the Irp.
	// * Copying the Irp->IoStatus to Irp->UserIosb so that the
	//  originator of this irp can see the final status of the
	//  operation.
	// * If this was an asynchronous request or this was a 
	//  synchronous request that got pending somewhere along the
	//  way, the IO Manager will signal the Irp->UserEvent, if one 
	//  exists, otherwise it will signal the FileObject->Event.
	//  (This can have REALLY bad implications if the irp originator
	//	did not an Irp->UserEvent and the irp originator is not
	//	waiting on the FileObject->Event.  It would not be that
	//	farfetched to believe that someone else in the system is
	//	waiting on FileObject->Event and who knows who will be
	//	awoken as a result of the IO Manager signaling this event.
	// 
	// Since some of these operations require the originating thread's
	// context (e.g., the IO Manager need the UserBuffer address to 
	// be valid when copy is done), the IO Manager queues this work
	// to an APC on the Irp's originating thread.
	// 
	// Since FileSpy allocated and initialized this irp, we know
	// what cleanup work needs to be done.  We can do this cleanup
	// work more efficiently than the IO Manager since we are handling
	// a very specific case.  Therefore, it is better for us to
	// perform the cleanup work here then free the irp than passing
	// control back to the IO Manager to do this work.
	// 
	// By returning STATUS_MORE_PROCESS_REQUIRED, we tell the IO Manager 
	// to stop processing this irp until it is told to restart processing
	// with a call to IoCompleteRequest.  Since the IO Manager has
	// already performed all the work we want it to do on this
	// irp, we do the cleanup work, return STATUS_MORE_PROCESSING_REQUIRED,
	// and ask the IO Manager to resume processing by calling 
	// IoCompleteRequest.
	// 

	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
SfQueryFileSystemForFileName (
	IN PFILE_OBJECT FileObject,
	IN PDEVICE_OBJECT NextDeviceObject,
	IN ULONG FileNameInfoLength,
	OUT PFILE_NAME_INFORMATION FileNameInfo,
	OUT PULONG ReturnedLength
	)
/*++

Routine Description:

	This routine rolls an irp to query the name of the
	FileObject parameter from the base file system.

	Note:  ObQueryNameString CANNOT be used here because it
	  would cause recursive lookup of the file name for FileObject.
	  
Arguments:

	FileObject - the file object for which we want the name.
	NextDeviceObject - the device object for the next driver in the
		stack.  This is where we want to start our request
		for the name of FileObject.
	FileNameInfoLength - the length in bytes of FileNameInfo
		parameter.
	FileNameInfo - the buffer that will be receive the name
		information.  This must be memory that safe to write
		to from kernel space.
	ReturnedLength - the number of bytes written to FileNameInfo.
	
Return Value:

	Returns the status of the operation.
	
--*/
{
	PIRP Irp;
	PIO_STACK_LOCATION IrpSp;
	KEVENT Event;
	IO_STATUS_BLOCK IoStatus;
	NTSTATUS Status;

	PAGED_CODE();

	Irp = IoAllocateIrp(NextDeviceObject->StackSize, FALSE);
	if (!Irp)
		return STATUS_INSUFFICIENT_RESOURCES;

	// 
	// Set our current thread as the thread for this
	// Irp so that the IO Manager always knows which
	// thread to return to if it needs to get back into
	// the context of the thread that originated this
	// Irp.
	// 	
	Irp->Tail.Overlay.Thread = PsGetCurrentThread();

	// 
	// Set that this Irp originated from the kernel so that
	// the IO Manager knows that the buffers do not
	// need to be probed.
	// 
	Irp->RequestorMode = KernelMode;

	// 
	// Initialize the UserIosb and UserEvent in the 
	// 
	IoStatus.Status = STATUS_SUCCESS;
	IoStatus.Information = 0;

	Irp->UserIosb = &IoStatus;
	Irp->UserEvent = NULL;		// already zeroed

	// 
	// Set the IRP_SYNCHRONOUS_API to denote that this
	// is a synchronous IO request.
	// 
	Irp->Flags = IRP_SYNCHRONOUS_API;

	IrpSp = IoGetNextIrpStackLocation(Irp);
	IrpSp->MajorFunction = IRP_MJ_QUERY_INFORMATION;
	IrpSp->FileObject = FileObject;

	// 
	// Setup the parameters for IRP_MJ_QUERY_INFORMATION.
	// The buffer we want to be filled in should be placed in
	// the system buffer.
	// 
	Irp->AssociatedIrp.SystemBuffer = FileNameInfo;

	IrpSp->Parameters.QueryFile.Length = FileNameInfoLength;
	IrpSp->Parameters.QueryFile.FileInformationClass = FileNameInformation;

	// 
	// Set up the completion routine so that we know when our
	// request for the file name is completed.  At that time,
	// we can free the Irp.
	// 
	KeInitializeEvent(&Event, NotificationEvent, FALSE);

	IoSetCompletionRoutine(Irp, 
		SfQueryCompletion, 
		&Event, 
		TRUE, 
		TRUE, 
		TRUE
		);

	Status = IoCallDriver(NextDeviceObject, Irp);
	if (STATUS_PENDING == Status)
	{
		(VOID) KeWaitForSingleObject(&Event, 
			Executive, 
			KernelMode,
			FALSE,
			NULL
			);
	}

	ASSERT(KeReadStateEvent(&Event) || !NT_SUCCESS(IoStatus.Status));

	*ReturnedLength = (ULONG) IoStatus.Information;
	return IoStatus.Status;
}

NTSTATUS
SfIsEncryptFlagExist(
	IN PDEVICE_OBJECT DeviceObject,
	IN PCWSTR FileName,
	OUT PBOOLEAN IsEncrypted,
	OUT PVOID Data,
	IN ULONG DataLength
	)
{
	PSFILTER_DEVICE_EXTENSION DevExt = (PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING ObjectName;
	HANDLE FileHandle;
	IO_STATUS_BLOCK IoStatus;
	NTSTATUS Status;
	PWSTR EncryptFlagFile;

	ASSERT(DeviceObject);
	ASSERT(FileName);
	ASSERT(IsEncrypted);

	*IsEncrypted = FALSE;

	// 
	// Is root dir ?
	// 
	if (wcslen(FileName) <= 3)
		return STATUS_SUCCESS;

	EncryptFlagFile = ExAllocateFromPagedLookasideList(&gFileNameLookAsideList);
	if (EncryptFlagFile == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	EncryptFlagFile[0] = L'\\';
	EncryptFlagFile[1] = L'?';
	EncryptFlagFile[2] = L'?';
	EncryptFlagFile[3] = L'\\';
	EncryptFlagFile[4] = L'\0';
	
	wcscat(EncryptFlagFile, FileName);

	if (EncryptFlagFile[wcslen(EncryptFlagFile) - 1] == L'\\')
		EncryptFlagFile[wcslen(EncryptFlagFile) - 1] = L'\0';

	wcscat(EncryptFlagFile, SF_ENCRYPT_POSTFIX);
	
	RtlInitUnicodeString(&ObjectName, EncryptFlagFile);
	
	InitializeObjectAttributes(&ObjectAttributes,
		&ObjectName,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL
		);

	Status = ZwCreateFile(&FileHandle,
		FILE_READ_DATA | SYNCHRONIZE,
		&ObjectAttributes,
		&IoStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
		);
	if (!NT_SUCCESS(Status))
	{
		if ((STATUS_NO_SUCH_FILE == Status) ||
			(STATUS_OBJECT_NAME_NOT_FOUND == Status) ||
			(STATUS_OBJECT_PATH_NOT_FOUND == Status))
		{
			Status = STATUS_SUCCESS;
		}

		ExFreeToPagedLookasideList(&gFileNameLookAsideList, EncryptFlagFile);

		return Status;
	}

	*IsEncrypted = TRUE;

	if (Data)
	{
		Status = ZwReadFile(FileHandle,
			NULL,
			NULL,
			NULL,
			&IoStatus,
			Data,
			DataLength,
			NULL,
			NULL
			);
	}
	
	ZwClose(FileHandle);

	ExFreeToPagedLookasideList(&gFileNameLookAsideList, EncryptFlagFile);

	return Status;
}

NTSTATUS
SfIsFileNeedEncrypt(
	IN PDEVICE_OBJECT DeviceObject,
	IN PCWSTR FileName,
	OUT PBOOLEAN NeedEncrypt
	)
/*++

Arguments:
	FileName - x:\xxx\...\xxx.xxx

--*/
{
	UNREFERENCED_PARAMETER(DeviceObject);

	if (POLICY_ENCRYPT == SfMatchRules(FileName))
		*NeedEncrypt = TRUE;
	else
		*NeedEncrypt = FALSE;

	return STATUS_SUCCESS;
}

NTSTATUS
SfSetFileEncrypted(
	IN PDEVICE_OBJECT DeviceObject,
	IN PCWSTR FileName,
	IN BOOLEAN IsEncrypted,
	IN PVOID Data,
	IN ULONG DataLength
	)
/*++

Arguments:
	FileName - x:\xxx\...\xxx.xxx
	
--*/
{
	PSFILTER_DEVICE_EXTENSION DevExt = (PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING ObjectName;
	HANDLE FileHandle = NULL;
	IO_STATUS_BLOCK IoStatus;
	NTSTATUS Status;
	PWSTR EncryptFlagFile;
	WCHAR *Pos1 = NULL, *Pos2 = NULL;

	EncryptFlagFile = ExAllocateFromPagedLookasideList(&gFileNameLookAsideList);
	if (EncryptFlagFile == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	EncryptFlagFile[0] = L'\\';
	EncryptFlagFile[1] = L'?';
	EncryptFlagFile[2] = L'?';
	EncryptFlagFile[3] = L'\\';
	EncryptFlagFile[4] = L'\0';
	
	wcscat(EncryptFlagFile, FileName);

	if (EncryptFlagFile[wcslen(EncryptFlagFile) - 1] == L'\\')
		EncryptFlagFile[wcslen(EncryptFlagFile) - 1] = L'\0';

	wcscat(EncryptFlagFile, SF_ENCRYPT_POSTFIX);

	RtlInitUnicodeString(&ObjectName, EncryptFlagFile);
	
	InitializeObjectAttributes(&ObjectAttributes,
		&ObjectName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
		);

	if (IsEncrypted)
	{
		Pos2 = wcsrchr(EncryptFlagFile, L'\\');
		if (!Pos2)
		{
			ExFreeToPagedLookasideList(&gFileNameLookAsideList, EncryptFlagFile);
			return STATUS_INVALID_PARAMETER;
		}
		
		Pos1 = wcschr(&EncryptFlagFile[7], L'\\');
		if (Pos1)
		{
			while (Pos1 <= Pos2)
			{
				if (L'\\' == *Pos1)
				{
					*Pos1 = L'\0';
					Status = SfCreateFile(
						EncryptFlagFile,
						FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
						FALSE
						);
					if (!NT_SUCCESS(Status))
					{
						if ((STATUS_OBJECT_NAME_EXISTS != Status) &&
							(STATUS_OBJECT_NAME_COLLISION != Status))
						{
							ExFreeToPagedLookasideList(&gFileNameLookAsideList,
								EncryptFlagFile);
							return Status;
						}
					}
					*Pos1 = L'\\';
				}
		
				++Pos1;
			}
		}

		Status = ZwCreateFile(&FileHandle,
			FILE_WRITE_DATA | SYNCHRONIZE,
			&ObjectAttributes,
			&IoStatus,
			NULL,
			FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
			0,
			FILE_OVERWRITE_IF,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0
			);
		if (NT_SUCCESS(Status))
		{
			if (Data)
			{
				Status = ZwWriteFile(FileHandle,
					NULL,
					NULL,
					NULL,
					&IoStatus,
					Data,
					DataLength,
					NULL,
					NULL
					);
			}

			ZwClose(FileHandle);
		}
	}
	else
	{
		Status = ZwDeleteFile(&ObjectAttributes);
		if (!NT_SUCCESS(Status))
		{
			if ((STATUS_INVALID_PARAMETER == Status) ||
				(STATUS_OBJECT_NAME_INVALID == Status) ||
				(STATUS_OBJECT_NAME_NOT_FOUND == Status) ||
				(STATUS_OBJECT_PATH_NOT_FOUND == Status) ||
				(STATUS_OBJECT_PATH_SYNTAX_BAD == Status))
			{
				Status = STATUS_SUCCESS;
			}
		}
	}

	ExFreeToPagedLookasideList(&gFileNameLookAsideList, EncryptFlagFile);
	return Status;
}

NTSTATUS
SfUpdateFileByFileObject(
	IN PDEVICE_OBJECT DeviceObject,
	IN PFILE_OBJECT FileObject
	)
{
	IO_STATUS_BLOCK IoStatus = {0};
	NTSTATUS Status;
	PUCHAR Buffer;
	LARGE_INTEGER ByteOffset;
	ULONG Offset = 0;
	BOOLEAN EndOfFile = FALSE;

	Buffer = ExAllocatePoolWithTag(PagedPool, 512, SFLT_POOL_TAG);
	if (!Buffer)
		return STATUS_INSUFFICIENT_RESOURCES;

	ByteOffset.QuadPart = 0;

	while (TRUE)
	{
		IoStatus.Status = STATUS_SUCCESS;
		IoStatus.Information = 0;

		Status = SfIssueReadWriteIrpSynchronously(
			DeviceObject,
			FileObject,
			IRP_MJ_READ,
			&IoStatus,	
			Buffer,
			512,
			&ByteOffset,
			0
			);
		if (!NT_SUCCESS(Status))
		{
			if (STATUS_END_OF_FILE == Status)
				Status = STATUS_SUCCESS;

			break;
		}

		if (0 == IoStatus.Information)
			break;

		if (IoStatus.Information < 512)
			EndOfFile = TRUE;

		Status = SfIssueReadWriteIrpSynchronously(
			DeviceObject,
			FileObject,
			IRP_MJ_WRITE,
			&IoStatus,	
			Buffer,
			IoStatus.Information,
			&ByteOffset,
			0
			);
		if (!NT_SUCCESS(Status))
		{
			if (STATUS_END_OF_FILE == Status)
				Status = STATUS_SUCCESS;

			break;
		}

		if (EndOfFile)
			break;

		ByteOffset.QuadPart += 512;
	}

	ExFreePool(Buffer);
	return Status;
}

NTSTATUS
SfIssueReadWriteIrpSynchronously(
	IN PDEVICE_OBJECT DeviceObject,
	IN PFILE_OBJECT FileObject,
	IN ULONG MajorFunction,
	IN PIO_STATUS_BLOCK IoStatus,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset,
	IN ULONG IrpFlags
	)
{
	PIRP Irp = NULL;
	PIO_STACK_LOCATION IrpSp = NULL;
	KEVENT Event;
	NTSTATUS Status;

	ASSERT((MajorFunction == IRP_MJ_READ) || (MajorFunction == IRP_MJ_WRITE));
	
	KeInitializeEvent(&Event, NotificationEvent, FALSE);

	Irp = IoBuildSynchronousFsdRequest(
		MajorFunction,
		DeviceObject,
		Buffer,
		Length,
		ByteOffset,
		&Event,
		IoStatus
		);
	if (!Irp)
		return STATUS_INSUFFICIENT_RESOURCES;

	Irp->Flags |= IrpFlags;

	IrpSp = IoGetNextIrpStackLocation(Irp);
	IrpSp->FileObject = FileObject;

	Status = IoCallDriver(DeviceObject, Irp);
	if (STATUS_PENDING == Status)
	{
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
	}

	return IoStatus->Status;
}

NTSTATUS
SfIssueCleanupIrpSynchronously(
	IN PDEVICE_OBJECT NextDeviceObject,
	IN PIRP Irp,
	IN PFILE_OBJECT FileObject
	)
{
	PIO_STACK_LOCATION IrpSp = NULL;
	IO_STATUS_BLOCK IoStatus;
	KEVENT Event;

	KeInitializeEvent(&Event, NotificationEvent, FALSE);
	KeClearEvent(&FileObject->Event);

	Irp->Tail.Overlay.OriginalFileObject = FileObject;
	Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	Irp->Overlay.AsynchronousParameters.UserApcRoutine = (PIO_APC_ROUTINE) NULL;
	Irp->RequestorMode = KernelMode;
	Irp->UserEvent = &Event;
	Irp->UserIosb = &IoStatus;
	Irp->Flags = IRP_SYNCHRONOUS_API | IRP_CLOSE_OPERATION;

	IrpSp = IoGetNextIrpStackLocation(Irp);
	IrpSp->MajorFunction = IRP_MJ_CLEANUP;
	IrpSp->FileObject = FileObject;

	if (STATUS_PENDING == IoCallDriver(NextDeviceObject, Irp))
	{
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
	}

	return IoStatus.Status;
}

NTSTATUS
SfCreateFile(
	IN PCWSTR FileName,
	IN ULONG FileAttributes,
	IN BOOLEAN IsFile
	)
/*++

Arguments:
	FileName - \??\x:\xxx\...\xxx.xxx

--*/
{
	HANDLE FileHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING ObjectName;
	IO_STATUS_BLOCK IoStatus;
	NTSTATUS Status;
	
	RtlInitUnicodeString(&ObjectName, FileName);

	InitializeObjectAttributes(
		&ObjectAttributes,
		&ObjectName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
		);

	if (IsFile)
	{
		Status = ZwCreateFile(&FileHandle,
			FILE_READ_ATTRIBUTES,
			&ObjectAttributes,
			&IoStatus,
			NULL,
			FileAttributes,
			0,
			FILE_OPEN_IF,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0
			);
	}
	else
	{
		Status = ZwCreateFile(&FileHandle,
			FILE_READ_ATTRIBUTES,
			&ObjectAttributes,
			&IoStatus,
			NULL,
			FileAttributes,
			0,
			FILE_OPEN_IF,
			FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0
			);
	}

	if (NT_SUCCESS(Status))
		ZwClose(FileHandle);

	return Status;
}

NTSTATUS
SfRenameFile(
	IN PWSTR SrcFileName,
	IN PWSTR DstFileName
	)
/*++

Arguments:
	SrcFileName - \??\x:\xxx\...\xxx.xxx
	DstFileName - \??\x:\xxx\...\xxx.xxx

--*/
{
	HANDLE FileHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatus;
	NTSTATUS Status;
	PFILE_RENAME_INFORMATION RenameInfo = NULL;
	UNICODE_STRING ObjectName;

	RenameInfo = (PFILE_RENAME_INFORMATION) ExAllocatePoolWithTag(
		NonPagedPool,
		sizeof(FILE_RENAME_INFORMATION) + MAX_PATH * sizeof(WCHAR),
		SFLT_POOL_TAG
		);
	if (RenameInfo == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory(RenameInfo, sizeof(FILE_RENAME_INFORMATION) + MAX_PATH * sizeof(WCHAR));
	RenameInfo->FileNameLength = wcslen(DstFileName) * sizeof(WCHAR);
	wcscpy(RenameInfo->FileName, DstFileName);
	RenameInfo->ReplaceIfExists = 0;
	RenameInfo->RootDirectory = NULL;

	RtlInitUnicodeString(&ObjectName, SrcFileName);
	
	InitializeObjectAttributes(
		&ObjectAttributes,
		&ObjectName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
		);
	
	Status = ZwCreateFile(
		&FileHandle,
		SYNCHRONIZE | DELETE,
		&ObjectAttributes,
		&IoStatus,
		NULL,
		0,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING,
		NULL,
		0);
	if (!NT_SUCCESS(Status))
	{
		ExFreePoolWithTag(RenameInfo, SFLT_POOL_TAG);
		return Status;
	}

	Status = ZwSetInformationFile(
		FileHandle,
		&IoStatus,
		RenameInfo,
		sizeof(FILE_RENAME_INFORMATION) + MAX_PATH * sizeof(WCHAR),
		FileRenameInformation
		);
	if (!NT_SUCCESS(Status))
	{
		ExFreePoolWithTag(RenameInfo, SFLT_POOL_TAG);
		ZwClose(FileHandle);
		return Status;
	}

	ZwClose(FileHandle);
	return Status;
}

NTSTATUS
SfForwardIrpSyncronouslyCompletion (
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context
	)
{
	PKEVENT Event = Context;

	UNREFERENCED_PARAMETER(DeviceObject);

	ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

	if (Irp->PendingReturned)
	{
		KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
	}

	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
SfForwardIrpSyncronously(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	KEVENT Event;
	NTSTATUS Status;

	KeInitializeEvent(&Event, NotificationEvent, FALSE);
	IoCopyCurrentIrpStackLocationToNext(Irp);
	IoSetCompletionRoutine(Irp, SfForwardIrpSyncronouslyCompletion, &Event, TRUE, TRUE, TRUE);
	Status = IoCallDriver(DeviceObject, Irp);
	if (STATUS_PENDING == Status)
	{
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
		Status = Irp->IoStatus.Status;
	}
	return Status;
}

NTSTATUS
SfLoadRules(
	OUT PHANDLE FileHandle
	)
{
	UNICODE_STRING FileName;
	IO_STATUS_BLOCK IoStatus;
	FILE_STANDARD_INFORMATION StandardInfo;
	ULONG Length;
	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS Status;
	PRULE Rule;
	
	RtlInitUnicodeString(&FileName, RULE_FILE_NAME);
	
	InitializeObjectAttributes(&ObjectAttributes,
		&FileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
		);

	do
	{
		Status = ZwCreateFile(FileHandle,
			(SYNCHRONIZE | FILE_READ_DATA),
			&ObjectAttributes,
			&IoStatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			0,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING,
			NULL,
			0
			);
		if (!NT_SUCCESS(Status))
		{
			*FileHandle = NULL;
			break;
		}

		Status = ZwQueryInformationFile(*FileHandle,
			&IoStatus,
			&StandardInfo,
			sizeof(FILE_STANDARD_INFORMATION),
			FileStandardInformation
			);
		if (!NT_SUCCESS(Status))
		{
			ZwClose(*FileHandle);
			*FileHandle = NULL;
			break;
		}

		Length = StandardInfo.EndOfFile.LowPart;
		if (Length % sizeof(RULE) != 4)
		{
			Status = STATUS_INVALID_PARAMETER;
			ZwClose(*FileHandle);
			*FileHandle = NULL;
			break;
		}

		Rule = (PRULE) ExAllocatePoolWithTag(NonPagedPool, Length - 4 + sizeof(RULE), SFLT_POOL_TAG);
		if (!Rule)
		{
			Status = STATUS_INSUFFICIENT_RESOURCES;
			ZwClose(*FileHandle);
			*FileHandle = NULL;
			break;
		}
			
		Status = ZwReadFile(*FileHandle,
			NULL,
			NULL,
			NULL,
			&IoStatus,
			Rule,
			Length,
			NULL,
			NULL
			);
		if ((!NT_SUCCESS(Status)) || (IoStatus.Information != Length))
		{
			ExFreePoolWithTag(Rule, SFLT_POOL_TAG);
			Rule = NULL;
			ZwClose(*FileHandle);
			*FileHandle = NULL;
			break;
		}

		ZwClose(*FileHandle);
		*FileHandle = NULL;
/*
		{
			PULONG Data = (PULONG) Rule;
			ULONG CRC = 0;
			ULONG i;
			ULONG TmpLength = Length / 4;

			for (i = 0; i < TmpLength - 1; ++i)
				CRC += Data[i];

			if (CRC != Data[TmpLength - 1])
			{
				Status = STATUS_INVALID_PARAMETER;
				ExFreePoolWithTag(Rule, SFLT_POOL_TAG);
				Rule = NULL;
				break;
			}
		}		
*/
		((PRULE)((PUCHAR) Rule + Length - 4))->Policy = POLICY_END;

	    ExAcquireResourceSharedLite(&gRulesResource, TRUE);
	    if (gRules)
	    	ExFreePool(gRules);
		gRules = Rule;
		ExReleaseResourceLite(&gRulesResource);

	} while (FALSE);

	return Status;
}

ULONG 
SfMatchRules(
	IN PCWSTR FileName
	)
{
	PRULE Rule;
	PWSTR Pattern = NULL;
	ULONG Policy = POLICY_NONE;

	KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&gRulesResource, TRUE);
	
	Rule = gRules;
	if (Rule == NULL)
	{
		ExReleaseResourceLite(&gRulesResource);
		KeLeaveCriticalRegion();
		return POLICY_NONE;
	}

	for (; Rule->Policy != POLICY_END; ++Rule)
	{
		Pattern = Rule->Pattern;
		Pattern[MAX_PATH - 1] = L'\0';
		
		if (!SfMatchWithPattern(Pattern, FileName))
			continue;

		Policy = Rule->Policy;
		break;
	}

	ExReleaseResourceLite(&gRulesResource);
	KeLeaveCriticalRegion();
	
	return Policy;
}

BOOLEAN
SfMatchWithPattern(
	IN PCWSTR Pattern,
	IN PCWSTR Name
	)
{
    WCHAR Upcase;

	if ((!Name) || (!Pattern))
		return FALSE;
	
    //
    // End of pattern and name?
    //
    if ((!*Pattern) && (!*Name)) 
        return TRUE;

	if (!*Pattern) //Pattern is Empty, Name not Empty
		return FALSE;

	if (!*Name)//Name is Enpty, Pattern not Enpty
		return SfMatchOkay(Pattern);

    //
    // If we hit a wild card, do recursion
    //
    if (*Pattern == L'*') 
	{
		while (*Pattern == L'*')
			Pattern++;

		if (!*Pattern)
			return TRUE;

		while (*Name)
		{
            if (*Name >= L'a' && *Name <= L'z')
                Upcase = *Name - L'a' + L'A';
            else
                Upcase = *Name;

            //
            // See if this substring matches
            //
            if ((*Pattern == Upcase) || (*Pattern == L'?')) 
			{
                if (SfMatchWithPattern(Pattern + 1, Name + 1)) 
                    return TRUE;
            }

            //
            // Try the next substring
            //
            Name++;
        }

        //
        // See if match condition was met
        //
        return FALSE;
    } 

    //
    // Do straight compare until we hit a wild card
    //
    while (*Name && *Pattern != L'*') 
	{
        if (*Name >= L'a' && *Name <= L'z')
            Upcase = *Name - L'a' + L'A';
        else
            Upcase = *Name;

        if ((*Pattern == Upcase) || (*Pattern == L'?')) 
		{
            Pattern++;
            Name++;
        } 
		else 
            return FALSE;
    }

    //
    // If not done, recurse
    //
    if (*Name) // *Pattern == '*'
        return SfMatchWithPattern(Pattern, Name);

    //
    // Make sure its a match
    //
    return SfMatchOkay(Pattern); // *Name == '\0'
}

BOOLEAN
SfMatchOkay(
	IN PCWSTR Pattern
	)
{
    //
    // If pattern isn't empty, it must be a wildcard
    //
	while (*Pattern)
	{
		if (*Pattern != L'*')
			return FALSE;
		
		Pattern++;
	}

    //
    // Matched
    //
    return TRUE;
}

#define FAT_NTC_FCB						0x0502
#define NTFS_NTC_FCB					0x0705

BOOLEAN
SfIsObjectFile(
	IN PFILE_OBJECT FileObject
	)
{
	PFSRTL_COMMON_FCB_HEADER fcb = (PFSRTL_COMMON_FCB_HEADER) FileObject->FsContext;

	KdPrint(("sfilter!SfIsObjectFile: fcb->NodeTypeCode = %x\n", fcb->NodeTypeCode));

	if (fcb->NodeTypeCode == FAT_NTC_FCB)
		return TRUE;
	else if (fcb->NodeTypeCode == NTFS_NTC_FCB)
		return TRUE;

	return FALSE;
}

NTSTATUS
SfQuerySymbolicLink(
    IN  PUNICODE_STRING SymbolicLinkName,
    OUT PUNICODE_STRING LinkTarget
    )
/*++

Routine Description:

    This routine returns the target of the symbolic link name.

Arguments:

    SymbolicLinkName    - Supplies the symbolic link name.

    LinkTarget          - Returns the link target.

Return Value:

    NTSTATUS

--*/

{
    HANDLE Handle;
    OBJECT_ATTRIBUTES ObjAttribute;
    NTSTATUS Status;

    InitializeObjectAttributes(&ObjAttribute, SymbolicLinkName, OBJ_CASE_INSENSITIVE,
                               0, 0);

    Status = ZwOpenSymbolicLinkObject(&Handle, GENERIC_READ, &ObjAttribute);
    if (!NT_SUCCESS(Status))
        return Status;

    LinkTarget->MaximumLength = 200*sizeof(WCHAR);
    LinkTarget->Length = 0;
    LinkTarget->Buffer = ExAllocatePool(PagedPool, LinkTarget->MaximumLength);
    if (!LinkTarget->Buffer)
    {
        ZwClose(Handle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = ZwQuerySymbolicLinkObject(Handle, LinkTarget, NULL);
    ZwClose(Handle);

    if (!NT_SUCCESS(Status))
        ExFreePool(LinkTarget->Buffer);

    return Status;
}

NTSTATUS
SfVolumeDeviceNameToDosName(
    IN PUNICODE_STRING VolumeDeviceName,
    OUT PUNICODE_STRING DosName
    )
/*++

Routine Description:

    This routine returns a valid DOS path for the given device object.
    This caller of this routine must call ExFreePool on DosName->Buffer
    when it is no longer needed.

Arguments:

    VolumeDeviceName    - Supplies the volume device object.

    DosName             - Returns the DOS name for the volume

Return Value:

    NTSTATUS

--*/

{
    WCHAR Buffer[30];
    UNICODE_STRING DriveLetterName;
    UNICODE_STRING LinkTarget;
    WCHAR Char;
    NTSTATUS Status;

    swprintf(Buffer, L"\\??\\C:");
    RtlInitUnicodeString(&DriveLetterName, Buffer);

    for (Char = 'A'; Char <= 'Z'; Char++)
    {
        DriveLetterName.Buffer[4] = Char;

        Status = SfQuerySymbolicLink(&DriveLetterName, &LinkTarget);
        if (!NT_SUCCESS(Status))
            continue;

        if (RtlEqualUnicodeString(&LinkTarget, VolumeDeviceName, TRUE))
        {
            ExFreePool(LinkTarget.Buffer);
            break;
        }

        ExFreePool(LinkTarget.Buffer);
    }

    if (Char <= 'Z')
    {
        DosName->Buffer = ExAllocatePool(PagedPool, 3*sizeof(WCHAR));
        if (!DosName->Buffer)
            return STATUS_INSUFFICIENT_RESOURCES;

        DosName->MaximumLength = 6;
        DosName->Length = 4;
        DosName->Buffer[0] = Char;
        DosName->Buffer[1] = ':';
        DosName->Buffer[2] = 0;

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


