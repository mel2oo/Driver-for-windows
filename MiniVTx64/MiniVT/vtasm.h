#pragma  once

#include <ntddk.h>

typedef union
{
	struct
	{
		unsigned PE:1;
		unsigned MP:1;
		unsigned EM:1;
		unsigned TS:1;
		unsigned ET:1;
		unsigned NE:1;
		unsigned Reserved_1:10;
		unsigned WP:1;
		unsigned Reserved_2:1;
		unsigned AM:1;
		unsigned Reserved_3:10;
		unsigned NW:1;
		unsigned CD:1;
		unsigned PG:1;
		unsigned Reserved_64:32;
	};

}_CR0;

typedef union
{
	struct{
		unsigned VME:1;
		unsigned PVI:1;
		unsigned TSD:1;
		unsigned DE:1;
		unsigned PSE:1;
		unsigned PAE:1;
		unsigned MCE:1;
		unsigned PGE:1;
		unsigned PCE:1;
		unsigned OSFXSR:1;
		unsigned PSXMMEXCPT:1;
		unsigned UNKONOWN_1:1;		//These are zero
		unsigned UNKONOWN_2:1;		//These are zero
		unsigned VMXE:1;			//It's zero in normal
		unsigned Reserved:18;		//These are zero
		unsigned Reserved_64:32;
	};
}_CR4;

typedef union
{
	struct
	{
		unsigned CF:1;
		unsigned Unknown_1:1;	//Always 1
		unsigned PF:1;
		unsigned Unknown_2:1;	//Always 0
		unsigned AF:1;
		unsigned Unknown_3:1;	//Always 0
		unsigned ZF:1;
		unsigned SF:1;
		unsigned TF:1;
		unsigned IF:1;
		unsigned DF:1;
		unsigned OF:1;
		unsigned TOPL:2;
		unsigned NT:1;
		unsigned Unknown_4:1;
		unsigned RF:1;
		unsigned VM:1;
		unsigned AC:1;
		unsigned VIF:1;
		unsigned VIP:1;
		unsigned ID:1;
		unsigned Reserved:10;	//Always 0
		unsigned Reserved_64:32;	//Always 0
	};
}_EFLAGS;

typedef union
{
	struct
	{
		unsigned SSE3:1;
		unsigned PCLMULQDQ:1;
		unsigned DTES64:1;
		unsigned MONITOR:1;
		unsigned DS_CPL:1;
		unsigned VMX:1;
		unsigned SMX:1;
		unsigned EIST:1;
		unsigned TM2:1;
		unsigned SSSE3:1;
		unsigned Reserved:22;
		unsigned Reserved_64 : 32;
	};

}_CPUID_RCX;

typedef struct _IA32_FEATURE_CONTROL_MSR
{
	unsigned Lock			:1;		// Bit 0 is the lock bit - cannot be modified once lock is set
	unsigned Reserved1		:1;		// Undefined
	unsigned EnableVmxon	:1;		// Bit 2. If this bit is clear, VMXON causes a general protection exception
	unsigned Reserved2		:29;	// Undefined
	unsigned Reserved3		:32;	// Undefined

} IA32_FEATURE_CONTROL_MSR;

typedef struct _VMX_BASIC_MSR
{
	unsigned RevId: 32;
	unsigned szVmxOnRegion: 12;
	unsigned ClearBit: 1;
	unsigned Reserved: 3;
	unsigned PhysicalWidth: 1;
	unsigned DualMonitor: 1;
	unsigned MemoryType: 4;
	unsigned VmExitInformation: 1;
	unsigned Reserved2: 9;
} VMX_BASIC_MSR, *PVMX_BASIC_MSR;

ULONG64 Asm_GetRflags();
ULONG64 Asm_GetCs();
ULONG64 Asm_GetDs();
ULONG64 Asm_GetEs();
ULONG64 Asm_GetFs();
ULONG64 Asm_GetGs();
ULONG64 Asm_GetSs();
ULONG64 Asm_GetLdtr();
ULONG64 Asm_GetTr();

void Asm_SetGdtr(ULONG64 uBase,ULONG64 uLimit);
void Asm_SetIdtr(ULONG64 uBase,ULONG64 uLimit);

ULONG64 Asm_GetGdtBase();
ULONG64 Asm_GetIdtBase();
ULONG64 Asm_GetGdtLimit();
ULONG64 Asm_GetIdtLimit();

ULONG64 Asm_GetCr0();
ULONG64 Asm_GetCr2();
ULONG64 Asm_GetCr3();
ULONG64 Asm_GetCr4();
void Asm_SetCr0(ULONG64 uNewCr0);
void Asm_SetCr2(ULONG64 uNewCr2);
void Asm_SetCr3(ULONG64 uNewCr3);
void Asm_SetCr4(ULONG64 uNewCr4);

ULONG64 Asm_GetDr0();
ULONG64 Asm_GetDr1();
ULONG64 Asm_GetDr2();
ULONG64 Asm_GetDr3();
ULONG64 Asm_GetDr6();
ULONG64 Asm_GetDr7();
void Asm_SetDr0(ULONG64 uNewDr0);
void Asm_SetDr1(ULONG64 uNewDr1);
void Asm_SetDr2(ULONG64 uNewDr2);
void Asm_SetDr3(ULONG64 uNewDr3);
void Asm_SetDr6(ULONG64 uNewDr6);
void Asm_SetDr7(ULONG64 uNewDr7);

ULONG64 Asm_ReadMsr(ULONG64 uIndex);
void Asm_WriteMsr(ULONG64 uIndex,ULONG64 QuadPart);

void Asm_CPUID(ULONG64 uFn,PULONG64 uRet_RAX,PULONG64 uRet_RBX,PULONG64 uRet_RCX,PULONG64 uRet_RDX);
void Asm_Invd();

void Vmx_VmxOn(ULONG64 QuadPartt);
void Vmx_VmxOff();
void Vmx_VmClear(ULONG64 QuadPart);
void Vmx_VmPtrld(ULONG64 QuadPart);
ULONG64 Vmx_VmRead(ULONG64 uField);
void Vmx_VmWrite(ULONG64 uField, ULONG64 uValue);
void Vmx_VmLaunch();
void Vmx_VmResume();
void Vmx_VmCall(ULONG64 uCallNumber);

void Asm_VMMEntryPoint();

void Asm_SetupVMCS();

ULONG64 Asm_GetGuestReturn();
ULONG64 Asm_GetGuestRSP();

void Asm_AfterVMXOff(ULONG64 JmpRSP, ULONG64 JmpEIP);
