#pragma once

GUEST_REGS g_GuestRegs[128];

void HandleCPUID()
{
	ULONG uCPUID;
	uCPUID = KeGetCurrentProcessorNumber();
	if (g_GuestRegs[uCPUID].eax == 'Mini')
	{
		g_GuestRegs[uCPUID].ebx = 0x88888888;
		g_GuestRegs[uCPUID].ecx = 0x11111111;
		g_GuestRegs[uCPUID].edx = 0x12345678;
	}
	else Asm_CPUID(g_GuestRegs[uCPUID].eax, &g_GuestRegs[uCPUID].eax, &g_GuestRegs[uCPUID].ebx, &g_GuestRegs[uCPUID].ecx, &g_GuestRegs[uCPUID].edx);
}

void HandleInvd()
{
	Asm_Invd();
}

void HandleVmCall()
{
	ULONG JmpEIP;
	ULONG uCPUID;
	uCPUID = KeGetCurrentProcessorNumber();
	if (g_GuestRegs[uCPUID].eax == 'SVT')
	{
		JmpEIP = g_GuestRegs[uCPUID].eip + Vmx_VmRead(VM_EXIT_INSTRUCTION_LEN);
		Vmx_VmxOff();

		Asm_AfterVMXOff(g_GuestRegs[uCPUID].esp, JmpEIP);
	}
}

void HandleMsrRead()
{
	ULONG uCPUID;
	uCPUID = KeGetCurrentProcessorNumber();
	switch (g_GuestRegs[uCPUID].ecx)
	{
	case MSR_IA32_SYSENTER_CS:
	{
		g_GuestRegs[uCPUID].eax = Vmx_VmRead(GUEST_SYSENTER_CS);
		break;
	}
	case MSR_IA32_SYSENTER_ESP:
	{
		g_GuestRegs[uCPUID].eax = Vmx_VmRead(GUEST_SYSENTER_ESP);
		break;
	}
	case MSR_IA32_SYSENTER_EIP:	// KiFastCallEntry
	{
		g_GuestRegs[uCPUID].eax = Vmx_VmRead(GUEST_SYSENTER_EIP);
		break;
	}
	default:
		g_GuestRegs[uCPUID].eax = Asm_ReadMsr(g_GuestRegs[uCPUID].ecx);
	}

}

void HandleMsrWrite()
{
	ULONG uCPUID;
	uCPUID = KeGetCurrentProcessorNumber();
	switch (g_GuestRegs[uCPUID].ecx)
	{
	case MSR_IA32_SYSENTER_CS:
	{
		Vmx_VmWrite(GUEST_SYSENTER_CS, g_GuestRegs[uCPUID].eax);
		break;
	}
	case MSR_IA32_SYSENTER_ESP:
	{
		Vmx_VmWrite(GUEST_SYSENTER_ESP, g_GuestRegs[uCPUID].eax);
		break;
	}
	case MSR_IA32_SYSENTER_EIP:	// KiFastCallEntry
	{
		Vmx_VmWrite(GUEST_SYSENTER_EIP, g_GuestRegs[uCPUID].eax);
		break;
	}
	default:
		Asm_WriteMsr(g_GuestRegs[uCPUID].ecx, g_GuestRegs[uCPUID].eax, g_GuestRegs[uCPUID].edx);
	}
}

void HandleCrAccess()
{
	ULONG		movcrControlRegister;
	ULONG		movcrAccessType;
	ULONG		movcrOperandType;
	ULONG		movcrGeneralPurposeRegister;
	ULONG		movcrLMSWSourceData;
	ULONG		ExitQualification;
	ULONG		uCPUID;

	uCPUID = KeGetCurrentProcessorNumber();

	ExitQualification = Vmx_VmRead(EXIT_QUALIFICATION);
	movcrControlRegister = (ExitQualification & 0x0000000F);
	movcrAccessType = ((ExitQualification & 0x00000030) >> 4);
	movcrOperandType = ((ExitQualification & 0x00000040) >> 6);
	movcrGeneralPurposeRegister = ((ExitQualification & 0x00000F00) >> 8);

	//	Control Register Access (CR3 <-- reg32)
	//
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 0)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs[uCPUID].eax);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 1)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs[uCPUID].ecx);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 2)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs[uCPUID].edx);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 3)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs[uCPUID].ebx);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 4)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs[uCPUID].esp);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 5)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs[uCPUID].ebp);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 6)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs[uCPUID].esi);
	}
	if (movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 7)
	{
		Vmx_VmWrite(GUEST_CR3, g_GuestRegs[uCPUID].edi);
	}
	//	Control Register Access (reg32 <-- CR3)
	//
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 0)
	{
		g_GuestRegs[uCPUID].eax = g_GuestRegs[uCPUID].cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 1)
	{
		g_GuestRegs[uCPUID].ecx = g_GuestRegs[uCPUID].cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 2)
	{
		g_GuestRegs[uCPUID].edx = g_GuestRegs[uCPUID].cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 3)
	{
		g_GuestRegs[uCPUID].ebx = g_GuestRegs[uCPUID].cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 4)
	{
		g_GuestRegs[uCPUID].esp = g_GuestRegs[uCPUID].cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 5)
	{
		g_GuestRegs[uCPUID].ebp = g_GuestRegs[uCPUID].cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 6)
	{
		g_GuestRegs[uCPUID].esi = g_GuestRegs[uCPUID].cr3;
	}
	if (movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 7)
	{
		g_GuestRegs[uCPUID].edi = g_GuestRegs[uCPUID].cr3;
	}
}

ULONG GetGuestRegsAddress()
{
	ULONG uCPUID;
	uCPUID = KeGetCurrentProcessorNumber();
	return (ULONG)&g_GuestRegs[uCPUID];
}

VOID VMMEntryPoint()
{
	ULONG ExitReason;
	ULONG ExitInstructionLength;
	ULONG GuestResumeEIP;
	ULONG uCPUID;

	uCPUID = KeGetCurrentProcessorNumber();

	ExitReason = Vmx_VmRead(VM_EXIT_REASON);
	ExitInstructionLength = Vmx_VmRead(VM_EXIT_INSTRUCTION_LEN);

	g_GuestRegs[uCPUID].esp = Vmx_VmRead(GUEST_RSP);
	g_GuestRegs[uCPUID].eip = Vmx_VmRead(GUEST_RIP);
	g_GuestRegs[uCPUID].cr3 = Vmx_VmRead(GUEST_CR3);

	switch (ExitReason)
	{
	case EXIT_REASON_CPUID:
	{
		HandleCPUID();
		break;
	}
	case EXIT_REASON_INVD:
	{
		HandleInvd();
		break;
	}
	case EXIT_REASON_VMCALL:
	{
		HandleVmCall();
		break;
	}
	case EXIT_REASON_MSR_READ:
	{
		HandleMsrRead();
		break;
	}
	case EXIT_REASON_MSR_WRITE:
	{
		HandleMsrWrite();
		break;
	}
	case EXIT_REASON_CR_ACCESS:
	{
		HandleCrAccess();
		break;
	}
	default:
		break;
	}

Resume:
	GuestResumeEIP = g_GuestRegs[uCPUID].eip + ExitInstructionLength;
	Vmx_VmWrite(GUEST_RIP, GuestResumeEIP);
	Vmx_VmWrite(GUEST_RSP, g_GuestRegs[uCPUID].esp);
}