/* Copyright (c) 2002-2005 Vladislav Goncharov.
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 */
 
// -*- mode: C++; tab-width: 4; indent-tabs-mode: nil -*- (for GNU Emacs)
//
// $Id: disp_obj.c,v 1.10 2003/09/04 15:20:09 dev Exp $

/*
 * This file contains TDI_CREATE, TDI_CLEANUP, TDI_ASSOCIATE_ADDRESS and
 * TDI_DISASSOCIATE_ADDRESS handlers
 */

#include <ntddk.h>
#include <tdikrnl.h>
#include "sock.h"

#include "conn_state.h"
#include "dispatch.h"
#include "events.h"
#include "memtrack.h"
#include "obj_tbl.h"
#include "pid_pname.h"
#include "sids.h"
#include "tdi_fw.h"

/* IRP completion routines and their contexts */

static NTSTATUS	tdi_create_addrobj_complete(
	IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);

// context for tdi_create_addrobj_complete2
typedef struct {
	TDI_ADDRESS_INFO	*tai;		/* address info -- result of TDI_QUERY_ADDRESS_INFO */
	PFILE_OBJECT		fileobj;	/* FileObject from IO_STACK_LOCATION */
} TDI_CREATE_ADDROBJ2_CTX;

static NTSTATUS tdi_create_addrobj_complete2(
	IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);

//----------------------------------------------------------------------------

/*
 * TDI_CREATE handler
 */

int
tdi_create(PIRP irp, PIO_STACK_LOCATION irps, struct completion *completion)
{
	NTSTATUS status;
	FILE_FULL_EA_INFORMATION *ea = (FILE_FULL_EA_INFORMATION *)irp->AssociatedIrp.SystemBuffer;

	/* pid resolving stuff: a good place for it (PASSIVE level, begin of working with TDI-objects) */
	ULONG pid = (ULONG)PsGetCurrentProcessId();

	//获取进程的PID和进程名
	// if process name is unknown try to resolve it
	if (!pid_pname_resolve(pid, NULL, 0)) {
		KEVENT event;
		struct flt_request request;
	
		KeInitializeEvent(&event, NotificationEvent, FALSE);
		pid_pname_set_event(pid, &event);

		memset(&request, 0, sizeof(request));
		request.struct_size = sizeof(request);

		request.type = TYPE_RESOLVE_PID;
		request.pid = pid;

		// get user SID & attributes!
		request.sid_a = get_current_sid_a(&request.sid_a_size);
		
		if (log_request(&request)) {
			// wait a little for reply from user-mode application
			LARGE_INTEGER li;
			li.QuadPart = 5000 * -10000;	// 5 sec

			status = KeWaitForSingleObject(&event, UserRequest, KernelMode, FALSE, &li);

		} else {
			// check all rulesets: we've got the only _default_ ruleset active
			status = default_chain_only() ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		}

		if (request.sid_a != NULL)
			free(request.sid_a);

		// reset wait event
		pid_pname_set_event(pid, NULL);

		if (status != STATUS_SUCCESS)
			return FILTER_DENY;			// deny it!
	}

	/* TDI_CREATE related stuff */

	if (ea != NULL) {
		/*
		 * We have FILE_FULL_EA_INFORMATION
		 */
		
		PDEVICE_OBJECT devobj;
		int ipproto;
		
		devobj = get_original_devobj(irps->DeviceObject, &ipproto);
		if (devobj == NULL) {
			KdPrint(("[tdi_fw] tdi_create: unknown device object 0x%x!\n", irps->DeviceObject));
			return FILTER_DENY;
		}
		// NOTE: for RawIp you can extract protocol number from irps->FileObject->FileName
		//如果ea不为空，且满足下面这个if条件，那么是在create里生成了一个地址对象，
		//因此需要在这个IRP结束之后，在完成例程里查询本地地址和端口
		//见下面的tdi_create_addrobj_complete完成例程，这时候就是生成地址
		if (ea->EaNameLength == TDI_TRANSPORT_ADDRESS_LENGTH &&
			memcmp(ea->EaName, TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH) == 0) {

			PIRP query_irp;

			/*
			 * This is creation of address object
			 */

			KdPrint(("[tdi_fw] tdi_create: devobj 0x%x; addrobj 0x%x\n",
				irps->DeviceObject,
				irps->FileObject));
			//将地址对象irps->FileObject加入HASH表g_ot_hash
			status = ot_add_fileobj(irps->DeviceObject, irps->FileObject, FILEOBJ_ADDROBJ, ipproto, NULL);
			if (status != STATUS_SUCCESS) {
				KdPrint(("[tdi_fw] tdi_create: ot_add_fileobj: 0x%x\n", status));
				return FILTER_DENY;
			}

			// while we're on PASSIVE_LEVEL build control IRP for completion，添加进去之后下面创建了个查询IRP
			query_irp = TdiBuildInternalDeviceControlIrp(TDI_QUERY_INFORMATION,
				devobj, irps->FileObject, NULL, NULL);
			if (query_irp == NULL) {
				KdPrint(("[tdi_fw] tdi_create: TdiBuildInternalDeviceControlIrp\n"));
				return FILTER_DENY;
			}

			/* set IRP completion & context for completion */
			//tdi_create_addrobj_complete是irp的完成例程调用
			//tdi_create_addrobj_complete2是query_irp完成后调用
			completion->routine = tdi_create_addrobj_complete;
			completion->context = query_irp;//把查询IRP放到了上下文结构体中。

		} else if (ea->EaNameLength == TDI_CONNECTION_CONTEXT_LENGTH &&
			memcmp(ea->EaName, TdiConnectionContext, TDI_CONNECTION_CONTEXT_LENGTH) == 0) {
			
			/*
			 * This is creation of connection object
			 */
			//如果ea不为空，且满足下面这个if条件，那么是在create里生成了一个连接对象，
			//irps->FileObject为连接对象，并将该连接对象加入HASH表：g_ot_hash
			//在TDI_ASSOCIATE_ADDRESS对应的次功能号中，会将地址对象和连接对象关联起来。
			//对于udp,地址对象和连接对象是同一个对象
			//关联的时候是在：tdi_associate_address函数中完成

			CONNECTION_CONTEXT conn_ctx = *(CONNECTION_CONTEXT *)
				(ea->EaName + ea->EaNameLength + 1);

			KdPrint(("[tdi_fw] tdi_create: devobj 0x%x; connobj 0x%x; conn_ctx 0x%x\n",
				irps->DeviceObject,
				irps->FileObject,
				conn_ctx));
			//将该连接对象加入HASH表：g_ot_hash
			status = ot_add_fileobj(irps->DeviceObject, irps->FileObject,
				FILEOBJ_CONNOBJ, ipproto, conn_ctx);

			if (status != STATUS_SUCCESS) {
				KdPrint(("[tdi_fw] tdi_create: ot_add_fileobj: 0x%x\n", status));
				return FILTER_DENY;
			}
		}
	
	} else {
		/*
		 * This is creation of control object
		 */
		
		KdPrint(("[tdi_fw] tdi_create(pid:%u): devobj 0x%x; Control Object: 0x%x\n",
			pid, irps->DeviceObject, irps->FileObject));
	}

	return FILTER_ALLOW;
}

/* this completion routine queries address and port from address object */
NTSTATUS
tdi_create_addrobj_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(Irp);
	PIRP query_irp = (PIRP)Context;
	PDEVICE_OBJECT devobj;
	TDI_CREATE_ADDROBJ2_CTX *ctx = NULL;
	PMDL mdl = NULL;

	KdPrint(("[tdi_fw] tdi_create_addrobj_complete: devobj 0x%x; addrobj 0x%x\n",
		DeviceObject, irps->FileObject));

	if (Irp->IoStatus.Status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: status 0x%x\n", Irp->IoStatus.Status));

		status = Irp->IoStatus.Status;
		goto done;
	}

	// query addrobj address:port

	ctx = (TDI_CREATE_ADDROBJ2_CTX *)malloc_np(sizeof(TDI_CREATE_ADDROBJ2_CTX));
	if (ctx == NULL) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: malloc_np\n"));
		
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	ctx->fileobj = irps->FileObject;

	ctx->tai = (TDI_ADDRESS_INFO *)malloc_np(TDI_ADDRESS_INFO_MAX);
	if (ctx->tai == NULL) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: malloc_np!\n"));

		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	mdl = IoAllocateMdl(ctx->tai, TDI_ADDRESS_INFO_MAX, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: IoAllocateMdl!\n"));
		
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	MmBuildMdlForNonPagedPool(mdl);

	devobj = get_original_devobj(DeviceObject, NULL);	// use original devobj!
	if (devobj == NULL) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: get_original_devobj!\n"));

		status = STATUS_INVALID_PARAMETER;
		goto done;
	}

	TdiBuildQueryInformation(query_irp, devobj, irps->FileObject,//在这个下发的完成例程tdi_create_addrobj_complete2，拿到ip地址和端口
		tdi_create_addrobj_complete2, ctx,
		TDI_QUERY_ADDRESS_INFO, mdl);

	status = IoCallDriver(devobj, query_irp);
	query_irp = NULL;
	mdl = NULL;
	ctx = NULL;

	if (status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: IoCallDriver: 0x%x\n", status));
		goto done;
	}

	status = STATUS_SUCCESS;

done:
	// cleanup
	if (mdl != NULL)
		IoFreeMdl(mdl);
	
	if (ctx != NULL) {
		if (ctx->tai != NULL)
			free(ctx->tai);
		free(ctx);
	}
	
	if (query_irp != NULL)
		IoCompleteRequest(query_irp, IO_NO_INCREMENT);

	Irp->IoStatus.Status = status;
	
	if (status != STATUS_SUCCESS) {
		// tdi_create failed - remove fileobj from hash
		ot_del_fileobj(irps->FileObject, NULL);
	}

	return tdi_generic_complete(DeviceObject, Irp, Context);
}

/* this completion routine gets address and port from reply to TDI_QUERY_ADDRESS_INFO */
NTSTATUS
tdi_create_addrobj_complete2(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	NTSTATUS status;
	TDI_CREATE_ADDROBJ2_CTX *ctx = (TDI_CREATE_ADDROBJ2_CTX *)Context;
	TA_ADDRESS *addr = ctx->tai->Address.Address;//查询到的IP地址和端口
	struct ot_entry *ote_addr;
	KIRQL irql;
	int ipproto;

	KdPrint(("[tdi_fw] tdi_create_addrobj_complete2: address: %x:%u\n", 
		 ntohl(((TDI_ADDRESS_IP *)(addr->Address))->in_addr),
		 ntohs(((TDI_ADDRESS_IP *)(addr->Address))->sin_port)));

	// save address
    //查询地址对象在hash表中的结构
	ote_addr = ot_find_fileobj(ctx->fileobj, &irql);
	if (ote_addr == NULL) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete2: ot_find_fileobj(0x%x)\n",
			ctx->fileobj));
		status = STATUS_OBJECT_NAME_NOT_FOUND;
		goto done;
	}

	if (addr->AddressLength > sizeof(ote_addr->local_addr)) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete2: address too long! (%u)\n",
			addr->AddressLength));
		status = STATUS_BUFFER_OVERFLOW;
		goto done;
	}
	//在此处将查询到的IP地址更新hash表中对应的地址对象中的ip地址和端口
	memcpy(ote_addr->local_addr, addr, addr->AddressLength);

	if (ote_addr->ipproto != IPPROTO_TCP) {
		// set "LISTEN" state for this addrobj
		status = add_listen(ote_addr);
		if (status != STATUS_SUCCESS) {
			KdPrint(("[tdi_fw] tdi_create_addrobj_complete2: add_listen: 0x%x!\n", status));
			goto done;
		}
	}

	status = STATUS_SUCCESS;
done:
	if (ote_addr != NULL)
		KeReleaseSpinLock(&g_ot_hash_guard, irql);

	// cleanup MDL to avoid unlocking pages from NonPaged pool
	if (Irp->MdlAddress != NULL) {
		IoFreeMdl(Irp->MdlAddress);
		Irp->MdlAddress = NULL;
	}

	free(ctx->tai);
	free(ctx);

	// success anyway
	return STATUS_SUCCESS;
}

//----------------------------------------------------------------------------

/*
 * TDI_CLEANUP handler
 */

int
tdi_cleanup(PIRP irp, PIO_STACK_LOCATION irps, struct completion *completion)
{
	NTSTATUS status;
	int type;

	// delete fileobj

	status = ot_del_fileobj(irps->FileObject, &type);
	if (status != STATUS_SUCCESS)
		KdPrint(("[tdi_fw] tdi_cleanup: del_fileobj: 0x%x!\n", status));
	else
		KdPrint(("[tdi_fw] tdi_cleanup: fileobj 0x%x, type %d\n", irps->FileObject, type));

	// success anyway
	return FILTER_ALLOW;
}

//----------------------------------------------------------------------------

/*
 * TDI_ASSOCIATE_ADDRESS handler
 *
 * With help of this routine we can get address object by connection object
 * and get connection object by connection context and address object
 */
int
tdi_associate_address(PIRP irp, PIO_STACK_LOCATION irps, struct completion *completion)
{
	//地址对象的句柄
	HANDLE addr_handle = ((TDI_REQUEST_KERNEL_ASSOCIATE *)(&irps->Parameters))->AddressHandle;
	PFILE_OBJECT addrobj = NULL;
	NTSTATUS status;
	struct ot_entry *ote_conn = NULL;
	KIRQL irql;
	int result = FILTER_DENY;

	KdPrint(("[tdi_fw] tdi_associate_address: devobj 0x%x; connobj 0x%x\n",
		irps->DeviceObject, irps->FileObject));

	//获取地址对象
	status = ObReferenceObjectByHandle(addr_handle, GENERIC_READ, NULL, KernelMode, &addrobj, NULL);
	if (status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] tdi_associate_address: ObReferenceObjectByHandle: 0x%x\n", status));
		goto done;
	}

	KdPrint(("[tdi_fw] tdi_associate_address: connobj = 0x%x ---> addrobj = 0x%x\n",
		irps->FileObject, addrobj));

	// associate addrobj with connobj

	//获取连接对象
	ote_conn = ot_find_fileobj(irps->FileObject, &irql);
	if (ote_conn == NULL) {
		KdPrint(("[tdi_fw] tdi_associate_address: ot_find_fileobj(0x%x)\n", irps->FileObject));
		goto done;
	}
	//将地址对象放在连接对象的结构体中保存：associated_fileobj
	ote_conn->associated_fileobj = addrobj;

	// add (conn_ctx, addrobj)->connobj

	status = ot_add_conn_ctx(addrobj, ote_conn->conn_ctx, irps->FileObject);
	if (status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] tdi_associate_address: ot_add_conn_ctx: 0x%x\n", status));
		goto done;
	}

	result = FILTER_ALLOW;
done:
	if (addrobj != NULL)
		ObDereferenceObject(addrobj);

	// cleanup
	if (ote_conn != NULL)
		KeReleaseSpinLock(&g_ot_hash_guard, irql);

	return result;
}

//----------------------------------------------------------------------------

/*
 * TDI_DISASSOCIATE_ADDRESS handler
 */
int
tdi_disassociate_address(PIRP irp, PIO_STACK_LOCATION irps, struct completion *completion)
{
	struct ot_entry *ote_conn = NULL;
	KIRQL irql;
	NTSTATUS status;

	KdPrint(("[tdi_fw] tdi_disassociate_address: connobj 0x%x\n", irps->FileObject));

	// delete connnection object
	ote_conn = ot_find_fileobj(irps->FileObject, &irql);
	if (ote_conn == NULL) {
		KdPrint(("[tdi_fw] tdi_disassociate_address: ot_find_fileobj(0x%x)\n", irps->FileObject));
		goto done;
	}

	// delete link of (addrobj, conn_ctx)->connobj
	status = ot_del_conn_ctx(ote_conn->associated_fileobj, ote_conn->conn_ctx);
	if (status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] tdi_disassociate_address: ot_del_conn_ctx: 0x%x\n", status));
		goto done;
	}

done:
	if (ote_conn != NULL)
		KeReleaseSpinLock(&g_ot_hash_guard, irql);

	// success anyway
	return FILTER_ALLOW;
}
