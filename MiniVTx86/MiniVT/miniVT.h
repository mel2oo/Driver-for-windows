#pragma once
#ifndef MINIVT_H
#define MINIVT_H

#include <ntddk.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath);

void MiniVTUnload(IN PDRIVER_OBJECT DriverObject);

NTSTATUS MiniVTCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS MiniVTDefaultHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

#endif