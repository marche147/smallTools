#include <ntifs.h>
#include <ntstrsafe.h>

#include "kMisc.h"
#include "kMiscKernel.h"

NTSTATUS kMiscQueryDriverInfoByDeviceName(PDRIVER_BY_DEVICE_IO pParam)
{
	NTSTATUS s = STATUS_UNSUCCESSFUL;
	PWCHAR buffer = NULL;
	OBJECT_ATTRIBUTES oa;
	HANDLE hFile = NULL;
	UNICODE_STRING ustrFileName;
	IO_STATUS_BLOCK iosb;
	PDEVICE_OBJECT pDevObj = NULL;
	PDRIVER_OBJECT pDrvObj = NULL;
	ULONG copylen;

	if (pParam->deviceNameLen > MAX_DEVICE_NAME_LEN) return STATUS_NO_MEMORY;
	buffer = (PWCHAR)ExAllocatePool(NonPagedPoolNx, pParam->deviceNameLen);
	if (!buffer)		return STATUS_NO_MEMORY;
	__try {
		ProbeForRead(pParam->deviceName, pParam->deviceNameLen, sizeof(WCHAR));
		RtlCopyMemory(buffer, pParam->deviceName, pParam->deviceNameLen);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		s = GetExceptionCode();
		KMISC_PRINT("Exception : %08x\n", s);
	}
	RtlInitUnicodeString(&ustrFileName, buffer);
	InitializeObjectAttributes(&oa, &ustrFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	s = NtCreateFile(&hFile, GENERIC_READ, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
	if (!NT_SUCCESS(s)) {
		KMISC_PRINT("Failed create file %08x\n", s);
		goto Finish;
	}
	s = ObReferenceObjectByHandle(hFile, GENERIC_READ, NULL, KernelMode, (PVOID*)&pDevObj, NULL);
	if (!NT_SUCCESS(s)) {
		KMISC_PRINT("Failed reference object %08x\n", s);
		goto Finish;
	}
	pDrvObj = pDevObj->DriverObject;
	if (!pDrvObj) {
		KMISC_PRINT("Weird device.\n");
		goto Finish;
	}
	ObReferenceObject(pDrvObj);
	pParam->driverSection = pDrvObj->DriverSection;
	for (int i = 0;i < IRP_MJ_MAXIMUM_FUNCTION + 1;i++) {
		pParam->majorFunctions[i] = pDrvObj->MajorFunction[i];
	}
	
	__try {
		copylen = (pParam->driverNameLen < pDrvObj->DriverName.Length ? pParam->driverNameLen : pDrvObj->DriverName.Length);
		ProbeForWrite(pParam->driverName, copylen, sizeof(WCHAR));
		RtlCopyMemory(pParam->driverName, pDrvObj->DriverName.Buffer, copylen);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		s = GetExceptionCode();
		KMISC_PRINT("Exception %08x\n", s);
	}

Finish:
	if (buffer)	ExFreePool(buffer);
	if (pDevObj) ObDereferenceObject(pDevObj);
	if (hFile) NtClose(hFile);
	if (pDrvObj) ObDereferenceObject(pDrvObj);
	return	s;
}

NTSTATUS kMiscDummyDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);

	PIO_STACK_LOCATION ioStackLoc = IoGetCurrentIrpStackLocation(pIrp);
	KMISC_PRINT("Dummy Dispatch : %d\n", ioStackLoc->MajorFunction);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS kMiscIoctlDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS s = STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION ioStackLoc = IoGetCurrentIrpStackLocation(pIrp);

	UNREFERENCED_PARAMETER(pDevObj);

	// METHOD_BUFFERED
	ULONG ioCtlCode = ioStackLoc->Parameters.DeviceIoControl.IoControlCode;
	ULONG inBufLen = ioStackLoc->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outBufLen = ioStackLoc->Parameters.DeviceIoControl.OutputBufferLength;

	switch (ioCtlCode) {
	case IOCTL_GET_DRIVER_INFO_BY_DEVICE:
		KMISC_PRINT("IOCTL_GET_DRIVER_INFO_BY_DEVICE\n");
		if (inBufLen < sizeof(DRIVER_BY_DEVICE_IO)) {
			s = STATUS_INVALID_PARAMETER;
			pIrp->IoStatus.Information = 0;
			break;
		}

		s = kMiscQueryDriverInfoByDeviceName((PDRIVER_BY_DEVICE_IO)(pIrp->AssociatedIrp.SystemBuffer));
		if (NT_SUCCESS(s))
			pIrp->IoStatus.Information = (outBufLen < sizeof(DRIVER_BY_DEVICE_IO) ? outBufLen : sizeof(DRIVER_BY_DEVICE_IO));
		else
			pIrp->IoStatus.Information = 0;
		break;
	default:
		s = STATUS_NOT_SUPPORTED;
		pIrp->IoStatus.Information = 0;
		break;
	}

	pIrp->IoStatus.Status = s;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return s;
}

VOID kMiscDriverUnload(PDRIVER_OBJECT pDrvObj)
{
	UNICODE_STRING ustrSymName;
	PDEVICE_OBJECT pDev = pDrvObj->DeviceObject;

	RtlInitUnicodeString(&ustrSymName, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&ustrSymName);

	if (pDev) {
		IoDeleteDevice(pDev);
	}

	KMISC_PRINT("Unload done.\n");
	return;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
	NTSTATUS s = STATUS_UNSUCCESSFUL;
	PDEVICE_OBJECT pDevObj = NULL;
	UNICODE_STRING ustrDevName, ustrSymName;

	UNREFERENCED_PARAMETER(pRegPath);

	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	s = IoCreateDevice(pDrvObj, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, 0, &pDevObj);
	if (!NT_SUCCESS(s)) {
		KMISC_PRINT("Cannot create device %08x\n", s);
		return s;
	}
	RtlInitUnicodeString(&ustrSymName, DOS_DEVICE_NAME);
	s = IoCreateSymbolicLink(&ustrSymName, &ustrDevName);
	if (!NT_SUCCESS(s)) {
		KMISC_PRINT("Cannot create symlink %08x\n", s);
		IoDeleteDevice(pDevObj);
		return s;
	}
	
	for (int i = 0;i < IRP_MJ_MAXIMUM_FUNCTION;i++) {
		pDrvObj->MajorFunction[i] = kMiscDummyDispatch;
	}
	pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = kMiscIoctlDispatch;
	pDrvObj->DriverUnload = kMiscDriverUnload;

	pDevObj->Flags |= DO_BUFFERED_IO;
	pDevObj->Flags &= ~DO_DEVICE_INITIALIZING;

	KMISC_PRINT("Init finish\n");

	return s;
}