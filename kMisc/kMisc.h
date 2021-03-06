#pragma once

#define DEVICE_NAME L"\\Device\\kMisc"
#define DOS_DEVICE_NAME L"\\??\\kMisc"
#define USERSPACE_DEVICE_NAME L"\\\\.\\kMisc"

#ifndef IRP_MJ_MAXIMUM_FUNCTION
#define IRP_MJ_MAXIMUM_FUNCTION 0x1b
#endif

#ifndef CTL_CODE
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)
#endif

/* Get driver info by device name */
#define IOCTL_GET_DRIVER_INFO_BY_DEVICE CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef struct _DRIVER_BY_DEVICE_IO {
	PWCHAR deviceName;	// device name "\\\\.\\Xxx"
	ULONG deviceNameLen;
	PWCHAR driverName;	// driver name buffer
	ULONG driverNameLen;	// in bytes
	PVOID driverSection;	// driver section
	PVOID majorFunctions[IRP_MJ_MAXIMUM_FUNCTION + 1];	// major function array
} DRIVER_BY_DEVICE_IO, *PDRIVER_BY_DEVICE_IO;