#pragma once

#define KMISC_TAG "[MISC] "
#define KMISC_PRINT(s, ...)  DbgPrint(KMISC_TAG s, __VA_ARGS__)

#define MAX_DEVICE_NAME_LEN 0x2710000

extern "C"
{
	extern NTSTATUS
		ObReferenceObjectByName(
			__in PUNICODE_STRING ObjectName,
			__in ULONG Attributes,
			__in_opt PACCESS_STATE AccessState,
			__in_opt ACCESS_MASK DesiredAccess,
			__in POBJECT_TYPE ObjectType,
			__in KPROCESSOR_MODE AccessMode,
			__inout_opt PVOID ParseContext,
			__out PVOID *Object
		);
	extern POBJECT_TYPE *IoDriverObjectType;
	extern POBJECT_TYPE *IoDeviceObjectType;
};