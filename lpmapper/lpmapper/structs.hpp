#pragma once
#include "kdmapper/utils.hpp"

#define IRP_MJ_MAXIMUM_FUNCTION         0x1b
#define IRP_MJ_DEVICE_CONTROL           0x0e


typedef struct _DRIVER_OBJECT
{
    int16_t            Type;
    int16_t            Size;
    PVOID              DeviceObject;
    ULONG              Flags;
    PVOID              DriverStart;
    ULONG              DriverSize;
    PVOID              DriverSection;
    PVOID              DriverExtension;
    UNICODE_STRING     DriverName;
    PUNICODE_STRING    HardwareDatabase;
    PVOID              FastIoDispatch;
    PVOID              DriverInit;
    PVOID              DriverStartIo;
    PVOID              DriverUnload;
    PVOID              MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT, * PDRIVER_OBJECT;

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _DEVICE_OBJECT
{
    int16_t                    Type;
    uint16_t                   Size;
    int32_t                    ReferenceCount;
    _DRIVER_OBJECT* DriverObject;
    
    // There would be more stuff here, but we don't need it.

} DEVICE_OBJECT, * PDEVICE_OBJECT;