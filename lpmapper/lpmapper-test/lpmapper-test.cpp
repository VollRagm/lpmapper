#include <iostream>
#include <Windows.h>

//This is the project to test if lpmapper has worked and if the shellcode is working as it should

const ULONG IOCTL_READCR3 = CTL_CODE(0x8000, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS);
const ULONG IOCTL_PROCESS_BASE = CTL_CODE(0x8000, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS);
const ULONG IOCTL_COPY = CTL_CODE(0x8000, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS);

bool TestReadCr3(HANDLE beepHandle)
{
    uint64_t cr3 = 0;

    bool success = DeviceIoControl(beepHandle, IOCTL_READCR3,
        nullptr, 0,
        &cr3, sizeof(uint64_t),
        nullptr, nullptr);

    if (!success)
    {
        std::cout << "DeviceIoControl failed during cr3 test! -> " << GetLastError();
        return false;
    }

    std::cout << "IOCTL_READCR3 returned 0x" << std::hex << cr3 << " -> " << (cr3 == 0 ? "Test failed" : "Test successful") << std::endl;

    return cr3 != 0;
}

bool TestProcessBase(HANDLE beepHandle, uint64_t* baseAddress)
{
    uint64_t processBase = 0;

    uint64_t processId = GetCurrentProcessId();

    bool success = DeviceIoControl(beepHandle, IOCTL_PROCESS_BASE,
        &processId, sizeof(uint64_t),
        &processBase, sizeof(uint64_t),
        nullptr, nullptr);

    if (!success)
    {
        std::cout << "DeviceIoControl failed during process base test! -> " << GetLastError();
        return false;
    }

    std::cout << "IOCTL_PROCESS_BASE returned 0x" << std::hex << processBase << " -> " << (processBase == 0 ? "Test failed" : "Test successful") << std::endl;
    *baseAddress = processBase;

    return processBase != 0;
}

struct memory_copy
{
    uint64_t processId;
    PVOID sourceAddress;
    PVOID targetAddress;
    BOOL write;
    SIZE_T size;
};


bool TestMemoryRead(HANDLE beepHandle, uint64_t baseAddress)
{
    char buffer[3];

    memory_copy data = {};

    data.processId = GetCurrentProcessId();
    data.targetAddress = buffer;
    data.sourceAddress = (PVOID)baseAddress;
    data.write = false;
    data.size = 2; //only read MZ into buffer

    buffer[2] = 0; // set null terminator after "MZ"

    bool success = DeviceIoControl(beepHandle, IOCTL_COPY,
        &data, sizeof(memory_copy),
        nullptr, 0,
        nullptr, nullptr);

    if (!success)
    {
        std::cout << "DeviceIoControl failed during process base test! -> " << GetLastError();
        return false;
    }

    std::cout << "IOCTL_COPY returned 0x" << std::hex << *(WORD*)buffer << " (" << buffer << ") -> "
                << (*(WORD*)buffer != 0x5A4D ? "Test failed" : "Test successful") << std::endl;

    return *(WORD*)buffer != 0x5A4D;
}

int main()
{
    std::cout << "Press any key to run the test!" << std::endl;
    std::cin.ignore();

    HANDLE beepHandle = CreateFile(L"\\\\.\\GLOBALROOT\\Device\\Beep", FILE_ANY_ACCESS, 0, 
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (beepHandle == INVALID_HANDLE_VALUE)
    {
        std::cout << "Test failed. Could not open handle to \\.\GLOBALROOT\\Device\\Beep -> " << GetLastError();
        return -1;
    }

    std::cout << "Opened handle to Beep -> " << std::hex << beepHandle << std::endl;

    if (!TestReadCr3(beepHandle))
    {
        std::cin.ignore();
        return -1;
    }

    uint64_t baseAddress = 0;

    if (!TestProcessBase(beepHandle, &baseAddress))
    {
        std::cin.ignore();
        return -1;
    }

    if (!TestMemoryRead(beepHandle, baseAddress))
    {
        std::cin.ignore();
        return -1;
    }


    CloseHandle(beepHandle);
    std::cin.ignore();



}
