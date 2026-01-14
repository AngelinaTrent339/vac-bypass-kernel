/******************************************************************************
    MIT License

    Copyright (c) 2024 Ricardo Carvalho

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
 ******************************************************************************/
#pragma once

// Debug output macros
#define DBG_PRINT(fmt, ...)                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        std::wcout << L"  [DBG] " << fmt << std::endl;                                                                 \
    } while (0)

#define DBG_PRINT_HEX(name, value)                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        std::wcout << L"  [DBG] " << name << L": 0x" << std::hex << std::uppercase << value << std::dec << std::endl;  \
    } while (0)

class IVACDriverManager
{
  private:
    HANDLE deviceHandle = INVALID_HANDLE_VALUE;
    bool debugMode = true;

    const wchar_t *GetRequestName(Comms::EDriverCommunicationRequest req)
    {
        switch (req)
        {
        case Comms::EDriverCommunicationRequest::EnableBypass:
            return L"EnableBypass";
        case Comms::EDriverCommunicationRequest::DisableBypass:
            return L"DisableBypass";
        case Comms::EDriverCommunicationRequest::InjectDll:
            return L"InjectDll";
        default:
            return L"Unknown";
        }
    }

    template <class T> NTSTATUS SendIoctl(_In_ T *request)
    {
        const ULONG bufferSize = sizeof(T);

        if (debugMode)
        {
            std::wcout << L"\n  ┌─────────────────────────────────────────────────┐" << std::endl;
            std::wcout << L"  │ KERNEL IOCTL CALL                                │" << std::endl;
            std::wcout << L"  ├─────────────────────────────────────────────────┤" << std::endl;
            std::wcout << L"  │ Request Type: " << std::left << std::setw(33) << GetRequestName(request->Request)
                       << L"│" << std::endl;
            std::wcout << L"  │ Buffer Size:  " << std::left << std::setw(33) << bufferSize << L"│" << std::endl;
            std::wcout << L"  │ Device Handle: 0x" << std::hex << std::uppercase << std::setw(30) << std::left
                       << reinterpret_cast<ULONG_PTR>(deviceHandle) << std::dec << L"│" << std::endl;
            std::wcout << L"  │ IOCTL Code:   0x" << std::hex << std::uppercase << std::setw(31) << std::left
                       << IOCTL_VAC_REQUEST << std::dec << L"│" << std::endl;
            std::wcout << L"  │ Magic:        0x" << std::hex << std::uppercase << std::setw(31) << std::left
                       << request->Magic << std::dec << L"│" << std::endl;
            std::wcout << L"  └─────────────────────────────────────────────────┘" << std::endl;
        }

        // Make the kernel call using NtDeviceIoControlFile
        IO_STATUS_BLOCK iosb{};

        if (debugMode)
        {
            std::wcout << L"  [KERNEL] Calling NtDeviceIoControlFile..." << std::endl;
        }

        const NTSTATUS status = NtDeviceIoControlFile(this->deviceHandle, // Device handle
                                                      nullptr,            // Event (optional)
                                                      nullptr,            // APC routine (optional)
                                                      nullptr,            // APC context (optional)
                                                      &iosb,              // IO_STATUS_BLOCK
                                                      IOCTL_VAC_REQUEST,  // IOCTL code
                                                      request,            // Input buffer
                                                      bufferSize,         // Input buffer size
                                                      request,   // Output buffer (same as input for this driver)
                                                      bufferSize // Output buffer size
        );

        if (debugMode)
        {
            std::wcout << L"  [KERNEL] NtDeviceIoControlFile returned: 0x" << std::hex << std::uppercase << std::setw(8)
                       << std::setfill(L'0') << status << std::dec << std::setfill(L' ') << std::endl;
            std::wcout << L"  [KERNEL] IO_STATUS_BLOCK.Status: 0x" << std::hex << std::uppercase << std::setw(8)
                       << std::setfill(L'0') << iosb.Status << std::dec << std::setfill(L' ') << std::endl;
            std::wcout << L"  [KERNEL] IO_STATUS_BLOCK.Information: " << iosb.Information << std::endl;
            std::wcout << L"  [KERNEL] Request.Status: 0x" << std::hex << std::uppercase << std::setw(8)
                       << std::setfill(L'0') << request->Status << std::dec << std::setfill(L' ') << std::endl;
        }

        if (!NT_SUCCESS(status))
        {
            std::wcerr << L"  [ERROR] NtDeviceIoControlFile FAILED: 0x" << std::hex << std::uppercase << std::setw(8)
                       << std::setfill(L'0') << status << std::dec << std::setfill(L' ') << std::endl;
            request->SetStatus(status);
        }

        return request->Status;
    }

  public:
    IVACDriverManager(bool enableDebug = true) : debugMode(enableDebug)
    {
        std::wstring devicePath = L"\\\\.\\" VAC_DEVICE_GUID;

        if (debugMode)
        {
            std::wcout << L"  [KERNEL] Opening device: " << devicePath << std::endl;
        }

        this->deviceHandle = CreateFileW(devicePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                                         FILE_ATTRIBUTE_NORMAL, NULL);

        if (!this->deviceHandle || this->deviceHandle == INVALID_HANDLE_VALUE)
        {
            DWORD error = GetLastError();
            if (debugMode)
            {
                std::wcerr << L"  [ERROR] CreateFile failed with error: " << error << std::endl;
            }
            throw std::runtime_error("Failed to open device. Error: " + std::to_string(error));
        }

        if (debugMode)
        {
            std::wcout << L"  [KERNEL] Device opened successfully! Handle: 0x" << std::hex << std::uppercase
                       << reinterpret_cast<ULONG_PTR>(deviceHandle) << std::dec << std::endl;
        }
    }

    ~IVACDriverManager()
    {
        if (deviceHandle && deviceHandle != INVALID_HANDLE_VALUE)
        {
            if (debugMode)
            {
                std::wcout << L"  [KERNEL] Closing device handle..." << std::endl;
            }
            CloseHandle(deviceHandle);
            deviceHandle = INVALID_HANDLE_VALUE;
        }
    }

    void SetDebugMode(bool enable)
    {
        debugMode = enable;
    }

    NTSTATUS DisableBypass()
    {
        if (debugMode)
        {
            std::wcout << L"\n  [KERNEL] === DisableBypass Request ===" << std::endl;
        }

        auto request = new Comms::DRIVER_REQUEST_DISABLE_BYPASS();
        NTSTATUS status = SendIoctl(request);
        delete request;
        return status;
    }

    NTSTATUS EnableBypass()
    {
        if (debugMode)
        {
            std::wcout << L"\n  [KERNEL] === EnableBypass Request ===" << std::endl;
        }

        auto request = new Comms::DRIVER_REQUEST_ENABLE_BYPASS();
        NTSTATUS status = SendIoctl(request);
        delete request;
        return status;
    }

    NTSTATUS InjectDll(_In_ std::vector<uint8_t> &imageBuffer)
    {
        if (debugMode)
        {
            std::wcout << L"\n  [KERNEL] === InjectDll Request ===" << std::endl;
            std::wcout << L"  [KERNEL] DLL Buffer Address: 0x" << std::hex << std::uppercase
                       << reinterpret_cast<ULONG_PTR>(imageBuffer.data()) << std::dec << std::endl;
            std::wcout << L"  [KERNEL] DLL Buffer Size: " << imageBuffer.size() << L" bytes" << std::endl;
        }

        auto request = new Comms::DRIVER_REQUEST_INJECT(reinterpret_cast<PVOID>(imageBuffer.data()),
                                                        static_cast<ULONG>(imageBuffer.size()));

        if (debugMode)
        {
            std::wcout << L"  [KERNEL] Request ImageBase: 0x" << std::hex << std::uppercase
                       << reinterpret_cast<ULONG_PTR>(request->ImageBase) << std::dec << std::endl;
            std::wcout << L"  [KERNEL] Request ImageSize: " << request->ImageSize << std::endl;
        }

        NTSTATUS status = SendIoctl(request);
        delete request;
        return status;
    }
};