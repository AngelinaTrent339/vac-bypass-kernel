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

// Forward declare Color namespace
namespace Color
{
extern const wchar_t *Reset;
extern const wchar_t *Red;
extern const wchar_t *Green;
extern const wchar_t *Yellow;
extern const wchar_t *Blue;
extern const wchar_t *Magenta;
extern const wchar_t *Cyan;
extern const wchar_t *White;
extern const wchar_t *Gray;
} // namespace Color

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
        case Comms::EDriverCommunicationRequest::GetLogs:
            return L"GetLogs";
        case Comms::EDriverCommunicationRequest::ClearLogs:
            return L"ClearLogs";
        case Comms::EDriverCommunicationRequest::GetStatus:
            return L"GetStatus";
        default:
            return L"Unknown";
        }
    }

    const wchar_t *GetLogLevelString(Comms::ELogLevel level)
    {
        switch (level)
        {
        case Comms::ELogLevel::Critical:
            return L"CRIT";
        case Comms::ELogLevel::Error:
            return L"ERR ";
        case Comms::ELogLevel::Warning:
            return L"WARN";
        case Comms::ELogLevel::Info:
            return L"INFO";
        case Comms::ELogLevel::Verbose:
            return L"VERB";
        case Comms::ELogLevel::Debug:
            return L"DBG ";
        default:
            return L"??? ";
        }
    }

    const wchar_t *GetLogLevelColor(Comms::ELogLevel level)
    {
        switch (level)
        {
        case Comms::ELogLevel::Critical:
            return Color::Red;
        case Comms::ELogLevel::Error:
            return Color::Red;
        case Comms::ELogLevel::Warning:
            return Color::Yellow;
        case Comms::ELogLevel::Info:
            return Color::Cyan;
        case Comms::ELogLevel::Verbose:
            return Color::Gray;
        case Comms::ELogLevel::Debug:
            return Color::Magenta;
        default:
            return Color::White;
        }
    }

    template <class T> NTSTATUS SendIoctl(_In_ T *request, bool suppressLogs = false)
    {
        const ULONG bufferSize = sizeof(T);

        if (debugMode && !suppressLogs)
        {
            std::wcout << L"\n  " << Color::Gray << L"┌───────────────────────────────────────────────┐" << Color::Reset
                       << std::endl;
            std::wcout << L"  " << Color::Gray << L"│ " << Color::Cyan << L"KERNEL IOCTL" << Color::Gray
                       << L"                                  │" << Color::Reset << std::endl;
            std::wcout << L"  " << Color::Gray << L"├───────────────────────────────────────────────┤" << Color::Reset
                       << std::endl;
            std::wcout << L"  " << Color::Gray << L"│ Request: " << Color::Yellow << std::left << std::setw(36)
                       << GetRequestName(request->Request) << Color::Gray << L"│" << Color::Reset << std::endl;
            std::wcout << L"  " << Color::Gray << L"│ Size:    " << Color::White << std::left << std::setw(36)
                       << bufferSize << Color::Gray << L"│" << Color::Reset << std::endl;
            std::wcout << L"  " << Color::Gray << L"│ Handle:  0x" << std::hex << std::left << std::setw(34)
                       << reinterpret_cast<ULONG_PTR>(deviceHandle) << std::dec << Color::Gray << L"│" << Color::Reset
                       << std::endl;
            std::wcout << L"  " << Color::Gray << L"└───────────────────────────────────────────────┘" << Color::Reset
                       << std::endl;
        }

        IO_STATUS_BLOCK iosb{};

        const NTSTATUS status = NtDeviceIoControlFile(this->deviceHandle, nullptr, nullptr, nullptr, &iosb,
                                                      IOCTL_VAC_REQUEST, request, bufferSize, request, bufferSize);

        if (debugMode && !suppressLogs)
        {
            if (NT_SUCCESS(status))
            {
                std::wcout << L"  " << Color::Green << L"[+]" << Color::Gray << L" IOCTL Success: " << Color::Green
                           << L"0x" << std::hex << std::setw(8) << std::setfill(L'0') << status << std::dec
                           << std::setfill(L' ') << Color::Reset << std::endl;
            }
            else
            {
                std::wcout << L"  " << Color::Red << L"[!]" << Color::Gray << L" IOCTL Failed: " << Color::Red << L"0x"
                           << std::hex << std::setw(8) << std::setfill(L'0') << status << std::dec << std::setfill(L' ')
                           << Color::Reset << std::endl;
            }
        }

        if (!NT_SUCCESS(status))
        {
            request->SetStatus(status);
        }

        return request->Status;
    }

  public:
    IVACDriverManager(bool enableDebug = true) : debugMode(enableDebug)
    {
        std::wstring devicePath = L"\\\\.\\" VAC_DEVICE_GUID;

        this->deviceHandle = CreateFileW(devicePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                                         FILE_ATTRIBUTE_NORMAL, NULL);

        if (!this->deviceHandle || this->deviceHandle == INVALID_HANDLE_VALUE)
        {
            DWORD error = GetLastError();
            throw std::runtime_error("Failed to open device. Error: " + std::to_string(error));
        }
    }

    ~IVACDriverManager()
    {
        if (deviceHandle && deviceHandle != INVALID_HANDLE_VALUE)
        {
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
        auto request = new Comms::DRIVER_REQUEST_DISABLE_BYPASS();
        NTSTATUS status = SendIoctl(request);
        delete request;
        return status;
    }

    NTSTATUS EnableBypass()
    {
        auto request = new Comms::DRIVER_REQUEST_ENABLE_BYPASS();
        NTSTATUS status = SendIoctl(request);
        delete request;
        return status;
    }

    NTSTATUS InjectDll(_In_ std::vector<uint8_t> &imageBuffer)
    {
        if (debugMode)
        {
            std::wcout << L"  " << Color::Blue << L"[*]" << Color::Gray << L" DLL Buffer: " << Color::White << L"0x"
                       << std::hex << reinterpret_cast<ULONG_PTR>(imageBuffer.data()) << std::dec << Color::Reset
                       << std::endl;
            std::wcout << L"  " << Color::Blue << L"[*]" << Color::Gray << L" DLL Size:   " << Color::White
                       << imageBuffer.size() << L" bytes" << Color::Reset << std::endl;
        }

        auto request = new Comms::DRIVER_REQUEST_INJECT(reinterpret_cast<PVOID>(imageBuffer.data()),
                                                        static_cast<ULONG>(imageBuffer.size()));

        NTSTATUS status = SendIoctl(request);
        delete request;
        return status;
    }

    //=========================================================================
    // GetLogs - Retrieve kernel debug logs
    //=========================================================================
    NTSTATUS GetLogs(_Out_ std::vector<Comms::DRIVER_LOG_ENTRY> &logs, _Out_opt_ ULONG *totalAvailable = nullptr,
                     _Out_opt_ ULONG *dropped = nullptr)
    {
        auto request = new Comms::DRIVER_REQUEST_GET_LOGS(Comms::MAX_LOG_ENTRIES);
        NTSTATUS status = SendIoctl(request, true); // Suppress recursive logging

        if (NT_SUCCESS(status))
        {
            logs.clear();
            logs.reserve(request->EntriesReturned);

            for (ULONG i = 0; i < request->EntriesReturned; i++)
            {
                logs.push_back(request->Entries[i]);
            }

            if (totalAvailable)
                *totalAvailable = request->TotalEntriesAvailable;
            if (dropped)
                *dropped = request->EntriesDropped;
        }

        delete request;
        return status;
    }

    //=========================================================================
    // PrintKernelLogs - Fetch and display kernel logs with colors
    //=========================================================================
    void PrintKernelLogs()
    {
        std::vector<Comms::DRIVER_LOG_ENTRY> logs;
        ULONG totalAvailable = 0;
        ULONG dropped = 0;

        NTSTATUS status = GetLogs(logs, &totalAvailable, &dropped);

        if (!NT_SUCCESS(status))
        {
            std::wcout << L"  " << Color::Red << L"[!] Failed to get kernel logs: 0x" << std::hex << status << std::dec
                       << Color::Reset << std::endl;
            return;
        }

        if (logs.empty())
        {
            std::wcout << L"  " << Color::Gray << L"[*] No new kernel logs" << Color::Reset << std::endl;
            return;
        }

        std::wcout << std::endl;
        std::wcout << L"  " << Color::Cyan
                   << L"╔═══════════════════════════════════════════════════════════════════════════════╗"
                   << Color::Reset << std::endl;
        std::wcout << L"  " << Color::Cyan
                   << L"║                          KERNEL DRIVER LOGS                                   ║"
                   << Color::Reset << std::endl;
        std::wcout << L"  " << Color::Cyan
                   << L"╠═══════════════════════════════════════════════════════════════════════════════╣"
                   << Color::Reset << std::endl;

        if (dropped > 0)
        {
            std::wcout << L"  " << Color::Yellow << L"║ WARNING: " << dropped
                       << L" log entries were dropped due to buffer overflow"
                       << std::setw(30 - std::to_wstring(dropped).length()) << L"║" << Color::Reset << std::endl;
        }

        for (const auto &entry : logs)
        {
            // Convert timestamp to readable format
            LARGE_INTEGER timestamp;
            timestamp.QuadPart = entry.Timestamp;

            TIME_FIELDS timeFields;
            RtlTimeToTimeFields(&timestamp, &timeFields);

            // Convert function and message to wide strings
            std::string funcStr(entry.Function);
            std::string msgStr(entry.Message);
            std::wstring funcWstr(funcStr.begin(), funcStr.end());
            std::wstring msgWstr(msgStr.begin(), msgStr.end());

            // Print log entry
            std::wcout << L"  " << Color::Gray << L"║ ";

            // Timestamp
            std::wcout << Color::Gray << std::setw(2) << std::setfill(L'0') << timeFields.Hour << L":" << std::setw(2)
                       << timeFields.Minute << L":" << std::setw(2) << timeFields.Second << L"." << std::setw(3)
                       << timeFields.Milliseconds << std::setfill(L' ');

            // Level
            std::wcout << L" " << GetLogLevelColor(entry.Level) << L"[" << GetLogLevelString(entry.Level) << L"]"
                       << Color::Reset;

            // Function:Line
            std::wcout << Color::Blue << L" " << std::left << std::setw(20) << funcWstr.substr(0, 20) << Color::Gray
                       << L":" << Color::Yellow << std::right << std::setw(4) << entry.Line;

            // Status code if error
            if (entry.StatusCode != 0)
            {
                std::wcout << Color::Red << L" [0x" << std::hex << entry.StatusCode << std::dec << L"]";
            }

            // Message
            std::wcout << Color::White << L" " << msgWstr.substr(0, 40) << Color::Reset << std::endl;
        }

        std::wcout << L"  " << Color::Cyan
                   << L"╚═══════════════════════════════════════════════════════════════════════════════╝"
                   << Color::Reset << std::endl;
        std::wcout << L"  " << Color::Gray << L"  Retrieved " << logs.size() << L" log entries" << Color::Reset
                   << std::endl;
        std::wcout << std::endl;
    }

    //=========================================================================
    // ClearLogs - Clear kernel log buffer
    //=========================================================================
    NTSTATUS ClearLogs(_Out_opt_ ULONG *cleared = nullptr)
    {
        auto request = new Comms::DRIVER_REQUEST_CLEAR_LOGS();
        NTSTATUS status = SendIoctl(request, true);

        if (NT_SUCCESS(status) && cleared)
        {
            *cleared = request->EntriesCleared;
        }

        delete request;
        return status;
    }

    //=========================================================================
    // GetStatus - Get driver status
    //=========================================================================
    NTSTATUS GetStatus(_Out_ Comms::DRIVER_REQUEST_GET_STATUS &statusOut)
    {
        auto request = new Comms::DRIVER_REQUEST_GET_STATUS();
        NTSTATUS status = SendIoctl(request, true);

        if (NT_SUCCESS(status))
        {
            statusOut = *request;
        }

        delete request;
        return status;
    }

    //=========================================================================
    // PrintDriverStatus - Display driver status with colors
    //=========================================================================
    void PrintDriverStatus()
    {
        Comms::DRIVER_REQUEST_GET_STATUS status;
        NTSTATUS ntStatus = GetStatus(status);

        if (!NT_SUCCESS(ntStatus))
        {
            std::wcout << L"  " << Color::Red << L"[!] Failed to get driver status: 0x" << std::hex << ntStatus
                       << std::dec << Color::Reset << std::endl;
            return;
        }

        std::string procName(status.TargetProcessName);
        std::wstring procNameW(procName.begin(), procName.end());

        std::wcout << std::endl;
        std::wcout << L"  " << Color::Cyan << L"╔═══════════════════════════════════════════════╗" << Color::Reset
                   << std::endl;
        std::wcout << L"  " << Color::Cyan << L"║            DRIVER STATUS                      ║" << Color::Reset
                   << std::endl;
        std::wcout << L"  " << Color::Cyan << L"╠═══════════════════════════════════════════════╣" << Color::Reset
                   << std::endl;

        std::wcout << L"  " << Color::Gray << L"║ Bypass:          "
                   << (status.BypassEnabled ? Color::Green : Color::Red)
                   << (status.BypassEnabled ? L"ENABLED " : L"DISABLED") << std::setw(20) << L"" << Color::Gray << L"║"
                   << Color::Reset << std::endl;

        std::wcout << L"  " << Color::Gray << L"║ Hooks:           "
                   << (status.HooksInstalled ? Color::Green : Color::Yellow)
                   << (status.HooksInstalled ? L"INSTALLED" : L"NOT INSTALLED") << std::setw(19) << L"" << Color::Gray
                   << L"║" << Color::Reset << std::endl;

        std::wcout << L"  " << Color::Gray << L"║ Target PID:      " << Color::White << std::left << std::setw(28)
                   << status.TargetProcessId << Color::Gray << L"║" << Color::Reset << std::endl;

        std::wcout << L"  " << Color::Gray << L"║ Target Process:  " << Color::Yellow << std::left << std::setw(28)
                   << procNameW << Color::Gray << L"║" << Color::Reset << std::endl;

        std::wcout << L"  " << Color::Gray << L"║ Injections:      " << Color::Green << std::left << std::setw(28)
                   << status.InjectionCount << Color::Gray << L"║" << Color::Reset << std::endl;

        std::wcout << L"  " << Color::Gray << L"║ Log Buffer:      " << Color::White << std::left << std::setw(28)
                   << status.LogBufferUsage << Color::Gray << L"║" << Color::Reset << std::endl;

        std::wcout << L"  " << Color::Cyan << L"╚═══════════════════════════════════════════════╝" << Color::Reset
                   << std::endl;
        std::wcout << std::endl;
    }
};