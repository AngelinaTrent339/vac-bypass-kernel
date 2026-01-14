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
#include "includes.hpp"

std::unique_ptr<IVACDriverManager> g_VACDriverManager = nullptr;

// Console colors for ANSI escape sequences
namespace Color
{
const wchar_t *Reset = L"\x1b[0m";
const wchar_t *Red = L"\x1b[91m";
const wchar_t *Green = L"\x1b[92m";
const wchar_t *Yellow = L"\x1b[93m";
const wchar_t *Blue = L"\x1b[94m";
const wchar_t *Magenta = L"\x1b[95m";
const wchar_t *Cyan = L"\x1b[96m";
const wchar_t *White = L"\x1b[97m";
const wchar_t *Gray = L"\x1b[90m";
} // namespace Color

void EnableVirtualTerminal()
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

void PrintBanner()
{
    std::wcout << Color::Cyan << LR"(
  ██████╗  ██████╗ ██████╗ ██╗      ██████╗ ██╗  ██╗
  ██╔══██╗██╔═══██╗██╔══██╗██║     ██╔═══██╗╚██╗██╔╝
  ██████╔╝██║   ██║██████╔╝██║     ██║   ██║ ╚███╔╝ 
  ██╔══██╗██║   ██║██╔══██╗██║     ██║   ██║ ██╔██╗ 
  ██║  ██║╚██████╔╝██████╔╝███████╗╚██████╔╝██╔╝ ██╗
  ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝
)" << Color::Reset
               << std::endl;
    std::wcout << Color::Gray << L"  Kernel-Mode DLL Injector for Roblox" << Color::Reset << std::endl;
    std::wcout << Color::Gray << L"  ═══════════════════════════════════════════════" << Color::Reset << std::endl
               << std::endl;
}

void PrintStatus(const wchar_t *prefix, const wchar_t *message, const wchar_t *color = Color::White)
{
    std::wcout << Color::Gray << L"  [" << color << prefix << Color::Gray << L"] " << Color::White << message
               << Color::Reset << std::endl;
}

void PrintSuccess(const wchar_t *message)
{
    PrintStatus(L"+", message, Color::Green);
}
void PrintError(const wchar_t *message)
{
    PrintStatus(L"!", message, Color::Red);
}
void PrintInfo(const wchar_t *message)
{
    PrintStatus(L"*", message, Color::Blue);
}
void PrintWarning(const wchar_t *message)
{
    PrintStatus(L"~", message, Color::Yellow);
}
void PrintDebug(const wchar_t *message)
{
    PrintStatus(L"DBG", message, Color::Magenta);
}

// Debug helper to print hex value
void PrintDebugHex(const wchar_t *name, ULONG_PTR value)
{
    std::wstringstream ss;
    ss << name << L": 0x" << std::hex << std::uppercase << value;
    PrintDebug(ss.str().c_str());
}

// Debug helper to print NTSTATUS
void PrintNtStatus(const wchar_t *operation, NTSTATUS status)
{
    std::wstringstream ss;
    ss << operation << L" returned NTSTATUS: 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill(L'0')
       << status;
    if (NT_SUCCESS(status))
    {
        PrintSuccess(ss.str().c_str());
    }
    else
    {
        PrintError(ss.str().c_str());
    }
}

bool WaitForRoblox(ULONG &outProcessId, int timeoutSeconds = 60)
{
    PrintInfo(L"Waiting for Roblox to start...");

    const wchar_t *processNames[] = {L"RobloxPlayerBeta.exe", L"Windows10Universal.exe", L"RobloxPlayer.exe"};

    auto startTime = std::chrono::steady_clock::now();

    while (true)
    {
        for (const auto &name : processNames)
        {
            ULONG pid = Utils::GetProcessIdByName(name);
            if (pid != static_cast<ULONG>(-1))
            {
                outProcessId = pid;
                std::wstring msg = L"Found Roblox: ";
                msg += name;
                msg += L" (PID: ";
                msg += std::to_wstring(pid);
                msg += L")";
                PrintSuccess(msg.c_str());
                PrintDebugHex(L"Process ID", pid);
                return true;
            }
        }

        auto elapsed =
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - startTime).count();

        if (elapsed >= timeoutSeconds)
        {
            PrintError(L"Timeout waiting for Roblox!");
            return false;
        }

        std::wcout << L"\r" << Color::Gray << L"  [" << Color::Blue << L"*" << Color::Gray << L"] " << Color::White
                   << L"Waiting for Roblox... " << Color::Yellow << elapsed << L"s" << Color::Reset << std::flush;

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

bool IsRobloxReady(ULONG processId)
{
    const wchar_t *requiredModules[] = {L"ntdll.dll", L"kernel32.dll", L"user32.dll"};

    for (const auto &moduleName : requiredModules)
    {
        HMODULE hMod = Utils::GetProcessModule(processId, moduleName);
        if (!hMod)
        {
            return false;
        }
    }

    return true;
}

bool WaitForRobloxReady(ULONG processId, int timeoutSeconds = 30)
{
    PrintInfo(L"Waiting for Roblox to initialize...");
    PrintDebugHex(L"Target PID", processId);

    auto startTime = std::chrono::steady_clock::now();

    while (true)
    {
        if (IsRobloxReady(processId))
        {
            PrintSuccess(L"Roblox is ready for injection!");
            return true;
        }

        auto elapsed =
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - startTime).count();

        if (elapsed >= timeoutSeconds)
        {
            PrintError(L"Timeout waiting for Roblox to initialize!");
            return false;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

int handleBypass(const std::vector<std::wstring> &args)
{
    for (size_t i = 2; i < args.size(); ++i)
    {
        if (args[i].find(L"/enable") != std::string::npos)
        {
            PrintInfo(L"Sending EnableBypass to kernel driver...");
            NTSTATUS status = g_VACDriverManager->EnableBypass();
            PrintNtStatus(L"EnableBypass", status);

            if (!NT_SUCCESS(status))
            {
                return EXIT_FAILURE;
            }
            PrintSuccess(L"Bypass ENABLED!");
        }
        else if (args[i].find(L"/disable") != std::string::npos)
        {
            PrintInfo(L"Sending DisableBypass to kernel driver...");
            NTSTATUS status = g_VACDriverManager->DisableBypass();
            PrintNtStatus(L"DisableBypass", status);

            if (!NT_SUCCESS(status))
            {
                return EXIT_FAILURE;
            }
            PrintSuccess(L"Bypass DISABLED!");
        }
        else
        {
            std::wstring msg = L"Unknown argument: ";
            msg += args[i];
            PrintError(msg.c_str());
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

int handleInject(const std::vector<std::wstring> &args)
{
    std::wstring dllPath;
    bool autoInject = false;
    int waitTimeout = 60;

    // Parse arguments
    for (size_t i = 2; i < args.size(); ++i)
    {
        if (args[i] == L"/auto" || args[i] == L"-auto")
        {
            autoInject = true;
        }
        else if (args[i] == L"/timeout" || args[i] == L"-timeout")
        {
            if (i + 1 < args.size())
            {
                waitTimeout = std::stoi(args[++i]);
            }
        }
        else if (dllPath.empty())
        {
            dllPath = args[i];
        }
    }

    if (dllPath.empty())
    {
        PrintError(L"No DLL path specified!");
        return EXIT_FAILURE;
    }

    // Debug: Print arguments
    PrintDebug(L"=== Injection Parameters ===");
    std::wstringstream ss;
    ss << L"DLL Path: " << dllPath;
    PrintDebug(ss.str().c_str());
    ss.str(L"");
    ss << L"Auto Inject: " << (autoInject ? L"YES" : L"NO");
    PrintDebug(ss.str().c_str());
    ss.str(L"");
    ss << L"Timeout: " << waitTimeout << L"s";
    PrintDebug(ss.str().c_str());

    // Validate DLL path
    if (!std::filesystem::exists(dllPath))
    {
        std::wstring msg = L"DLL not found: ";
        msg += dllPath;
        PrintError(msg.c_str());
        return EXIT_FAILURE;
    }

    auto fileSize = std::filesystem::file_size(dllPath);
    ss.str(L"");
    ss << L"DLL Size: " << fileSize << L" bytes (" << (fileSize / 1024) << L" KB)";
    PrintInfo(ss.str().c_str());

    // Check for Roblox
    ULONG processId = static_cast<ULONG>(-1);
    const wchar_t *processNames[] = {L"RobloxPlayerBeta.exe", L"Windows10Universal.exe", L"RobloxPlayer.exe"};

    PrintInfo(L"Searching for Roblox process...");

    for (const auto &name : processNames)
    {
        PrintDebug(name);
        ULONG pid = Utils::GetProcessIdByName(name);
        if (pid != static_cast<ULONG>(-1))
        {
            processId = pid;
            ss.str(L"");
            ss << L"Found: " << name << L" (PID: " << pid << L")";
            PrintSuccess(ss.str().c_str());
            PrintDebugHex(L"Process ID", pid);
            break;
        }
    }

    if (processId == static_cast<ULONG>(-1))
    {
        if (autoInject)
        {
            if (!WaitForRoblox(processId, waitTimeout))
            {
                return EXIT_FAILURE;
            }
        }
        else
        {
            PrintError(L"Roblox is not running! Use /auto to wait for it.");
            return EXIT_FAILURE;
        }
    }

    // Wait for Roblox to be ready
    PrintInfo(L"Giving Roblox time to initialize...");
    std::this_thread::sleep_for(std::chrono::seconds(2));

    if (!WaitForRobloxReady(processId, 30))
    {
        PrintWarning(L"Roblox may not be fully initialized, proceeding anyway...");
    }

    // Read DLL into memory
    PrintInfo(L"Reading DLL into memory...");

    std::vector<uint8_t> imageBuffer{};

    try
    {
        std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
        std::streamsize fileSizeStream = file.tellg();
        file.seekg(0, std::ios::beg);
        imageBuffer = std::vector<uint8_t>(fileSizeStream);
        file.read(reinterpret_cast<char *>(imageBuffer.data()), fileSizeStream);
        file.close();

        PrintDebugHex(L"Buffer Address", reinterpret_cast<ULONG_PTR>(imageBuffer.data()));
        ss.str(L"");
        ss << L"Buffer Size: " << imageBuffer.size() << L" bytes";
        PrintDebug(ss.str().c_str());
    }
    catch (const std::exception &e)
    {
        std::string errMsg = "Failed to read DLL: ";
        errMsg += e.what();
        std::wstring wErrMsg(errMsg.begin(), errMsg.end());
        PrintError(wErrMsg.c_str());
        return EXIT_FAILURE;
    }

    PrintSuccess(L"DLL loaded into memory!");

    // Validate PE header
    PrintInfo(L"Validating PE structure...");

    if (imageBuffer.size() < sizeof(IMAGE_DOS_HEADER))
    {
        PrintError(L"Invalid DLL: File too small!");
        return EXIT_FAILURE;
    }

    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBuffer.data());
    PrintDebugHex(L"DOS Signature", dosHeader->e_magic);

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        PrintError(L"Invalid DLL: Bad DOS signature (expected 0x5A4D)!");
        return EXIT_FAILURE;
    }
    PrintSuccess(L"DOS Header: OK (MZ)");

    if (imageBuffer.size() < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS))
    {
        PrintError(L"Invalid DLL: Truncated PE header!");
        return EXIT_FAILURE;
    }

    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(imageBuffer.data() + dosHeader->e_lfanew);
    PrintDebugHex(L"PE Signature", ntHeaders->Signature);
    PrintDebugHex(L"Machine", ntHeaders->FileHeader.Machine);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        PrintError(L"Invalid DLL: Bad PE signature (expected 0x4550)!");
        return EXIT_FAILURE;
    }
    PrintSuccess(L"PE Header: OK");

    if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        PrintError(L"Invalid DLL: Not a 64-bit DLL (expected x64)!");
        return EXIT_FAILURE;
    }
    PrintSuccess(L"Architecture: x64 OK");

    // Print PE info
    PrintDebug(L"=== PE Information ===");
    PrintDebugHex(L"ImageBase", ntHeaders->OptionalHeader.ImageBase);
    PrintDebugHex(L"SizeOfImage", ntHeaders->OptionalHeader.SizeOfImage);
    PrintDebugHex(L"EntryPoint RVA", ntHeaders->OptionalHeader.AddressOfEntryPoint);
    ss.str(L"");
    ss << L"Number of Sections: " << ntHeaders->FileHeader.NumberOfSections;
    PrintDebug(ss.str().c_str());

    // Enable bypass before injection
    std::wcout << std::endl;
    PrintInfo(L"=== KERNEL BYPASS PHASE ===");
    PrintInfo(L"Enabling kernel bypass hooks...");

    NTSTATUS status = g_VACDriverManager->EnableBypass();
    PrintNtStatus(L"EnableBypass", status);

    if (!NT_SUCCESS(status))
    {
        return EXIT_FAILURE;
    }

    // Inject DLL via kernel driver
    std::wcout << std::endl;
    PrintInfo(L"=== KERNEL INJECTION PHASE ===");
    PrintInfo(L"Sending DLL to kernel driver for injection...");
    PrintDebugHex(L"Image Buffer", reinterpret_cast<ULONG_PTR>(imageBuffer.data()));
    ss.str(L"");
    ss << L"Image Size: " << imageBuffer.size() << L" bytes";
    PrintDebug(ss.str().c_str());

    status = g_VACDriverManager->InjectDll(imageBuffer);
    PrintNtStatus(L"InjectDll", status);

    if (!NT_SUCCESS(status))
    {
        PrintError(L"Injection FAILED!");

        // Print common error codes
        switch (status)
        {
        case STATUS_UNSUCCESSFUL:
            PrintInfo(L"Hint: The driver could not inject. Check if Roblox is running.");
            break;
        case STATUS_ACCESS_DENIED:
            PrintInfo(L"Hint: Access denied. Anti-cheat may be blocking injection.");
            break;
        case STATUS_INSUFFICIENT_RESOURCES:
            PrintInfo(L"Hint: Not enough memory in target process.");
            break;
        default:
            PrintInfo(L"Hint: Check DbgView for kernel driver logs.");
            break;
        }
        return EXIT_FAILURE;
    }

    std::wcout << std::endl;
    std::wcout << Color::Green << L"  ╔═══════════════════════════════════════════════╗" << Color::Reset << std::endl;
    std::wcout << Color::Green << L"  ║     DLL INJECTED SUCCESSFULLY!                ║" << Color::Reset << std::endl;
    std::wcout << Color::Green << L"  ╚═══════════════════════════════════════════════╝" << Color::Reset << std::endl;
    std::wcout << std::endl;

    PrintInfo(L"Check DbgView for kernel driver logs.");
    PrintInfo(L"Your DLL's DllMain should have been called with DLL_PROCESS_ATTACH.");

    return EXIT_SUCCESS;
}

void PrintUsage()
{
    std::wcout << Color::White << L"  Usage:" << Color::Reset << std::endl;
    std::wcout << Color::Gray << L"    injector.exe inject <dll-path> [options]" << Color::Reset << std::endl;
    std::wcout << Color::Gray << L"    injector.exe bypass /enable|/disable" << Color::Reset << std::endl;
    std::wcout << std::endl;

    std::wcout << Color::White << L"  Commands:" << Color::Reset << std::endl;
    std::wcout << Color::Cyan << L"    inject" << Color::Gray << L"      - Inject DLL into Roblox" << Color::Reset
               << std::endl;
    std::wcout << Color::Cyan << L"    bypass" << Color::Gray << L"      - Enable/disable kernel bypass" << Color::Reset
               << std::endl;
    std::wcout << std::endl;

    std::wcout << Color::White << L"  Inject Options:" << Color::Reset << std::endl;
    std::wcout << Color::Yellow << L"    /auto" << Color::Gray << L"       - Wait for Roblox to start" << Color::Reset
               << std::endl;
    std::wcout << Color::Yellow << L"    /timeout N" << Color::Gray << L"  - Set wait timeout in seconds (default: 60)"
               << Color::Reset << std::endl;
    std::wcout << std::endl;

    std::wcout << Color::White << L"  Examples:" << Color::Reset << std::endl;
    std::wcout << Color::Gray << L"    injector.exe inject C:\\path\\to\\dll.dll" << Color::Reset << std::endl;
    std::wcout << Color::Gray << L"    injector.exe inject mydll.dll /auto" << Color::Reset << std::endl;
    std::wcout << Color::Gray << L"    injector.exe bypass /enable" << Color::Reset << std::endl;
    std::wcout << std::endl;
}

int wmain(int argc, const wchar_t **argv)
{
    EnableVirtualTerminal();
    SetConsoleTitle(L"Roblox Kernel Injector");

    PrintBanner();

    if (argc < 2)
    {
        PrintUsage();
        return EXIT_FAILURE;
    }

    std::vector<std::wstring> args(argv, argv + argc);
    std::wstring operation = args[1];

    // Debug: print all args
    PrintDebug(L"=== Command Line Arguments ===");
    for (size_t i = 0; i < args.size(); ++i)
    {
        std::wstringstream ss;
        ss << L"argv[" << i << L"]: " << args[i];
        PrintDebug(ss.str().c_str());
    }
    std::wcout << std::endl;

    // Connect to driver
    PrintInfo(L"Connecting to kernel driver...");
    PrintDebug(L"Device GUID: " VAC_DEVICE_GUID);

    try
    {
        g_VACDriverManager = std::make_unique<IVACDriverManager>(true); // Enable debug mode
    }
    catch (const std::exception &e)
    {
        std::string errMsg = e.what();
        std::wstring wErrMsg(errMsg.begin(), errMsg.end());
        PrintError(wErrMsg.c_str());
        PrintError(L"Make sure the driver is loaded!");
        std::wcout << std::endl;
        std::wcout << Color::Yellow << L"  To load the driver:" << Color::Reset << std::endl;
        std::wcout << Color::Gray << L"    1. Run as Administrator" << Color::Reset << std::endl;
        std::wcout << Color::Gray << L"    2. Enable Test Signing: bcdedit /set testsigning on" << Color::Reset
                   << std::endl;
        std::wcout << Color::Gray << L"    3. Load driver: sc create VACBypass type=kernel binPath=<path>"
                   << Color::Reset << std::endl;
        std::wcout << Color::Gray << L"    4. Start driver: sc start VACBypass" << Color::Reset << std::endl;
        std::wcout << std::endl;
        return EXIT_FAILURE;
    }

    PrintSuccess(L"Connected to kernel driver!");
    std::wcout << std::endl;

    // Handle operations
    if (operation == L"inject" || operation == L"inject-dll")
    {
        if (args.size() < 3)
        {
            PrintError(L"'inject' requires a DLL path!");
            std::wcout << std::endl;
            PrintUsage();
            return EXIT_FAILURE;
        }
        return handleInject(args);
    }
    else if (operation == L"bypass")
    {
        if (args.size() < 3)
        {
            PrintError(L"'bypass' requires /enable or /disable!");
            return EXIT_FAILURE;
        }
        return handleBypass(args);
    }
    else
    {
        std::wstring msg = L"Unknown command: ";
        msg += operation;
        PrintError(msg.c_str());
        std::wcout << std::endl;
        PrintUsage();
        return EXIT_FAILURE;
    }
}
