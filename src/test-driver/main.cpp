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

// Console colors - defined here for use in driver_manager.hpp
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

std::unique_ptr<IVACDriverManager> g_VACDriverManager = nullptr;

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

void PrintNtStatus(const wchar_t *operation, NTSTATUS status)
{
    std::wstringstream ss;
    ss << operation << L" returned: 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill(L'0') << status;
    if (NT_SUCCESS(status))
        PrintSuccess(ss.str().c_str());
    else
        PrintError(ss.str().c_str());
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
            return false;
    }
    return true;
}

bool WaitForRobloxReady(ULONG processId, int timeoutSeconds = 30)
{
    PrintInfo(L"Waiting for Roblox to initialize...");

    auto startTime = std::chrono::steady_clock::now();

    while (true)
    {
        if (IsRobloxReady(processId))
        {
            PrintSuccess(L"Roblox is ready!");
            return true;
        }

        auto elapsed =
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - startTime).count();

        if (elapsed >= timeoutSeconds)
        {
            PrintWarning(L"Timeout waiting for Roblox to initialize");
            return false;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

//=============================================================================
// Command Handlers
//=============================================================================

int handleBypass(const std::vector<std::wstring> &args)
{
    for (size_t i = 2; i < args.size(); ++i)
    {
        if (args[i].find(L"/enable") != std::string::npos)
        {
            PrintInfo(L"Enabling kernel bypass...");
            NTSTATUS status = g_VACDriverManager->EnableBypass();
            PrintNtStatus(L"EnableBypass", status);

            // Fetch and display kernel logs
            g_VACDriverManager->PrintKernelLogs();

            if (!NT_SUCCESS(status))
                return EXIT_FAILURE;
            PrintSuccess(L"Bypass ENABLED!");
        }
        else if (args[i].find(L"/disable") != std::string::npos)
        {
            PrintInfo(L"Disabling kernel bypass...");
            NTSTATUS status = g_VACDriverManager->DisableBypass();
            PrintNtStatus(L"DisableBypass", status);

            // Fetch and display kernel logs
            g_VACDriverManager->PrintKernelLogs();

            if (!NT_SUCCESS(status))
                return EXIT_FAILURE;
            PrintSuccess(L"Bypass DISABLED!");
        }
        else
        {
            std::wstring msg = L"Unknown argument: " + args[i];
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
            autoInject = true;
        else if ((args[i] == L"/timeout" || args[i] == L"-timeout") && i + 1 < args.size())
            waitTimeout = std::stoi(args[++i]);
        else if (dllPath.empty())
            dllPath = args[i];
    }

    if (dllPath.empty())
    {
        PrintError(L"No DLL path specified!");
        return EXIT_FAILURE;
    }

    // Validate DLL
    if (!std::filesystem::exists(dllPath))
    {
        PrintError((L"DLL not found: " + dllPath).c_str());
        return EXIT_FAILURE;
    }

    auto fileSize = std::filesystem::file_size(dllPath);
    std::wstringstream ss;
    ss << L"DLL: " << dllPath << L" (" << fileSize << L" bytes)";
    PrintInfo(ss.str().c_str());

    // Find or wait for Roblox
    ULONG processId = static_cast<ULONG>(-1);
    const wchar_t *processNames[] = {L"RobloxPlayerBeta.exe", L"Windows10Universal.exe", L"RobloxPlayer.exe"};

    PrintInfo(L"Searching for Roblox...");
    for (const auto &name : processNames)
    {
        ULONG pid = Utils::GetProcessIdByName(name);
        if (pid != static_cast<ULONG>(-1))
        {
            processId = pid;
            ss.str(L"");
            ss << L"Found: " << name << L" (PID: " << pid << L")";
            PrintSuccess(ss.str().c_str());
            break;
        }
    }

    if (processId == static_cast<ULONG>(-1))
    {
        if (autoInject)
        {
            if (!WaitForRoblox(processId, waitTimeout))
                return EXIT_FAILURE;
        }
        else
        {
            PrintError(L"Roblox is not running! Use /auto to wait.");
            return EXIT_FAILURE;
        }
    }

    // Wait for initialization
    std::this_thread::sleep_for(std::chrono::seconds(2));
    WaitForRobloxReady(processId, 30);

    // Read DLL
    PrintInfo(L"Loading DLL...");
    std::vector<uint8_t> imageBuffer{};

    try
    {
        std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
        std::streamsize fileSizeStream = file.tellg();
        file.seekg(0, std::ios::beg);
        imageBuffer.resize(fileSizeStream);
        file.read(reinterpret_cast<char *>(imageBuffer.data()), fileSizeStream);
        file.close();
    }
    catch (const std::exception &e)
    {
        std::string err = "Failed to read DLL: ";
        err += e.what();
        PrintError(std::wstring(err.begin(), err.end()).c_str());
        return EXIT_FAILURE;
    }
    PrintSuccess(L"DLL loaded!");

    // Validate PE
    PrintInfo(L"Validating PE...");
    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBuffer.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        PrintError(L"Invalid DLL: Bad DOS signature!");
        return EXIT_FAILURE;
    }

    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(imageBuffer.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        PrintError(L"Invalid DLL: Bad PE signature!");
        return EXIT_FAILURE;
    }

    if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        PrintError(L"Invalid DLL: Must be 64-bit!");
        return EXIT_FAILURE;
    }
    PrintSuccess(L"PE validation passed!");

    // Show driver status before injection
    g_VACDriverManager->PrintDriverStatus();

    // Enable bypass
    PrintInfo(L"=== KERNEL BYPASS ===");
    NTSTATUS status = g_VACDriverManager->EnableBypass();
    PrintNtStatus(L"EnableBypass", status);
    if (!NT_SUCCESS(status))
    {
        g_VACDriverManager->PrintKernelLogs();
        return EXIT_FAILURE;
    }

    // Inject
    PrintInfo(L"=== KERNEL INJECTION ===");
    status = g_VACDriverManager->InjectDll(imageBuffer);
    PrintNtStatus(L"InjectDll", status);

    // ALWAYS show kernel logs after injection
    std::wcout << std::endl;
    PrintInfo(L"=== KERNEL DRIVER LOGS ===");
    g_VACDriverManager->PrintKernelLogs();

    if (!NT_SUCCESS(status))
    {
        PrintError(L"INJECTION FAILED!");
        return EXIT_FAILURE;
    }

    std::wcout << std::endl;
    std::wcout << Color::Green << L"  ╔═══════════════════════════════════════════════╗" << Color::Reset << std::endl;
    std::wcout << Color::Green << L"  ║     DLL INJECTED SUCCESSFULLY!                ║" << Color::Reset << std::endl;
    std::wcout << Color::Green << L"  ╚═══════════════════════════════════════════════╝" << Color::Reset << std::endl;
    std::wcout << std::endl;

    return EXIT_SUCCESS;
}

int handleLogs(const std::vector<std::wstring> &args)
{
    bool clearLogs = false;
    bool watchMode = false;

    for (size_t i = 2; i < args.size(); ++i)
    {
        if (args[i] == L"/clear" || args[i] == L"-clear")
            clearLogs = true;
        else if (args[i] == L"/watch" || args[i] == L"-watch")
            watchMode = true;
    }

    if (clearLogs)
    {
        ULONG cleared = 0;
        NTSTATUS status = g_VACDriverManager->ClearLogs(&cleared);
        if (NT_SUCCESS(status))
        {
            std::wstringstream ss;
            ss << L"Cleared " << cleared << L" log entries";
            PrintSuccess(ss.str().c_str());
        }
        else
        {
            PrintError(L"Failed to clear logs!");
        }
        return EXIT_SUCCESS;
    }

    if (watchMode)
    {
        PrintInfo(L"Watch mode - Press Ctrl+C to exit");
        std::wcout << std::endl;

        while (true)
        {
            g_VACDriverManager->PrintKernelLogs();
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    else
    {
        g_VACDriverManager->PrintKernelLogs();
    }

    return EXIT_SUCCESS;
}

int handleStatus(const std::vector<std::wstring> &args)
{
    g_VACDriverManager->PrintDriverStatus();
    return EXIT_SUCCESS;
}

void PrintUsage()
{
    std::wcout << Color::White << L"  Usage:" << Color::Reset << std::endl;
    std::wcout << Color::Gray << L"    injector.exe <command> [options]" << Color::Reset << std::endl;
    std::wcout << std::endl;

    std::wcout << Color::White << L"  Commands:" << Color::Reset << std::endl;
    std::wcout << Color::Cyan << L"    inject <dll>" << Color::Gray << L"   - Inject DLL into Roblox" << Color::Reset
               << std::endl;
    std::wcout << Color::Cyan << L"    bypass" << Color::Gray << L"        - Enable/disable kernel bypass"
               << Color::Reset << std::endl;
    std::wcout << Color::Cyan << L"    logs" << Color::Gray << L"          - View kernel driver logs" << Color::Reset
               << std::endl;
    std::wcout << Color::Cyan << L"    status" << Color::Gray << L"        - Show driver status" << Color::Reset
               << std::endl;
    std::wcout << std::endl;

    std::wcout << Color::White << L"  Inject Options:" << Color::Reset << std::endl;
    std::wcout << Color::Yellow << L"    /auto" << Color::Gray << L"         - Wait for Roblox to start" << Color::Reset
               << std::endl;
    std::wcout << Color::Yellow << L"    /timeout N" << Color::Gray << L"    - Set wait timeout (default: 60s)"
               << Color::Reset << std::endl;
    std::wcout << std::endl;

    std::wcout << Color::White << L"  Bypass Options:" << Color::Reset << std::endl;
    std::wcout << Color::Yellow << L"    /enable" << Color::Gray << L"       - Enable bypass hooks" << Color::Reset
               << std::endl;
    std::wcout << Color::Yellow << L"    /disable" << Color::Gray << L"      - Disable bypass hooks" << Color::Reset
               << std::endl;
    std::wcout << std::endl;

    std::wcout << Color::White << L"  Logs Options:" << Color::Reset << std::endl;
    std::wcout << Color::Yellow << L"    /clear" << Color::Gray << L"        - Clear kernel log buffer" << Color::Reset
               << std::endl;
    std::wcout << Color::Yellow << L"    /watch" << Color::Gray << L"        - Continuously watch logs" << Color::Reset
               << std::endl;
    std::wcout << std::endl;

    std::wcout << Color::White << L"  Examples:" << Color::Reset << std::endl;
    std::wcout << Color::Gray << L"    injector.exe inject mydll.dll /auto" << Color::Reset << std::endl;
    std::wcout << Color::Gray << L"    injector.exe bypass /enable" << Color::Reset << std::endl;
    std::wcout << Color::Gray << L"    injector.exe logs /watch" << Color::Reset << std::endl;
    std::wcout << Color::Gray << L"    injector.exe status" << Color::Reset << std::endl;
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

    // Connect to driver
    PrintInfo(L"Connecting to kernel driver...");

    try
    {
        g_VACDriverManager = std::make_unique<IVACDriverManager>(true);
    }
    catch (const std::exception &e)
    {
        std::string err = e.what();
        PrintError(std::wstring(err.begin(), err.end()).c_str());
        PrintError(L"Make sure the driver is loaded!");
        std::wcout << std::endl;
        std::wcout << Color::Yellow << L"  To load the driver:" << Color::Reset << std::endl;
        std::wcout << Color::Gray << L"    1. Run as Administrator" << Color::Reset << std::endl;
        std::wcout << Color::Gray << L"    2. bcdedit /set testsigning on" << Color::Reset << std::endl;
        std::wcout << Color::Gray << L"    3. sc create VACBypass type=kernel binPath=<path>" << Color::Reset
                   << std::endl;
        std::wcout << Color::Gray << L"    4. sc start VACBypass" << Color::Reset << std::endl;
        std::wcout << std::endl;
        return EXIT_FAILURE;
    }

    PrintSuccess(L"Connected to kernel driver!");
    std::wcout << std::endl;

    // Dispatch command
    if (operation == L"inject" || operation == L"inject-dll")
    {
        if (args.size() < 3)
        {
            PrintError(L"'inject' requires a DLL path!");
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
    else if (operation == L"logs")
    {
        return handleLogs(args);
    }
    else if (operation == L"status")
    {
        return handleStatus(args);
    }
    else
    {
        PrintError((L"Unknown command: " + operation).c_str());
        PrintUsage();
        return EXIT_FAILURE;
    }
}
