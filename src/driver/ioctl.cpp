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

namespace Comms
{

// Statistics counters
static volatile LONG64 g_InjectionCount = 0;
static volatile LONG64 g_HookedSyscallCount = 0;

typedef struct _INJECT_IMAGE_CONTEXT
{
    WORK_QUEUE_ITEM WorkItem;
    PEPROCESS Process;
    PVOID ImageBase;
    ULONG ImageSize;
    NTSTATUS Status;
    KEVENT Event;
    BOOLEAN UseStealthInject;

} INJECT_IMAGE_CONTEXT, *PINJECT_IMAGE_CONTEXT;

static void InjectImageWorkerRoutine(_In_ PVOID param)
{
    PAGED_CODE();
    NT_ASSERT(param);

    auto context = reinterpret_cast<PINJECT_IMAGE_CONTEXT>(param);

    KERNEL_LOG_INFO("InjectImageWorkerRoutine started, UseStealthInject=%d", context->UseStealthInject);
    KERNEL_LOG_INFO("Target Process: 0x%p, ImageBase: 0x%p, ImageSize: %u", context->Process, context->ImageBase,
                    context->ImageSize);

    // Use stealth injection for Roblox
    if (context->UseStealthInject)
    {
        KERNEL_LOG_INFO("Using StealthInject method...");

        StealthInject::STEALTH_INJECT_CONFIG config = {};
        config.WaitForCompletion = TRUE;
        config.TimeoutMs = 60000;
        config.NotificationAddress = nullptr;

        auto result = StealthInject::AttachAndInject(context->Process, context->ImageBase, context->ImageSize, &config);

        if (result == StealthInject::INJECT_STATUS::Success)
        {
            KERNEL_LOG_INFO("StealthInject SUCCESS!");
            context->Status = STATUS_SUCCESS;
            InterlockedIncrement64(&g_InjectionCount);
        }
        else
        {
            KERNEL_LOG_ERROR(STATUS_UNSUCCESSFUL, "StealthInject FAILED with result: %d", (int)result);
            context->Status = STATUS_UNSUCCESSFUL;
        }
    }
    else
    {
        KERNEL_LOG_INFO("Using legacy Inject method...");

        context->Status = Inject::AttachAndInject(context->Process, context->ImageBase, context->ImageSize);

        if (NT_SUCCESS(context->Status))
        {
            KERNEL_LOG_INFO("Legacy inject SUCCESS!");
            InterlockedIncrement64(&g_InjectionCount);
        }
        else
        {
            KERNEL_LOG_ERROR(context->Status, "Legacy inject FAILED!");
        }
    }

    KERNEL_LOG_INFO("InjectImageWorkerRoutine completed with status: 0x%08X", context->Status);
    KeSetEvent(&context->Event, IO_NO_INCREMENT, FALSE);
};

NTSTATUS HandleIoctl(_In_ PVOID data, _In_ ULONG dataSize)
{
    PAGED_CODE();
    NT_ASSERT(data);

    KERNEL_LOG_DEBUG("HandleIoctl called, dataSize=%u", dataSize);

    //=========================================================================
    // Handler: DisableBypass
    //=========================================================================
    auto HandleDisableBypass = [](_In_ const PDRIVER_REQUEST_DISABLE_BYPASS request) -> NTSTATUS {
        KERNEL_LOG_INFO("=== DisableBypass Request ===");

        NTSTATUS status;
        __try
        {
            Hooks::g_shouldBypass = false;
            KERNEL_LOG_INFO("Bypass DISABLED - Hooks::g_shouldBypass = false");
            request->SetStatus(STATUS_SUCCESS);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            KERNEL_LOG_ERROR(status, "DisableBypass exception: 0x%08X", status);
            return status;
        }
        return STATUS_SUCCESS;
    };

    //=========================================================================
    // Handler: EnableBypass
    //=========================================================================
    auto HandleEnableBypass = [](_In_ const PDRIVER_REQUEST_ENABLE_BYPASS request) -> NTSTATUS {
        KERNEL_LOG_INFO("=== EnableBypass Request ===");

        NTSTATUS status;
        __try
        {
            Hooks::g_shouldBypass = true;
            KERNEL_LOG_INFO("Bypass ENABLED - Hooks::g_shouldBypass = true");
            request->SetStatus(STATUS_SUCCESS);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            KERNEL_LOG_ERROR(status, "EnableBypass exception: 0x%08X", status);
            return status;
        }
        return STATUS_SUCCESS;
    };

    //=========================================================================
    // Handler: InjectDll
    //=========================================================================
    auto HandleInject = [](_In_ const PDRIVER_REQUEST_INJECT request) -> NTSTATUS {
        KERNEL_LOG_INFO("=== InjectDll Request ===");
        KERNEL_LOG_INFO("ImageBase: 0x%p, ImageSize: %u bytes", request->ImageBase, request->ImageSize);

        NTSTATUS status = STATUS_UNSUCCESSFUL;

        if (request->ImageSize <= 0)
        {
            KERNEL_LOG_ERROR(STATUS_INVALID_PARAMETER, "Invalid ImageSize: %u", request->ImageSize);
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        __try
        {
            Hooks::g_shouldBypass = true;
            KERNEL_LOG_INFO("Bypass auto-enabled for injection");

            KERNEL_LOG_DEBUG("ProbeForRead on ImageBase 0x%p, size %u", request->ImageBase, request->ImageSize);
            ProbeForRead(request->ImageBase, request->ImageSize, alignof(PVOID));
            KERNEL_LOG_DEBUG("ProbeForRead succeeded");

            // Allocate kernel memory for image
            KERNEL_LOG_INFO("Allocating %u bytes in kernel pool...", request->ImageSize);
            auto imageBase = Memory::AllocNonPaged(request->ImageSize, Memory::TAG_DEFAULT);
            if (!imageBase)
            {
                KERNEL_LOG_ERROR(STATUS_INSUFFICIENT_RESOURCES, "FAILED to allocate %u bytes for DLL image!",
                                 request->ImageSize);
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto Exit;
            }
            KERNEL_LOG_INFO("Kernel allocation SUCCESS at 0x%p", imageBase);

            KERNEL_LOG_DEBUG("Copying %u bytes from usermode to kernel...", request->ImageSize);
            RtlCopyMemory(imageBase, request->ImageBase, request->ImageSize);
            KERNEL_LOG_DEBUG("Memory copy complete");

            // Get target process
            KERNEL_LOG_INFO("Getting target game process...");
            PEPROCESS process = Processes::GetGameProcess();
            if (!process)
            {
                KERNEL_LOG_ERROR(STATUS_NOT_FOUND, "FAILED to get game process! Is Roblox running?");
                Memory::FreePool(imageBase);
                status = STATUS_NOT_FOUND;
                goto Exit;
            }

            HANDLE processId = PsGetProcessId(process);
            KERNEL_LOG_INFO("Target process found: PID=%llu, EPROCESS=0x%p", (ULONG64)processId, process);

            SCOPE_EXIT
            {
                ObDereferenceObject(process);
            };

            // Allocate injection context
            KERNEL_LOG_DEBUG("Allocating INJECT_IMAGE_CONTEXT (%u bytes)...", (ULONG)sizeof(INJECT_IMAGE_CONTEXT));
            auto imageContext = reinterpret_cast<PINJECT_IMAGE_CONTEXT>(
                Memory::AllocNonPaged(sizeof(INJECT_IMAGE_CONTEXT), Memory::TAG_DEFAULT));
            if (!imageContext)
            {
                KERNEL_LOG_ERROR(STATUS_INSUFFICIENT_RESOURCES, "FAILED to allocate %u bytes for injection context!",
                                 (ULONG)sizeof(INJECT_IMAGE_CONTEXT));
                Memory::FreePool(imageBase);
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto Exit;
            }

            SCOPE_EXIT
            {
                Memory::FreePool(imageContext);
            };

            // Setup injection context
            imageContext->Process = process;
            imageContext->ImageBase = imageBase;
            imageContext->ImageSize = request->ImageSize;
            imageContext->UseStealthInject = TRUE;
            KeInitializeEvent(&imageContext->Event, NotificationEvent, FALSE);
            ExInitializeWorkItem(&imageContext->WorkItem, &InjectImageWorkerRoutine, imageContext);

            KERNEL_LOG_INFO("Queueing injection work item...");
            ExQueueWorkItem(&imageContext->WorkItem, DelayedWorkQueue);

            KERNEL_LOG_INFO("Waiting for injection to complete...");
            status = KeWaitForSingleObject(&imageContext->Event, Executive, KernelMode, FALSE, nullptr);
            if (!NT_SUCCESS(status))
            {
                KERNEL_LOG_ERROR(status, "KeWaitForSingleObject FAILED: 0x%08X", status);
                goto Exit;
            }

            status = imageContext->Status;

            if (NT_SUCCESS(status))
            {
                KERNEL_LOG_INFO("=== INJECTION SUCCESSFUL ===");
            }
            else
            {
                KERNEL_LOG_ERROR(status, "=== INJECTION FAILED: 0x%08X ===", status);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            KERNEL_LOG_ERROR(status, "InjectDll EXCEPTION: 0x%08X", status);
        }
    Exit:
        request->SetStatus(status);
        return status;
    };

    //=========================================================================
    // Handler: GetLogs - Return kernel debug logs to usermode
    //=========================================================================
    auto HandleGetLogs = [](_In_ PDRIVER_REQUEST_GET_LOGS request) -> NTSTATUS {
        KERNEL_LOG_DEBUG("=== GetLogs Request (MaxEntries=%u) ===", request->MaxEntries);

        ULONG maxEntries = min(request->MaxEntries, (ULONG)MAX_LOG_ENTRIES);
        ULONG totalAvailable = 0;
        ULONG dropped = 0;

        ULONG entriesReturned = KernelLog::GetLogs(request->Entries, maxEntries, &totalAvailable, &dropped);

        request->EntriesReturned = entriesReturned;
        request->TotalEntriesAvailable = totalAvailable;
        request->EntriesDropped = dropped;
        request->SetStatus(STATUS_SUCCESS);

        KERNEL_LOG_DEBUG("GetLogs returning %u entries (dropped=%u)", entriesReturned, dropped);
        return STATUS_SUCCESS;
    };

    //=========================================================================
    // Handler: ClearLogs - Clear kernel log buffer
    //=========================================================================
    auto HandleClearLogs = [](_In_ PDRIVER_REQUEST_CLEAR_LOGS request) -> NTSTATUS {
        KERNEL_LOG_INFO("=== ClearLogs Request ===");

        ULONG cleared = KernelLog::ClearLogs();
        request->EntriesCleared = cleared;
        request->SetStatus(STATUS_SUCCESS);

        KERNEL_LOG_INFO("Cleared %u log entries", cleared);
        return STATUS_SUCCESS;
    };

    //=========================================================================
    // Handler: GetStatus - Get driver status info
    //=========================================================================
    auto HandleGetStatus = [](_In_ PDRIVER_REQUEST_GET_STATUS request) -> NTSTATUS {
        KERNEL_LOG_DEBUG("=== GetStatus Request ===");

        request->BypassEnabled = Hooks::g_shouldBypass ? TRUE : FALSE;
        request->HooksInstalled = TRUE; // Assume hooks are installed if driver is loaded
        request->InjectionCount = g_InjectionCount;
        request->HookedSyscallCount = g_HookedSyscallCount;
        request->LogBufferUsage = KernelLog::GetUsage();

        // Get target process info
        PEPROCESS process = Processes::GetGameProcess();
        if (process)
        {
            request->TargetProcessId = (ULONG)(ULONG_PTR)PsGetProcessId(process);

            // Get process name
            PUCHAR imageName = PsGetProcessImageFileName(process);
            if (imageName)
            {
                RtlStringCchCopyA(request->TargetProcessName, 64, (PCSTR)imageName);
            }

            ObDereferenceObject(process);
        }
        else
        {
            request->TargetProcessId = 0;
            RtlStringCchCopyA(request->TargetProcessName, 64, "(not found)");
        }

        request->SetStatus(STATUS_SUCCESS);
        return STATUS_SUCCESS;
    };

    //=========================================================================
    // Main IOCTL dispatch
    //=========================================================================

    // Check minimum size
    if (dataSize < sizeof(DRIVER_REQUEST_HEADER))
    {
        KERNEL_LOG_ERROR(STATUS_INFO_LENGTH_MISMATCH, "Data size %u < sizeof(DRIVER_REQUEST_HEADER) %u", dataSize,
                         (ULONG)sizeof(DRIVER_REQUEST_HEADER));
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    const auto requestData = static_cast<PDRIVER_REQUEST_HEADER>(data);

    KERNEL_LOG_DEBUG("Request: Magic=0x%08X, Type=%d", requestData->Magic, (int)requestData->Request);

    if (!requestData->IsValid())
    {
        KERNEL_LOG_ERROR(STATUS_INVALID_DEVICE_REQUEST, "Invalid request! Magic=0x%08X, Type=%d", requestData->Magic,
                         (int)requestData->Request);
        return status;
    }

    switch (requestData->Request)
    {
    case EDriverCommunicationRequest::DisableBypass:
        if (dataSize < sizeof(DRIVER_REQUEST_DISABLE_BYPASS))
        {
            KERNEL_LOG_ERROR(STATUS_INVALID_PARAMETER_1, "DisableBypass: buffer too small");
            status = STATUS_INVALID_PARAMETER_1;
            break;
        }
        return HandleDisableBypass(reinterpret_cast<PDRIVER_REQUEST_DISABLE_BYPASS>(data));

    case EDriverCommunicationRequest::EnableBypass:
        if (dataSize < sizeof(DRIVER_REQUEST_ENABLE_BYPASS))
        {
            KERNEL_LOG_ERROR(STATUS_INVALID_PARAMETER_1, "EnableBypass: buffer too small");
            status = STATUS_INVALID_PARAMETER_1;
            break;
        }
        return HandleEnableBypass(reinterpret_cast<PDRIVER_REQUEST_ENABLE_BYPASS>(data));

    case EDriverCommunicationRequest::InjectDll:
        if (dataSize < sizeof(DRIVER_REQUEST_INJECT))
        {
            KERNEL_LOG_ERROR(STATUS_INVALID_PARAMETER_1, "InjectDll: buffer too small");
            status = STATUS_INVALID_PARAMETER_1;
            break;
        }
        return HandleInject(reinterpret_cast<PDRIVER_REQUEST_INJECT>(data));

    case EDriverCommunicationRequest::GetLogs:
        if (dataSize < sizeof(DRIVER_REQUEST_GET_LOGS))
        {
            status = STATUS_INVALID_PARAMETER_1;
            break;
        }
        return HandleGetLogs(reinterpret_cast<PDRIVER_REQUEST_GET_LOGS>(data));

    case EDriverCommunicationRequest::ClearLogs:
        if (dataSize < sizeof(DRIVER_REQUEST_CLEAR_LOGS))
        {
            status = STATUS_INVALID_PARAMETER_1;
            break;
        }
        return HandleClearLogs(reinterpret_cast<PDRIVER_REQUEST_CLEAR_LOGS>(data));

    case EDriverCommunicationRequest::GetStatus:
        if (dataSize < sizeof(DRIVER_REQUEST_GET_STATUS))
        {
            status = STATUS_INVALID_PARAMETER_1;
            break;
        }
        return HandleGetStatus(reinterpret_cast<PDRIVER_REQUEST_GET_STATUS>(data));

    default:
        KERNEL_LOG_ERROR(STATUS_INVALID_DEVICE_REQUEST, "Unknown request type: %d", (int)requestData->Request);
        break;
    }

    return status;
}

}; // namespace Comms