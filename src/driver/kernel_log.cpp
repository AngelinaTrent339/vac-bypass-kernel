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

// kernel_log.cpp - Storage for kernel log buffer
// This file defines the actual storage for the log buffer declared in trace.hpp

#include "includes.hpp"

namespace KernelLog
{
// Actual storage for log buffer
LogEntry g_LogBuffer[MAX_LOG_BUFFER_ENTRIES] = {};
volatile LONG g_LogWriteIndex = 0;
volatile LONG g_LogCount = 0;
volatile LONG g_LogDropped = 0;
KSPIN_LOCK g_LogSpinLock = {};
BOOLEAN g_LogInitialized = FALSE;

} // namespace KernelLog
