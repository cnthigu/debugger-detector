#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <cstdint>

#include <windows.h>
#include <TlHelp32.h>
#include <tchar.h>

#include "vendor/vmprotect/VMProtectSDK.h"
#include "third_party/xorstr.h"
#include "third_party/color.h"

using namespace std;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

namespace detector
{
    int  scan_detection_time = 1000;
    bool enable_window_scan = true;
    bool enable_verbose_log = true;
    bool enable_process_scan = true;
    bool enable_driver_scan = true;

    void on_debugger_detected(const string& name)
    {
        VMProtectBeginUltra("on_debugger_detected");

        if (enable_verbose_log)
        {
            std::cout << termcolor::white << XorStr("=====================================").c_str() << std::endl;
            std::cout << termcolor::green << XorStr(" Debugger detected!").c_str() << std::endl;
            std::cout << termcolor::red << XorStr(" Debugger Name: ").c_str() << termcolor::cyan << name << std::endl;
            std::cout << termcolor::white << XorStr("=====================================").c_str() << std::endl;

            Sleep(3000);
        }

        exit(0);
        VMProtectEnd();
    }

    void check_is_debugger_present()
    {
        if (IsDebuggerPresent())
        {
            on_debugger_detected("IsDebuggerPresent");
        }
    }

    void check_debug_break()
    {
        __try
        {
            DebugBreak();
        }
        __except (GetExceptionCode() == EXCEPTION_BREAKPOINT
            ? EXCEPTION_EXECUTE_HANDLER
            : EXCEPTION_CONTINUE_SEARCH)
        {
            // Normal flow when no debugger is attached.
        }
    }

    uint32_t get_process_id(const char* exe_name)
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (snap == INVALID_HANDLE_VALUE)
        {
            return 0;
        }

        PROCESSENTRY32 pe{ sizeof(PROCESSENTRY32) };
        uint32_t  pid = 0;

        if (Process32First(snap, &pe))
        {
            do
            {
                if (_stricmp(exe_name, pe.szExeFile) == 0)
                {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(snap, &pe));
        }

        CloseHandle(snap);
        return pid;
    }

    const vector<pair<string, string>> suspicious_processes = {

    { "KsDumperClient.exe",     "KsDumper" },
    { "KsDumper.exe",           "KsDumper" },
    { "HTTPDebuggerUI.exe",     "HTTP Debugger" },
    { "HTTPDebuggerSvc.exe",    "HTTP Debugger Service" },
    { "FolderChangesView.exe",  "FolderChangesView" },
    { "ProcessHacker.exe",      "Process Hacker" },
    { "procmon.exe",            "Process Monitor" },
    { "idaq.exe",               "IDA" },
    { "ida.exe",                "IDA" },
    { "idaq64.exe",             "IDA" },
    { "Wireshark.exe",          "Wireshark" },
    { "Fiddler.exe",            "Fiddler" },
    { "Fiddler Everywhere.exe", "Fiddler Everywhere" },
    { "Xenos64.exe",            "Xenos64" },
    { "Cheat Engine.exe",       "Cheat Engine" },
    { "x64dbg.exe",             "x64dbg" },
    { "x32dbg.exe",             "x32dbg" },
    { "die.exe",                "Detect It Easy" },
    { "Everything.exe",         "Everything" },
    { "OLLYDBG.exe",            "OllyDbg" },
    { "HxD64.exe",              "HxD" },
    { "HxD32.exe",              "HxD" },
    { "snowman.exe",            "Snowman" },
    };

    void check_suspicious_processes()
    {
        if (!enable_process_scan)
            return;

        for (const auto& entry : suspicious_processes)
        {
            const string& exe_name = entry.first;
            const string& friendly_name = entry.second;

            if (get_process_id(exe_name.c_str()))
            {
                on_debugger_detected(friendly_name);
                return;
            }
        }
    }

    const vector<pair<string, string>> suspicious_titles = {
        // IDA
        { "IDA: Quick start",     "IDA" },

        // Cheat Engine (multiple versions)
        { "Memory Viewer",        "Cheat Engine" },
        { "Cheat Engine",         "Cheat Engine" },
        { "Cheat Engine 7.0",     "Cheat Engine" },
        { "Cheat Engine 7.1",     "Cheat Engine" },
        { "Cheat Engine 7.2",     "Cheat Engine" },
        { "Cheat Engine 7.3",     "Cheat Engine" },
        { "Cheat Engine 7.4",     "Cheat Engine" },
        { "Process List",         "Cheat Engine" },

        // Debuggers
        { "x32DBG",               "x32dbg" },
        { "x64DBG",               "x64dbg" },
        { "OllyDbg",              "OllyDbg" },

        // Dumpers
        { "KsDumper",             "KsDumper" },
        { "Scylla x86 v0.9.5",    "Scylla x86" },
        { "Scylla x86 v0.9.5a",   "Scylla x86" },
        { "Scylla x86 v0.9.8",    "Scylla x86" },
        { "Scylla x64 v0.9.5",    "Scylla x64" },
        { "Scylla x64 v0.9.5a",   "Scylla x64" },
        { "Scylla x64 v0.9.8",    "Scylla x64" },

        // Network analyzers
        { "Fiddler Everywhere",   "Fiddler Everywhere" },
        { "Fiddler Classic",      "Fiddler Classic" },
        { "Fiddler Jam",          "Fiddler Jam" },
        { "FiddlerCap",           "FiddlerCap" },
        { "FiddlerCore",          "FiddlerCore" },

        // Other tools
        { "Detect It Easy v3.01", "Detect It Easy" },
        { "Everything",           "Everything" },
        { "HxD",                  "HxD" },
        { "Snowman",              "Snowman" },
    };

    void check_suspicious_windows()
    {
        if (!enable_window_scan)
            return;

        for (const auto& entry : suspicious_titles)
        {
            const string& title = entry.first;
            const string& friendly_name = entry.second;

            if (FindWindowA(NULL, title.c_str()))
            {
                on_debugger_detected(friendly_name);
                return;
            }
        }
    }

    const vector<wstring> suspicious_devices = {
       L"\\\\.\\Dumper",
       L"\\\\.\\KsDumper",
    };

    void check_suspicious_drivers()
    {
        VMProtectBeginUltra("check_suspicious_drivers");

        if (!enable_driver_scan)
            return;

        for (const auto& device : suspicious_devices)
        {
            HANDLE hFile = CreateFileW(
                device.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL);

            if (hFile != INVALID_HANDLE_VALUE)
            {
                CloseHandle(hFile);
                on_debugger_detected("kernel driver detected");
                return;
            }
        }

        VMProtectEnd();
    }

    FARPROC get_ntdll_function(const char* function_name)
    {
        static HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));

        if (!hNtDll)
        {
            return NULL;
        }

        return GetProcAddress(hNtDll, function_name);
    }

    BOOL check_process_debug_flags()
    {
        VMProtectBeginUltra("check_process_debug_flags");
        using pNtQueryInformationProcess = NTSTATUS(WINAPI*)(HANDLE, UINT, PVOID, ULONG, PULONG);

        auto NtQueryInfo = reinterpret_cast<pNtQueryInformationProcess>(
            get_ntdll_function("NtQueryInformationProcess")
            );

        if (!NtQueryInfo)
            return FALSE;

        const int ProcessDebugFlags = 0x1F;

        DWORD NoDebugInherit = 0;

        NTSTATUS status = NtQueryInfo(
            GetCurrentProcess(),
            ProcessDebugFlags,
            &NoDebugInherit,
            sizeof(DWORD),
            NULL
        );

        if (status != STATUS_SUCCESS)
            return FALSE;

        if (NoDebugInherit == FALSE)
        {
            on_debugger_detected("ProcessDebugFlags");
            return TRUE;
        }

        VMProtectEnd();
        return FALSE;
    }

    BOOL check_kernel_debugger()
    {
        VMProtectBeginUltra("check_kernel_debugger");
        struct SYSTEM_KERNEL_DEBUGGER_INFORMATION
        {
            BOOLEAN DebuggerEnabled;
            BOOLEAN DebuggerNotPresent;
        };

        enum { SystemKernelDebuggerInformationClass = 35 };

        using pZwQuerySystemInformation = NTSTATUS(WINAPI*)(int, PVOID, ULONG, PULONG);

        auto ZwQuerySysInfo = reinterpret_cast<pZwQuerySystemInformation>(
            get_ntdll_function("ZwQuerySystemInformation")
            );

        if (!ZwQuerySysInfo)
            return FALSE;

        SYSTEM_KERNEL_DEBUGGER_INFORMATION info{};

        NTSTATUS status = ZwQuerySysInfo(
            SystemKernelDebuggerInformationClass,
            &info,
            sizeof(info),
            NULL
        );

        if (status != STATUS_SUCCESS)
            return FALSE;

        if (info.DebuggerEnabled && !info.DebuggerNotPresent)
        {
            on_debugger_detected("SystemKernelDebuggerInformation");
            return TRUE;
        }
        VMProtectEnd();
        return FALSE;
    }

    BOOL check_thread_hide()
    {
        VMProtectBeginUltra("check_thread_hide");

        using pNtSetInformationThread = NTSTATUS(WINAPI*)(HANDLE, UINT, PVOID, ULONG);

        auto NtSetInfoThread = reinterpret_cast<pNtSetInformationThread>(
            get_ntdll_function("NtSetInformationThread")
            );

        if (!NtSetInfoThread)
            return FALSE;

        const int ThreadHideFromDebuggerClass = 0x11;

        NTSTATUS status = NtSetInfoThread(
            GetCurrentThread(),
            ThreadHideFromDebuggerClass,
            NULL,
            0
        );

        if (status != STATUS_SUCCESS)
        {
            on_debugger_detected("ThreadHideFromDebugger");
            return TRUE;
        }

        VMProtectEnd();
        return FALSE;
    }

    void erase_pe_header()
    {
        VMProtectBeginUltra("erase_pe_header");
        char* base = reinterpret_cast<char*>(GetModuleHandle(NULL));
        if (!base)
            return;

        DWORD oldProtect = 0;
        if (VirtualProtect(base, 4096, PAGE_READWRITE, &oldProtect))
        {
            ZeroMemory(base, 4096);
            VirtualProtect(base, 4096, oldProtect, &oldProtect);
        }
        VMProtectEnd();
    }

    void run_detection_loop()
    {
        erase_pe_header();

        while (true)
        {
            check_suspicious_processes();
            check_suspicious_windows();
            check_suspicious_drivers();
            check_process_debug_flags();
            check_kernel_debugger();
            check_thread_hide();

            SleepEx(scan_detection_time, TRUE);
        }
    }

    void start_protection()
    {
        thread(run_detection_loop).detach();
    }
}
