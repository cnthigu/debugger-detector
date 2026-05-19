#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <thread>
#include <chrono>
#include <cstdint>

using namespace std;

namespace detector
{
    int  scan_detection_time = 1000;
    bool enable_window_scan = true;
    bool enable_verbose_log = true;
    bool enable_process_scan = true;

    void on_debugger_detected(const string& name)
    {
        if (enable_verbose_log)
        {
            cout << "========================================" << endl;
            cout << "Debugger detected!" << endl;
            cout << "Debugger Name: " << name << endl;
            cout << "========================================" << endl;

            Sleep(3000);
        }

        exit(0);
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

    void run_detection_loop()
    {
        while (true)
        {
            check_suspicious_processes();
            check_suspicious_windows();
            SleepEx(scan_detection_time, TRUE);
        }
    }

    void start_protection()
    {
        thread(run_detection_loop).detach();
    }
}
