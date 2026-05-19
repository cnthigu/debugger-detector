#pragma once
#include <iostream>
#include <string>
#include <Windows.h>

using namespace std;

namespace detector
{
    bool enable_verbose_log = true;

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
}
