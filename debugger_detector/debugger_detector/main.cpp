#include "protect.h"

int main()
{
    detector::enable_window_scan = true;
    detector::enable_verbose_log = true;
    detector::enable_process_scan = true;
    detector::enable_driver_scan = true;


    detector::start_protection();

    detector::check_is_debugger_present();
    detector::check_debug_break();

    while (true)
    {
        SleepEx(10, TRUE);
    }

    return 0;
}