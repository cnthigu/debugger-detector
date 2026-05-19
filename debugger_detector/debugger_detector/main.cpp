#include "protect.h"

int main()
{
    detector::check_is_debugger_present();
    detector::check_debug_break();

    return 0;
}