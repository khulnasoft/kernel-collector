// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _KHULNASOFT_DEFS_
#define _KHULNASOFT_DEFS_ 1

enum khulnasoft_controller {
    KHULNASOFT_CONTROLLER_APPS_ENABLED,
    KHULNASOFT_CONTROLLER_APPS_LEVEL,

    // These index show the number of elements
    // stored inside hash tables.
    //
    // We have indexes to count increase and
    // decrease events, because __sync_fetch_and_sub
    // generates compilatoion errors.
    KHULNASOFT_CONTROLLER_PID_TABLE_ADD,
    KHULNASOFT_CONTROLLER_PID_TABLE_DEL,
    KHULNASOFT_CONTROLLER_TEMP_TABLE_ADD,
    KHULNASOFT_CONTROLLER_TEMP_TABLE_DEL,

    KHULNASOFT_CONTROLLER_END
};

enum khulnasoft_apps_level {
    KHULNASOFT_APPS_LEVEL_REAL_PARENT,
    KHULNASOFT_APPS_LEVEL_PARENT,
    KHULNASOFT_APPS_LEVEL_ALL,
    KHULNASOFT_APPS_LEVEL_IGNORE,

    KHULNASOFT_APPS_LEVEL_END
};

#endif

