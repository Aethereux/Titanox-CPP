// Modified by Euclid Jan G.

#pragma once
#include "hook.h"

class HookWrapper {
public:
    static bool CallHook(void *origArray[], void *hookArray[], int count) {
        return Hook(origArray, hookArray, count);
    }

    static bool CallUnhook(void *origArray[], int count) {
        return Unhook(origArray, count);
    }
};