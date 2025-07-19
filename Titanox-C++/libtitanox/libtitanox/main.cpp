#include "libtitanox.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach-o/dyld.h>
#include <string>
#include <objc/runtime.h>
#include <objc/message.h> // Added for Objective-C runtime support
#include <vector>
#include <functional> // For WriteMemory
#include <map>
#include <dirent.h>
#include <sys/stat.h>
#include "../fishhook/fishhook.h"
#include "../brk_hook/Hook/hook_wrapper.hpp"
#include "../MemX/MemX.hpp"
#include "../MemX/VMTWrapper.h"
#include "../vm_funcs/vm.hpp"

// yet another wrapper
void TitanoxHook::Log(const char* format, ...) {
    va_list args;
    va_start(args, format);
    THLog(format, args);
    va_end(args);
}

// Base Address and VM Address Slide
// MemX also have base addr fetch
uint64_t TitanoxHook::GetBaseOfBinary(const char* lib) {
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const char* dyldName = _dyld_get_image_name(i);
        if (dyldName && strstr(dyldName, lib)) {
            return reinterpret_cast<uint64_t>(_dyld_get_image_header(i));
        }
    }
    return 0;
}

intptr_t TitanoxHook::GetVmSlideOfBinary(const char* lib) {
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const char* dyldName = _dyld_get_image_name(i);
        if (dyldName && strstr(dyldName, lib)) {
            return _dyld_get_image_vmaddr_slide(i);
        }
    }
    return 0;
}

// Breakpoint hook
bool TitanoxHook::AddBreakpointAtAddress(void* original, void* hook) {
    if (!original || !hook) {
        Log("[ERROR] addBreakpointAtAddress: invalid params. original=%p, hook=%p", original, hook);
        return false;
    }
    void* origarray[] = { original };
    void* hookarray[] = { hook };
    bool res = HookWrapper::CallHook(origarray, hookarray, 1);
    if (res) {
        Log("[HOOK] Added a breakpoint at address: %p", original);
    } else {
        Log("[ERROR] Failed to add breakpoint at address: %p. Maybe your hooks exceeded limits or something else...", original);
    }
    return res;
}

bool TitanoxHook::RemoveBreakpointAtAddress(void* original) {
    if (!original) {
        Log("[ERROR] invalid param. original=%p", original);
        return false;
    }
    void* origarray[] = { original };
    bool res = HookWrapper::CallUnhook(origarray, 1);
    if (res) {
        Log("[HOOK] Removed breakpoint at address: %p", original);
    } else {
        Log("[ERROR] Failed to remove breakpoint at address: %p", original);
    }
    return res;
}

std::string TitanoxHook::FindExecBinary(const std::string& libName) {
    std::string bundlePath = GetBundlePath(); // GetBundlePath is in utils.h
    // Simple implementation - just return the bundlePath + libName for now
    // This is a simplified version, you may want to implement recursive directory search manually if needed
    std::string fullPath = bundlePath + "/" + libName;
    return fullPath;
}

// MemX Wrappers from eux
uintptr_t TitanoxHook::GetImageBase(const std::string& imageName) {
    return MemX::GetImageBase(imageName.c_str());
}

bool TitanoxHook::IsValidPointer(uintptr_t address) {
    return MemX::IsValidPointer(address);
}

bool TitanoxHook::ReadMemory(uintptr_t address, void* buffer, size_t len) {
    return MemX::_read(address, buffer, len);
}

std::string TitanoxHook::ReadString(uintptr_t address, size_t maxLen) {
    return MemX::ReadString(reinterpret_cast<void*>(address), maxLen);
}

// Refactored WriteMemory (no switch statement)
void TitanoxHook::WriteMemory(uintptr_t address, const std::string& value, const std::string& type) {
    static const std::map<std::string, std::function<void(uintptr_t, const std::string&)>> typeMap = {
        {"int", [](uintptr_t addr, const std::string& val) { MemX::Write<int>(addr, std::stoi(val)); }},
        {"long", [](uintptr_t addr, const std::string& val) { MemX::Write<long>(addr, std::stol(val)); }},
        {"uintptr_t", [](uintptr_t addr, const std::string& val) { MemX::Write<uintptr_t>(addr, std::stoull(val)); }},
        {"uint32_t", [](uintptr_t addr, const std::string& val) { MemX::Write<uint32_t>(addr, std::stoul(val)); }},
        {"uint64_t", [](uintptr_t addr, const std::string& val) { MemX::Write<uint64_t>(addr, std::stoull(val)); }},
        {"uint8_t", [](uintptr_t addr, const std::string& val) { MemX::Write<uint8_t>(addr, static_cast<uint8_t>(std::stoul(val))); }}
        // Add more types here as needed, e.g., {"float", [](uintptr_t addr, const std::string& val) { MemX::Write<float>(addr, std::stof(val)); }}
    };

    auto it = typeMap.find(type);
    if (it == typeMap.end()) {
        Log("[MemX] Unknown type: %s", type.c_str());
        return;
    }

    try {
        it->second(address, value); // Call the appropriate MemX::Write<T>
    } catch (const std::exception& e) {
        Log("[MemX] Error parsing value: %s", e.what());
    }
}

// ONLY CALL AFTER A MEMX FUNCTION CALL IN READ OR WRITE.
void TitanoxHook::ClearAddrRanges() {
    // MemX::ClearAddrRange(); // Method doesn't exist in current MemX implementation
}

// MemX Virtual Function hooking
void* TitanoxHook::VMTHookCreateWithNewFunction(void* newFunc, int32_t index) {
    if (!newFunc) {
        Log("[ERROR] vmthookCreateWithNewFunction: ERROR - newFunc is NULL");
        return nullptr;
    }
    if (index < 0) {
        Log("[ERROR] vmthookCreateWithNewFunction: ERROR - index (%d) is negative", index);
        return nullptr;
    }
    Log("[...] vmthookCreateWithNewFunction: Creating hook with newFunc=%p, index=%d", newFunc, index);
    void* makehook = VMTHook_Create(newFunc, index);
    if (!makehook) {
        Log("[ERROR] vmthookCreateWithNewFunction: Failed to create hook");
    } else {
        Log("[Success] vmthookCreateWithNewFunction: Hook created at %p", makehook);
    }
    return makehook;
}

void TitanoxHook::VMTHookSwap(void* hook, void* instance) {
    if (!hook) {
        Log("[ERROR] vmthookSwap: ERROR - hook pointer is NULL");
        return;
    }
    if (!instance) {
        Log("[ERROR] vmthookSwap: ERROR - instance pointer is NULL");
        return;
    }
    Log("[...] vmthookSwap: Swapping hook %p on instance %p", hook, instance);
    VMTHook_Swap(hook, instance);
    Log("[Success] vmthookSwap: Swap complete");
}

void TitanoxHook::VMTHookReset(void* hook, void* instance) {
    if (!hook) {
        Log("[ERROR] vmthookReset: ERROR - hook pointer is NULL");
        return;
    }
    if (!instance) {
        Log("[ERROR] vmthookReset: ERROR - instance pointer is NULL");
        return;
    }
    Log("[...] vmthookReset: Resetting hook %p on instance %p", hook, instance);
    VMTHook_Reset(hook, instance);
    Log("[Success] vmthookReset: Reset complete");
}

void TitanoxHook::VMTHookDestroy(void* hook) {
    if (!hook) {
        Log("[ERROR] vmthookDestroy: ERROR - hook pointer is NULL");
        return;
    }
    Log("[...] vmthookDestroy: Destroying hook %p", hook);
    VMTHook_Destroy(hook);
    Log("[Success] vmthookDestroy: Destroy complete");
}

void* TitanoxHook::VMTInvokerCreateWithInstance(void* instance, int32_t index) {
    if (!instance) {
        Log("[ERROR] vmtinvokerCreateWithInstance: ERROR - instance pointer is NULL");
        return nullptr;
    }
    if (index < 0) {
        Log("[ERROR] vmtinvokerCreateWithInstance: ERROR - index (%d) is negative", index);
        return nullptr;
    }
    Log("[...] vmtinvokerCreateWithInstance: Creating invoker for instance %p, index %d", instance, index);
    void* callhookidk = VMTInvoker_Create(instance, index);
    if (!callhookidk) {
        Log("[ERROR] vmtinvokerCreateWithInstance: Failed to create invoker");
    } else {
        Log("[Success] vmtinvokerCreateWithInstance: Invoker created at %p", callhookidk);
    }
    return callhookidk;
}

void TitanoxHook::VMTInvokerDestroy(void* invoker) {
    if (!invoker) {
        Log("[ERROR] vmtinvokerDestroy: ERROR - invoker pointer is NULL");
        return;
    }
    Log("[...] vmtinvokerDestroy: Destroying invoker %p", invoker);
    VMTInvoker_Destroy(invoker);
    Log("[Success] vmtinvokerDestroy: Destroy complete");
}

// Static Inline Patch
//init
TitanoxHook::TitanoxHook(const std::string& machoName) {
    if (machoName.empty()) {
        Log("[ERROR] initWithMachOName: Mach-O name is empty");
        return;
    }
    macho_name_ = machoName;
    hooker_ = std::make_unique<SIH::MachOHooker>(machoName);
    if (!hooker_) {
        Log("[ERROR] initWithMachOName: Failed to initialize MachOHooker");
    }
}

// make a patch
std::string TitanoxHook::ApplyPatchAtVaddr(uint64_t vaddr, const std::string& patchHex) {
    if (!hooker_) return "<hooker not initialized>";
    if (patchHex.empty()) return "<invalid patch>";
    auto result = hooker_->ApplyPatch(vaddr, patchHex);
    return result.value_or("<no result>");
}

// hook func via va addr
void* TitanoxHook::HookFunctionAtVaddr(uint64_t vaddr, void* replacement) {
    if (!hooker_ || !replacement) return nullptr;
    return hooker_->HookFunction(vaddr, replacement);
}

// activate patch AFTER making patch
bool TitanoxHook::ActivatePatchAtVaddr(uint64_t vaddr, const std::string& patchHex) {
    if (!hooker_ || patchHex.empty()) return false;
    return hooker_->ActivatePatch(vaddr, patchHex);
}

// deactvate patch AFTER its activated when NEEDED
bool TitanoxHook::DeactivatePatchAtVaddr(uint64_t vaddr, const std::string& patchHex) {
    if (!hooker_ || patchHex.empty()) return false;
    return hooker_->DeactivatePatch(vaddr, patchHex);
}

// static func hook by symbol i.e fishhook
void TitanoxHook::HookStaticFunction(const char* symbol, void* replacement, const char* libName, void** oldorigfuncptr) {
    std::string libnamestr = libName;
    std::string fulllibpath = FindExecBinary(libnamestr);
    void* openinghandle = dlopen(fulllibpath.c_str(), RTLD_NOW | RTLD_NOLOAD);
    if (!openinghandle) {
        Log("cant open lib: %s", libName);
        return;
    }
    if (IsFunctionHooked(symbol, *oldorigfuncptr, libName)) {
        Log("ERR: ptr for func %s is already hooked.", symbol);
        dlclose(openinghandle);
        return;
    }
    struct rebinding rebind;
    rebind.name = symbol;
    rebind.replacement = replacement;
    rebind.replaced = oldorigfuncptr;
    int result = rebind_symbols((struct rebinding[]){rebind}, 1); // fishhook
    if (result != 0) {
        Log("ERR:FISHHOOK %d", symbol, result);
    } else {
        Log("static hook func is good: %s", symbol);
    }
    dlclose(openinghandle);
}

// swizzle method, objc func hook
void TitanoxHook::SwizzleMethod(const char* old_sel, const char* swizzledSelector, const char* targetclass) {
    Class targetClass = objc_getClass(targetclass); // Renamed to avoid conflict
    if (!targetClass) {
        Log("Failed to find class: %s", targetclass);
        return;
    }
    SEL orig_sel = sel_getUid(old_sel);
    SEL myselnew = sel_getUid(swizzledSelector);
    Method originalMethod = class_getInstanceMethod(targetClass, orig_sel);
    Method swizzledMethod = class_getInstanceMethod(targetClass, myselnew);
    bool didAddMethod = class_addMethod(targetClass,
                                        orig_sel,
                                        method_getImplementation(swizzledMethod),
                                        method_getTypeEncoding(swizzledMethod));
    if (didAddMethod) {
        class_replaceMethod(targetClass,
                            myselnew,
                            method_getImplementation(originalMethod),
                            method_getTypeEncoding(originalMethod));
    } else {
        method_exchangeImplementations(originalMethod, swizzledMethod);
    }
}

// hook objc stuff
void TitanoxHook::OverrideMethodInClass(const char* targetclass, const char* selector, void* newFunction, void** oldfunptr) {
    Class target = objc_getClass(targetclass);
    if (!target) {
        Log("Failed to find class: %s", targetclass);
        return;
    }
    SEL sel = sel_getUid(selector);
    Method method = class_getInstanceMethod(target, sel); // Fixed: use 'target' instead of 'targetclass'
    if (!method) {
        Log("Failed to find method %s in class %s", selector, targetclass);
        return;
    }
    if (oldfunptr) {
        *oldfunptr = reinterpret_cast<void*>(method_getImplementation(method)); // Fixed: cast IMP to void*
    }
    method_setImplementation(method, reinterpret_cast<IMP>(newFunction));
    Log("hooked %s in class %s", selector, targetclass);
}

// Memory Patching
bool TitanoxHook::ReadMemoryAt(mach_vm_address_t address, void* buffer, mach_vm_size_t size) {
    return vm_read_custom(address, buffer, size);
}
bool TitanoxHook::WriteMemoryAt(mach_vm_address_t address, const void* data, mach_vm_size_t size) {
    return vm_write_custom(address, data, size);
}
void* TitanoxHook::AllocateMemoryWithSize(mach_vm_size_t size, int flags) {
    return vm_allocate_custom(size, flags);
}
bool TitanoxHook::DeallocateMemoryAt(mach_vm_address_t address, mach_vm_size_t size) {
    return vm_deallocate_custom(address, size);
}
kern_return_t TitanoxHook::ProtectMemoryAt(mach_vm_address_t address, mach_vm_size_t size, bool setMax, vm_prot_t newProt) {
    return vm_protect_custom(address, size, setMax, newProt);
}

// mme patch MIGHT need JIT?
void TitanoxHook::PatchMemoryAtAddress(void* address, uint8_t* patch, size_t size) {
    if (!address) {
        Log("Invalid address.");
        return;
    }
    bool res = THPatchMem::PatchMemory(address, patch, size);
    if (res) {
        Log("Memory patch succeeded at address %p", address);
    } else {
        Log("Memory patch failed at address %p", address);
    }
}

// needs symbol, generally useless, not for the user to use. TLDR:ignore
bool TitanoxHook::IsFunctionHooked(const char* symbol, void* original, const char* libName) {
    Dl_info info;
    if (dladdr(original, &info)) {
        std::string libnamestr = libName;
        std::string fulllibpath = FindExecBinary(libnamestr);
        if (strcmp(info.dli_sname, symbol) == 0 && (!libName || fulllibpath == info.dli_fname)) {
            return false; // Not hooked
        }
    }
    return true;
}

// toggle bool by symbol to its opposite current state
void TitanoxHook::HookBoolByName(const char* symbol, const char* libName) {
    std::string libnamestr = libName;
    std::string fulllibpath = FindExecBinary(libnamestr);
    void* openinghandle = dlopen(fulllibpath.c_str(), RTLD_NOW | RTLD_NOLOAD);
    if (!openinghandle) {
        Log("can't open: %s", libName);
        return;
    }
    bool* booladdr = reinterpret_cast<bool*>(dlsym(openinghandle, symbol));
    if (!booladdr) {
        Log("no such symbol: %s", symbol);
        dlclose(openinghandle);
        return;
    }
    if (!IsSafeToPatchMemoryAtAddress(booladdr, sizeof(bool))) {
        Log("can't patch: unsafe memory region.");
        dlclose(openinghandle);
        return;
    }
    *booladdr = !*booladdr; // just toggle state
    Log("toggled bool %s in library %s to %d", symbol, libName, *booladdr);
    dlclose(openinghandle);
}

// this is actually useful to see if you can modify an address/region
bool TitanoxHook::IsSafeToPatchMemoryAtAddress(void* address, size_t length) {
    if (!address || length == 0) {
        Log("ERR: invalid memory address or length.");
        return false;
    }
    vm_address_t regionStart = reinterpret_cast<vm_address_t>(address);
    vm_size_t regionSize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t objectName;
    if (vm_region_64(mach_task_self(), &regionStart, &regionSize, VM_REGION_BASIC_INFO_64, reinterpret_cast<vm_region_info_t>(&info), &infoCount, &objectName) != KERN_SUCCESS) {
        Log("ERR: syscall to region check failed for some reason, maybe we need entitlements...");
        return false;
    }
    return info.protection & VM_PROT_WRITE;
}