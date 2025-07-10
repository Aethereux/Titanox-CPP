#include "libtitanox.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach-o/dyld.h>
#include <string>
#include <objc/runtime.h>
#include <objc/message.h> // Added for Objective-C runtime support
#include <vector>
#include <filesystem>
#include <functional> // For MemXwriteMemory
#include <map>
#include "../fishhook/fishhook.h"
#include "../brk_hook/Hook/hook_wrapper.hpp"
#include "../MemX/MemX.hpp"
#include "../MemX/VMTWrapper.h"
#include "../vm_funcs/vm.hpp"

namespace fs = std::filesystem;

// yet another wrapper
void TitanoxHook::log(const char* format, ...) {
    va_list args;
    va_start(args, format);
    THLog(format, args);
    va_end(args);
}

// Base Address and VM Address Slide
// MemX also have base addr fetch
uint64_t TitanoxHook::getbaseofbinary(const char* lib) {
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const char* dyldName = _dyld_get_image_name(i);
        if (dyldName && strstr(dyldName, lib)) {
            return reinterpret_cast<uint64_t>(_dyld_get_image_header(i));
        }
    }
    return 0;
}

intptr_t TitanoxHook::getvmslideofbinary(const char* lib) {
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const char* dyldName = _dyld_get_image_name(i);
        if (dyldName && strstr(dyldName, lib)) {
            return _dyld_get_image_vmaddr_slide(i);
        }
    }
    return 0;
}

// Breakpoint hook
bool TitanoxHook::addBreakpointAtAddress(void* original, void* hook) {
    if (!original || !hook) {
        log("[ERROR] addBreakpointAtAddress: invalid params. original=%p, hook=%p", original, hook);
        return false;
    }
    void* origarray[] = { original };
    void* hookarray[] = { hook };
    bool res = HookWrapper::callHook(origarray, hookarray, 1);
    if (res) {
        log("[HOOK] Added a breakpoint at address: %p", original);
    } else {
        log("[ERROR] Failed to add breakpoint at address: %p. Maybe your hooks exceeded limits or something else...", original);
    }
    return res;
}

bool TitanoxHook::removeBreakpointAtAddress(void* original) {
    if (!original) {
        log("[ERROR] invalid param. original=%p", original);
        return false;
    }
    void* origarray[] = { original };
    bool res = HookWrapper::callUnHook(origarray, 1);
    if (res) {
        log("[HOOK] Removed breakpoint at address: %p", original);
    } else {
        log("[ERROR] Failed to remove breakpoint at address: %p", original);
    }
    return res;
}

std::string TitanoxHook::findexecbinary(const std::string& libName) {
    std::string bundlePath = fs::path(getBundlePath()).string(); // getBundlePath is in utils.mm
    for (const auto& entry : fs::recursive_directory_iterator(bundlePath)) {
        if (entry.path().filename() == libName) {
            return entry.path().string();
        }
    }
    return "";
}

// MemX Wrappers from eux
uintptr_t TitanoxHook::MemXgetImageBase(const std::string& imageName) {
    return MemX::GetImageBase(imageName.c_str());
}

bool TitanoxHook::MemXisValidPointer(uintptr_t address) {
    return MemX::IsValidPointer(address);
}

bool TitanoxHook::MemXreadMemory(uintptr_t address, void* buffer, size_t len) {
    return MemX::_read(address, buffer, len);
}

std::string TitanoxHook::MemXreadString(uintptr_t address, size_t maxLen) {
    return MemX::ReadString(reinterpret_cast<void*>(address), maxLen);
}

// Refactored MemXwriteMemory (no switch statement)
void TitanoxHook::MemXwriteMemory(uintptr_t address, const std::string& value, const std::string& type) {
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
        log("[MemX] Unknown type: %s", type.c_str());
        return;
    }

    try {
        it->second(address, value); // Call the appropriate MemX::Write<T>
    } catch (const std::exception& e) {
        log("[MemX] Error parsing value: %s", e.what());
    }
}

// ONLY CALL AFTER A MEMX FUNCTION CALL IN READ OR WRITE.
void TitanoxHook::ClearAddrRanges() {
    MemX::ClearAddrRange();
}

// MemX Virtual Function hooking
void* TitanoxHook::vmthookCreateWithNewFunction(void* newFunc, int32_t index) {
    if (!newFunc) {
        log("[ERROR] vmthookCreateWithNewFunction: ERROR - newFunc is NULL");
        return nullptr;
    }
    if (index < 0) {
        log("[ERROR] vmthookCreateWithNewFunction: ERROR - index (%d) is negative", index);
        return nullptr;
    }
    log("[...] vmthookCreateWithNewFunction: Creating hook with newFunc=%p, index=%d", newFunc, index);
    void* makehook = VMTHook_Create(newFunc, index);
    if (!makehook) {
        log("[ERROR] vmthookCreateWithNewFunction: Failed to create hook");
    } else {
        log("[Success] vmthookCreateWithNewFunction: Hook created at %p", makehook);
    }
    return makehook;
}

void TitanoxHook::vmthookSwap(void* hook, void* instance) {
    if (!hook) {
        log("[ERROR] vmthookSwap: ERROR - hook pointer is NULL");
        return;
    }
    if (!instance) {
        log("[ERROR] vmthookSwap: ERROR - instance pointer is NULL");
        return;
    }
    log("[...] vmthookSwap: Swapping hook %p on instance %p", hook, instance);
    VMTHook_Swap(hook, instance);
    log("[Success] vmthookSwap: Swap complete");
}

void TitanoxHook::vmthookReset(void* hook, void* instance) {
    if (!hook) {
        log("[ERROR] vmthookReset: ERROR - hook pointer is NULL");
        return;
    }
    if (!instance) {
        log("[ERROR] vmthookReset: ERROR - instance pointer is NULL");
        return;
    }
    log("[...] vmthookReset: Resetting hook %p on instance %p", hook, instance);
    VMTHook_Reset(hook, instance);
    log("[Success] vmthookReset: Reset complete");
}

void TitanoxHook::vmthookDestroy(void* hook) {
    if (!hook) {
        log("[ERROR] vmthookDestroy: ERROR - hook pointer is NULL");
        return;
    }
    log("[...] vmthookDestroy: Destroying hook %p", hook);
    VMTHook_Destroy(hook);
    log("[Success] vmthookDestroy: Destroy complete");
}

void* TitanoxHook::vmtinvokerCreateWithInstance(void* instance, int32_t index) {
    if (!instance) {
        log("[ERROR] vmtinvokerCreateWithInstance: ERROR - instance pointer is NULL");
        return nullptr;
    }
    if (index < 0) {
        log("[ERROR] vmtinvokerCreateWithInstance: ERROR - index (%d) is negative", index);
        return nullptr;
    }
    log("[...] vmtinvokerCreateWithInstance: Creating invoker for instance %p, index %d", instance, index);
    void* callhookidk = VMTInvoker_Create(instance, index);
    if (!callhookidk) {
        log("[ERROR] vmtinvokerCreateWithInstance: Failed to create invoker");
    } else {
        log("[Success] vmtinvokerCreateWithInstance: Invoker created at %p", callhookidk);
    }
    return callhookidk;
}

void TitanoxHook::vmtinvokerDestroy(void* invoker) {
    if (!invoker) {
        log("[ERROR] vmtinvokerDestroy: ERROR - invoker pointer is NULL");
        return;
    }
    log("[...] vmtinvokerDestroy: Destroying invoker %p", invoker);
    VMTInvoker_Destroy(invoker);
    log("[Success] vmtinvokerDestroy: Destroy complete");
}

// Static Inline Patch
//init
TitanoxHook::TitanoxHook(const std::string& machoName) {
    if (machoName.empty()) {
        log("[ERROR] initWithMachOName: Mach-O name is empty");
        return;
    }
    macho_name_ = machoName;
    hooker_ = std::make_unique<SIH::MachOHooker>(machoName);
    if (!hooker_) {
        log("[ERROR] initWithMachOName: Failed to initialize MachOHooker");
    }
}

// make a patch
std::string TitanoxHook::applyPatchAtVaddr(uint64_t vaddr, const std::string& patchHex) {
    if (!hooker_) return "<hooker not initialized>";
    if (patchHex.empty()) return "<invalid patch>";
    auto result = hooker_->apply_patch(vaddr, patchHex);
    return result.value_or("<no result>");
}

// hook func via va addr
void* TitanoxHook::hookFunctionAtVaddr(uint64_t vaddr, void* replacement) {
    if (!hooker_ || !replacement) return nullptr;
    return hooker_->hook_function(vaddr, replacement);
}

// activate patch AFTER making patch
bool TitanoxHook::activatePatchAtVaddr(uint64_t vaddr, const std::string& patchHex) {
    if (!hooker_ || patchHex.empty()) return false;
    return hooker_->activate_patch(vaddr, patchHex);
}

// deactvate patch AFTER its activated when NEEDED
bool TitanoxHook::deactivatePatchAtVaddr(uint64_t vaddr, const std::string& patchHex) {
    if (!hooker_ || patchHex.empty()) return false;
    return hooker_->deactivate_patch(vaddr, patchHex);
}

// static func hook by symbol i.e fishhook
void TitanoxHook::hookStaticFunction(const char* symbol, void* replacement, const char* libName, void** oldorigfuncptr) {
    std::string libnamestr = libName;
    std::string fulllibpath = findexecbinary(libnamestr);
    void* openinghandle = dlopen(fulllibpath.c_str(), RTLD_NOW | RTLD_NOLOAD);
    if (!openinghandle) {
        log("cant open lib: %s", libName);
        return;
    }
    if (isFunctionHooked(symbol, *oldorigfuncptr, libName)) {
        log("ERR: ptr for func %s is already hooked.", symbol);
        dlclose(openinghandle);
        return;
    }
    struct rebinding rebind;
    rebind.name = symbol;
    rebind.replacement = replacement;
    rebind.replaced = oldorigfuncptr;
    int result = rebind_symbols((struct rebinding[]){rebind}, 1); // fishhook
    if (result != 0) {
        log("ERR:FISHHOOK %d", symbol, result);
    } else {
        log("static hook func is good: %s", symbol);
    }
    dlclose(openinghandle);
}

// swizzle method, objc func hook
void TitanoxHook::swizzleMethod(const char* old_sel, const char* swizzledSelector, const char* targetclass) {
    Class targetClass = objc_getClass(targetclass); // Renamed to avoid conflict
    if (!targetClass) {
        log("Failed to find class: %s", targetclass);
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
void TitanoxHook::overrideMethodInClass(const char* targetclass, const char* selector, void* newFunction, void** oldfunptr) {
    Class target = objc_getClass(targetclass);
    if (!target) {
        log("Failed to find class: %s", targetclass);
        return;
    }
    SEL sel = sel_getUid(selector);
    Method method = class_getInstanceMethod(target, sel); // Fixed: use 'target' instead of 'targetclass'
    if (!method) {
        log("Failed to find method %s in class %s", selector, targetclass);
        return;
    }
    if (oldfunptr) {
        *oldfunptr = reinterpret_cast<void*>(method_getImplementation(method)); // Fixed: cast IMP to void*
    }
    method_setImplementation(method, reinterpret_cast<IMP>(newFunction));
    log("hooked %s in class %s", selector, targetclass);
}

// Memory Patching
bool TitanoxHook::readMemoryAt(mach_vm_address_t address, void* buffer, mach_vm_size_t size) {
    return vm_read_custom(address, buffer, size);
}
bool TitanoxHook::writeMemoryAt(mach_vm_address_t address, const void* data, mach_vm_size_t size) {
    return vm_write_custom(address, data, size);
}
void* TitanoxHook::allocateMemoryWithSize(mach_vm_size_t size, int flags) {
    return vm_allocate_custom(size, flags);
}
bool TitanoxHook::deallocateMemoryAt(mach_vm_address_t address, mach_vm_size_t size) {
    return vm_deallocate_custom(address, size);
}
kern_return_t TitanoxHook::protectMemoryAt(mach_vm_address_t address, mach_vm_size_t size, bool setMax, vm_prot_t newProt) {
    return vm_protect_custom(address, size, setMax, newProt);
}

// mme patch MIGHT need JIT?
void TitanoxHook::patchMemoryAtAddress(void* address, uint8_t* patch, size_t size) {
    if (!address) {
        log("Invalid address.");
        return;
    }
    bool res = THPatchMem::PatchMemory(address, patch, size);
    if (res) {
        log("Memory patch succeeded at address %p", address);
    } else {
        log("Memory patch failed at address %p", address);
    }
}

// needs symbol, generally useless, not for the user to use. TLDR:ignore
bool TitanoxHook::isFunctionHooked(const char* symbol, void* original, const char* libName) {
    Dl_info info;
    if (dladdr(original, &info)) {
        std::string libnamestr = libName;
        std::string fulllibpath = findexecbinary(libnamestr);
        if (strcmp(info.dli_sname, symbol) == 0 && (!libName || fulllibpath == info.dli_fname)) {
            return false; // Not hooked
        }
    }
    return true;
}

// toggle bool by symbol to its opposite current state
void TitanoxHook::hookBoolByName(const char* symbol, const char* libName) {
    std::string libnamestr = libName;
    std::string fulllibpath = findexecbinary(libnamestr);
    void* openinghandle = dlopen(fulllibpath.c_str(), RTLD_NOW | RTLD_NOLOAD);
    if (!openinghandle) {
        log("can't open: %s", libName);
        return;
    }
    bool* booladdr = reinterpret_cast<bool*>(dlsym(openinghandle, symbol));
    if (!booladdr) {
        log("no such symbol: %s", symbol);
        dlclose(openinghandle);
        return;
    }
    if (!isSafeToPatchMemoryAtAddress(booladdr, sizeof(bool))) {
        log("can't patch: unsafe memory region.");
        dlclose(openinghandle);
        return;
    }
    *booladdr = !*booladdr; // just toggle state
    log("toggled bool %s in library %s to %d", symbol, libName, *booladdr);
    dlclose(openinghandle);
}

// this is actually useful to see if you can modify an address/region
bool TitanoxHook::isSafeToPatchMemoryAtAddress(void* address, size_t length) {
    if (!address || length == 0) {
        log("ERR: invalid memory address or length.");
        return false;
    }
    vm_address_t regionStart = reinterpret_cast<vm_address_t>(address);
    vm_size_t regionSize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t objectName;
    if (vm_region_64(mach_task_self(), &regionStart, &regionSize, VM_REGION_BASIC_INFO_64, reinterpret_cast<vm_region_info_t>(&info), &infoCount, &objectName) != KERN_SUCCESS) {
        log("ERR: syscall to region check failed for some reason, maybe we need entitlements...");
        return false;
    }
    return info.protection & VM_PROT_WRITE;
}