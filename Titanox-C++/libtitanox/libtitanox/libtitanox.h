#include <string>
#include <vector>
#include <memory>
#include <cstdarg>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <dlfcn.h>
#include "../Fishhook/fishhook.h"
#include "../Mempatch/THPatchMem.h"
#include "../BreakpointHook/Hook/hook_wrapper.hpp"
#include "../Utils/utils.h"
#include "../MemX/MemX.hpp"
#include "../MemX/VMTWrapper.h"
#include "../Static-Inline-Hook/sih.hpp"
#include "../VM_Funcs/vm.hpp"

class TitanoxHook {
private:
    std::string macho_name_;
    std::unique_ptr<SIH::MachOHooker> hooker_;

public:
    // custom vm funcs (auto bypasses processes hooking and logging them)
    static void PatchMemoryAtAddress(void* address, uint8_t* patch, size_t size);
    static bool ReadMemoryAt(mach_vm_address_t address, void* buffer, mach_vm_size_t size);
    static bool WriteMemoryAt(mach_vm_address_t address, const void* data, mach_vm_size_t size);
    static void* AllocateMemoryWithSize(mach_vm_size_t size, int flags);
    static bool DeallocateMemoryAt(mach_vm_address_t address, mach_vm_size_t size);
    static kern_return_t ProtectMemoryAt(mach_vm_address_t address, mach_vm_size_t size, bool setMax, vm_prot_t newProt);

    // Hooking & swizzling (set & exchange impl)
    static void HookStaticFunction(const char* symbol, void* replacement, const char* libName, void** oldFunction);
    static void SwizzleMethod(const char* originalSelector, const char* swizzledSelector, const char* targetClassName);
    static void OverrideMethodInClass(const char* targetClassName, const char* selector, void* newFunction, void** oldFunctionPointer);
    static bool IsFunctionHooked(const char* symbol, void* original, const char* libName);
    static void HookBoolByName(const char* symbol, const char* libName);

    // brk hook & unhook, max is 6, partial debugger support (is borked)
    static bool AddBreakpointAtAddress(void* original, void* hook);
    static bool RemoveBreakpointAtAddress(void* original);

    // basic stuff
    static uint64_t GetBaseOfBinary(const char* libName);
    static intptr_t GetVmSlideOfBinary(const char* libName);
    static std::string FindExecBinary(const std::string& libName);

    // THLog wrapper
    static void Log(const char* format, ...);

    // MemX Wrappers, might aswell use them directly
    static uintptr_t GetImageBase(const std::string& imageName);
    static bool IsValidPointer(uintptr_t address);
    static void ClearAddrRanges();
    static bool ReadMemory(uintptr_t address, void* buffer, size_t len);
    static std::string ReadString(uintptr_t address, size_t maxLen);
    static void WriteMemory(uintptr_t address, const std::string& value, const std::string& type);

    // VMT Hook Wrappers, also MemX
    static void* VMTHookCreateWithNewFunction(void* newFunc, int32_t index);
    static void VMTHookSwap(void* hook, void* instance);
    static void VMTHookReset(void* hook, void* instance);
    static void VMTHookDestroy(void* hook);
    static void* VMTInvokerCreateWithInstance(void* instance, int32_t index);
    static void VMTInvokerDestroy(void* invoker);

    // Static Inline Hook and Patch, need to replace whole target
    TitanoxHook(const std::string& machoName);
    std::string ApplyPatchAtVaddr(uint64_t vaddr, const std::string& patchHex);
    void* HookFunctionAtVaddr(uint64_t vaddr, void* replacement);
    bool ActivatePatchAtVaddr(uint64_t vaddr, const std::string& patchHex);
    bool DeactivatePatchAtVaddr(uint64_t vaddr, const std::string& patchHex);

    // actually useful
    static bool IsSafeToPatchMemoryAtAddress(void* address, size_t length);
};