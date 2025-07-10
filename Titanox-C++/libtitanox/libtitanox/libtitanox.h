#include <string>
#include <vector>
#include <memory>
#include <cstdarg>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <dlfcn.h>
#include "../fishhook/fishhook.h"
#include "../mempatch/THPatchMem.h"
#include "../brk_hook/Hook/hook_wrapper.hpp"
#include "../utils/utils.h"
#include "../MemX/MemX.hpp"
#include "../MemX/VMTWrapper.h"
#include "../static-inline-hook/sih.hpp"

class TitanoxHook {
private:
    std::string macho_name_;
    std::unique_ptr<SIH::MachOHooker> hooker_;

public:
    // custom vm funcs (auto bypasses processes hooking and logging them)
    static void patchMemoryAtAddress(void* address, uint8_t* patch, size_t size);
    static bool readMemoryAt(mach_vm_address_t address, void* buffer, mach_vm_size_t size);
    static bool writeMemoryAt(mach_vm_address_t address, const void* data, mach_vm_size_t size);
    static void* allocateMemoryWithSize(mach_vm_size_t size, int flags);
    static bool deallocateMemoryAt(mach_vm_address_t address, mach_vm_size_t size);
    static kern_return_t protectMemoryAt(mach_vm_address_t address, mach_vm_size_t size, bool setMax, vm_prot_t newProt);

    // Hooking & swizzling (set & exchange impl)
    static void hookStaticFunction(const char* symbol, void* replacement, const char* libName, void** oldFunction);
    static void swizzleMethod(const char* originalSelector, const char* swizzledSelector, const char* targetClassName);
    static void overrideMethodInClass(const char* targetClassName, const char* selector, void* newFunction, void** oldFunctionPointer);
    static bool isFunctionHooked(const char* symbol, void* original, const char* libName);
    static void hookBoolByName(const char* symbol, const char* libName);

    // brk hook & unhook, max is 6, partial debugger support (is borked)
    static bool addBreakpointAtAddress(void* original, void* hook);
    static bool removeBreakpointAtAddress(void* original);

    // basic stuff
    static uint64_t getbaseofbinary(const char* libName);
    static intptr_t getvmslideofbinary(const char* libName);
    static std::string findexecbinary(const std::string& libName);

    // THLog wrapper
    static void log(const char* format, ...);

    // MemX Wrappers, might aswell use them directly
    static uintptr_t MemXgetImageBase(const std::string& imageName);
    static bool MemXisValidPointer(uintptr_t address);
    static void ClearAddrRanges();
    static bool MemXreadMemory(uintptr_t address, void* buffer, size_t len);
    static std::string MemXreadString(uintptr_t address, size_t maxLen);
    static void MemXwriteMemory(uintptr_t address, const std::string& value, const std::string& type);

    // VMT Hook Wrappers, also MemX
    static void* vmthookCreateWithNewFunction(void* newFunc, int32_t index);
    static void vmthookSwap(void* hook, void* instance);
    static void vmthookReset(void* hook, void* instance);
    static void vmthookDestroy(void* hook);
    static void* vmtinvokerCreateWithInstance(void* instance, int32_t index);
    static void vmtinvokerDestroy(void* invoker);

    // Static Inline Hook and Patch, need to replace whole target
    TitanoxHook(const std::string& machoName);
    std::string applyPatchAtVaddr(uint64_t vaddr, const std::string& patchHex);
    void* hookFunctionAtVaddr(uint64_t vaddr, void* replacement);
    bool activatePatchAtVaddr(uint64_t vaddr, const std::string& patchHex);
    bool deactivatePatchAtVaddr(uint64_t vaddr, const std::string& patchHex);

    // actually useful
    static bool isSafeToPatchMemoryAtAddress(void* address, size_t length);
};