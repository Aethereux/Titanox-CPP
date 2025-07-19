#include "THPatchMem.h"
#include "../Utils/utils.h"

#include <mach/mach.h>
#include <memory>
#include <cstring>
#include <sys/mman.h>
#include <mach/error.h>

bool THPatchMem::MemcpyAndValidate(void* address, const uint8_t* buffer, size_t bufferSize) {
    std::unique_ptr<uint8_t[]> bufferCopy(new uint8_t[bufferSize]);
    std::memcpy(bufferCopy.get(), buffer, bufferSize);
    return std::memcmp(address, bufferCopy.get(), bufferSize) == 0;
}

bool THPatchMem::WriteWithVMWrite(void* address, const uint8_t* buffer, size_t bufferSize) {
    std::unique_ptr<uint8_t[]> bufferCopy(new uint8_t[bufferSize]);
    std::memcpy(bufferCopy.get(), buffer, bufferSize);

    kern_return_t kr = vm_write(mach_task_self(),
                                reinterpret_cast<vm_address_t>(address),
                                reinterpret_cast<vm_address_t>(bufferCopy.get()),
                                static_cast<mach_msg_type_number_t>(bufferSize));
    if (kr != KERN_SUCCESS) {
        THLog(VM_WRITE_ERROR_MSG, mach_error_string(kr));
        return false;
    }
    return true;
}

bool THPatchMem::MemPatchR(void* address, uint8_t* buffer, size_t bufferSize) {
    if (!address || !buffer || bufferSize == 0) {
        return false;
    }

    std::unique_ptr<uint8_t[]> bufferCopy(new uint8_t[bufferSize]);
    std::memcpy(bufferCopy.get(), buffer, bufferSize);

    vm_size_t pageSize = PG_SIZE;
    uintptr_t pageStart = reinterpret_cast<uintptr_t>(address) & ~(pageSize - 1);
    size_t pageOffset = reinterpret_cast<uintptr_t>(address) - pageStart;

    mach_port_t selfTask = mach_task_self();
    kern_return_t kr;

    kr = vm_protect(selfTask, pageStart, pageSize, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        THLog(VM_PROTECT_ERROR_MSG, mach_error_string(kr));
        return false;
    }

    if (!MemcpyAndValidate(reinterpret_cast<void*>(pageStart + pageOffset), bufferCopy.get(), bufferSize)) {
        if (!WriteWithVMWrite(reinterpret_cast<void*>(pageStart + pageOffset), bufferCopy.get(), bufferSize)) {
            THLog("%s", MEMCPY_ERROR_MSG);
            return false;
        }
    }

    kr = vm_protect(selfTask, pageStart, pageSize, false, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        THLog(VM_PROTECT_RESTORE_ERROR_MSG, mach_error_string(kr));
        return false;
    }

    return true;
}

bool THPatchMem::PatchMemory(void* address, uint8_t* buffer, size_t bufferSize) {
    if (!address || !buffer || bufferSize == 0) {
        return false;
    }
    return MemPatchR(address, buffer, bufferSize);
}
