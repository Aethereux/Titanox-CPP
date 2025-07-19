#pragma once

#include "vm.h"
#include <mach/mach.h>

inline bool vm_read_custom(mach_vm_address_t address, void *buffer, mach_vm_size_t size) {
    return TotallyNotVM::Read(address, buffer, size) == KERN_SUCCESS;
}

inline bool vm_write_custom(mach_vm_address_t address, const void *data, mach_vm_size_t size) {
    return TotallyNotVM::Write(address, data, size) == KERN_SUCCESS;
}

inline void* vm_allocate_custom(mach_vm_size_t size, int flags) {
    mach_vm_address_t address = 0;
    return (TotallyNotVM::Allocate(&address, size, flags) == KERN_SUCCESS) ? (void*)address : nullptr;
}

inline bool vm_deallocate_custom(mach_vm_address_t address, mach_vm_size_t size) {
    return TotallyNotVM::Deallocate(address, size) == KERN_SUCCESS;
}

inline kern_return_t vm_protect_custom(mach_vm_address_t address, mach_vm_size_t size, boolean_t set_max, vm_prot_t new_prot) {
    return TotallyNotVM::Protect(address, size, set_max, new_prot);
}

