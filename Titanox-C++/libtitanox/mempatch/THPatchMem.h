#pragma once

#include <cstddef>
#include <cstdint>
#include <unistd.h>

static const size_t PG_SIZE = static_cast<size_t>(getpagesize());

constexpr const char* VM_WRITE_ERROR_MSG    = "[THPatchMem] vm_write failed: %s";
constexpr const char* VM_PROTECT_ERROR_MSG  = "[THPatchMem] vm_protect change failed: %s";
constexpr const char* VM_PROTECT_RESTORE_ERROR_MSG  = "[THPatchMem] vm_protect restore failed: %s";
constexpr const char* MEMCPY_ERROR_MSG      = "[THPatchMem] memcpy failed, fallback to vm_write";

class THPatchMem {
public:
    static bool PatchMemory(void* address, uint8_t* buffer, size_t bufferSize);
    static bool MemcpyAndValidate(void* address, const uint8_t* buffer, size_t bufferSize);
    static bool WriteWithVMWrite(void* address, const uint8_t* buffer, size_t bufferSize);
    static bool MemPatchR(void* address, uint8_t* buffer, size_t bufferSize);
};
