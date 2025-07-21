// https://github.com/Aethereux/MemX
#pragma once

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>
#include <utility>
#include <unistd.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/mman.h>
#include <mutex>
#include <setjmp.h>

namespace MemX {

    inline uintptr_t GetImageBase(const std::string& imageName) {
        for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
            const char* imgName = _dyld_get_image_name(i);
            if (imgName && strstr(imgName, imageName.c_str())) {
                return reinterpret_cast<uintptr_t>(_dyld_get_image_header(i));
            }
        }
        return 0;
    }
    /*
    You Could use this if you want to check if a pointer is valid in a more robust way (recommended for games that doesn't detect mach api calls)
    inline bool IsValidPointer(uintptr_t Address) {
        uint8_t Data = 0;
        size_t Size = 0;
        int KR = vm_read_overwrite(mach_task_self(), (vm_address_t)Address, 1, (vm_address_t)&Data, &Size);
        return !(KR == KERN_INVALID_ADDRESS || KR == KERN_MEMORY_FAILURE || KR == KERN_MEMORY_ERROR);
    }
    */

    static std::mutex sigsegv_mutex; // Mutex to protect global sigaction from races
    static thread_local sigjmp_buf thread_jump_buffer; // Thread-local jump buffer (isolated per thread)
    // SIGSEGV handler - long jumps to thread-local buffer
    static void sigsegv_handler(int) { 
        siglongjmp(thread_jump_buffer, 1);
    }

    // Checks if an address is in a valid memory region
    // Uses a signal handler to catch segmentation faults
    // Returns true if the address is valid, false otherwise
    inline bool IsValidPointer(uintptr_t address) {
        std::lock_guard<std::mutex> lock(sigsegv_mutex);

        struct sigaction sa{}, old_sa{};
        sa.sa_handler = sigsegv_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;

        if (sigaction(SIGSEGV, &sa, &old_sa) != 0)
            return false;

        bool result = false;

        if (sigsetjmp(thread_jump_buffer, 1) == 0) {
            // only checking if access causes a fault
            *(volatile uintptr_t*)address;
            result = true;
        }

        sigaction(SIGSEGV, &old_sa, nullptr);
        return result;
    }


    inline bool _read(uintptr_t addr, void* buffer, size_t len) {
        return IsValidPointer(addr) && (std::memcpy(buffer, reinterpret_cast<void*>(addr), len), true);
    }

    template <typename T>
    inline T Read(uintptr_t address) {
        T data{};
        _read(address, &data, sizeof(T));
        return data;
    }

    inline std::string ReadString(void* address, size_t max_len) {
        if (!IsValidPointer(reinterpret_cast<uintptr_t>(address))) return "Invalid Pointer!!";
        std::vector<char> chars(max_len + 1, '\0');
        if (_read(reinterpret_cast<uintptr_t>(address), chars.data(), max_len)) {
            return std::string(chars.data(), strnlen(chars.data(), max_len));
        }
        return "";
    }

    template <typename T>
    inline void Write(uintptr_t address, const T& value) {
        if (IsValidPointer(address)) *reinterpret_cast<T*>(address) = value;
    }
}
