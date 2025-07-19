/*
so painful to port this to C++...
*/

#pragma once

#include <cstdint>
#include <string>
#include <memory>
#include <vector>
#include <optional>
#include <mach-o/loader.h>

namespace SIH {
struct HookBlock {
    uint64_t hook_vaddr{0};
    uint64_t original_vaddr{0};
    uint64_t patched_vaddr{0};
    uint64_t code_vaddr{0};
    uint64_t code_size{0};
    uint64_t patch_size{0};
    uint64_t patch_hash{0};
    void* target_replace{nullptr};
};
class MachOHooker {
public:
    explicit MachOHooker(const std::string& macho_name);
    ~MachOHooker() = default;
    std::optional<std::string> ApplyPatch(uint64_t vaddr, const std::string& patch_bytes);
    void* HookFunction(uint64_t vaddr, void* replacement);
    bool ActivatePatch(uint64_t vaddr, const std::string& patch_bytes);
    bool DeactivatePatch(uint64_t vaddr, const std::string& patch_bytes);
private:
    static constexpr size_t CODE_PAGE_SIZE = 4096;
    static constexpr size_t DATA_PAGE_SIZE = 4096;
    static constexpr const char* HOOK_TEXT_SEGMENT = "__TITANOX_HOOK";
    static constexpr const char* HOOK_DATA_SEGMENT = "__TITANOX_HOOK";
    static constexpr const char* HOOK_TEXT_SECTION = "__titanox_text";
    static constexpr const char* HOOK_DATA_SECTION = "__titanox_data";
    std::string macho_name_;
    std::vector<uint8_t> macho_data_;  // replaces NSMutableData
    mach_header_64* header_{nullptr};
    segment_command_64* text_segment_{nullptr};
    segment_command_64* data_segment_{nullptr};
    uint32_t cryptid_{0};
    struct MachOInfo {
        uint64_t vm_end{0};
        uint64_t min_section_offset{0};
        segment_command_64* linkedit_seg{nullptr};
    };
    bool LoadMachoData();
    bool ValidateMacho();
    bool AddHookSections();
    bool UpdateLinkeditCommands(uint64_t offset);
    bool SavePatchedBinary();
    bool ApplyInlinePatch(HookBlock* block, uint64_t func_rva, void* func_data, uint64_t target_rva, void* target_data, const std::string& patch_bytes);
    static bool HexToBytes(const std::string& hex, std::vector<uint8_t>& buffer);
    std::optional<MachOInfo> ParseMachoInfo();
    uint64_t VaToRva(uint64_t va) const;
    static uint64_t CalculatePatchHash(uint64_t vaddr, const std::string& patch);
    void* RvaToData(uint64_t rva) const;
    void* FindModuleBase() const;
    HookBlock* FindHookBlock(void* base, uint64_t vaddr) const;
};

}
