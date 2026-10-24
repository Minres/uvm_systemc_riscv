#pragma once

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace components {
enum class field_type { IMM, SRC, DST, SRC_DST };

struct bit_range {
    unsigned msb{0};
    unsigned lsb{std::numeric_limits<unsigned>::max()};
};

struct bit_field_desc {
    std::string name;
    bit_range instr;
    bit_range field;
    unsigned width = 0;
    unsigned index = std::numeric_limits<unsigned>::max();
    unsigned total_size = 0;
    bool is_constant = false;
    field_type type = field_type::IMM;
};

struct instruction_desc {
    std::string isa_subset;
    std::string mnemonic;
    uint32_t index = 0;
    unsigned size = 0;
    uint32_t pattern = 0;
    uint32_t mask = 0;
    bool branch = false;
    std::vector<bit_field_desc> bitfields;
    std::unordered_map<std::string, bit_range> bitfield_sizes;
};

struct instruction_pattern {
    uint32_t value;
    uint32_t mask;
    unsigned id;
    unsigned length;
};

inline uint32_t extract_bits(uint32_t value, unsigned lsb, unsigned width) {
    if(width == 0 || width > 32 || lsb >= 32 || lsb + width > 32)
        throw std::out_of_range("invalid bit extraction");
    if(width == 32)
        return value;
    return (value >> lsb) & ((uint32_t{1} << width) - 1);
}

std::tuple<std::vector<instruction_desc>, std::array<std::vector<instruction_pattern>, 4>> parse_isa_yaml(std::string isa_file);
} // namespace components
