#include "yaml_instruction_parser.h"
#include <fstream>
#include <regex>
#include <util/ities.h>
#include <vector>
#include <yaml-cpp/yaml.h>

namespace components {
namespace {

unsigned checked_stoul(const std::string& value) {
    const auto parsed = std::stoul(value);
    if(parsed > std::numeric_limits<unsigned>::max())
        throw std::out_of_range("numeric value too large: " + value);
    return static_cast<unsigned>(parsed);
}

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if(first == std::string::npos)
        return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

uint32_t parse_binary_u32(std::string value) {
    value = trim(std::move(value));
    if(value.size() < 3 || value[0] != '0' || (value[1] != 'b' && value[1] != 'B'))
        throw std::runtime_error("expected binary literal with 0b prefix: " + value);
    if(value.size() > 34)
        throw std::out_of_range("binary literal is wider than 32 bits: " + value);

    uint32_t result = 0;
    for(std::size_t idx = 2; idx < value.size(); ++idx) {
        const char bit = value[idx];
        if(bit != '0' && bit != '1')
            throw std::runtime_error("invalid binary digit in literal: " + value);
        result = static_cast<uint32_t>((result << 1) | (bit - '0'));
    }
    return result;
}

bit_field_desc parse_bitfield_spec(std::string spec) {
    spec = trim(std::move(spec));

    static const std::regex named_re(R"(^([A-Za-z_][A-Za-z0-9_]*)\[(\d+):(\d+)\]$)");
    static const std::regex const_re(R"(^(\d+)'b([01]+)$)");
    std::smatch match;

    if(std::regex_match(spec, match, named_re)) {
        bit_field_desc field;
        field.name = match[1].str();
        field.field.msb = checked_stoul(match[2].str());
        field.field.lsb = checked_stoul(match[3].str());
        if(field.field.msb < field.field.lsb)
            throw std::runtime_error("invalid descending bit slice: " + spec);
        field.width = field.field.msb - field.field.lsb + 1;
        return field;
    }

    if(std::regex_match(spec, match, const_re)) {
        bit_field_desc field;
        field.is_constant = true;
        field.width = checked_stoul(match[1].str());
        if(field.width == 0 || field.width > 32)
            throw std::runtime_error("unsupported constant width in: " + spec);
        const auto bits = match[2].str();
        if(bits.size() > field.width)
            throw std::runtime_error("constant value is wider than its declared field: " + spec);
        field.field.msb = field.width - 1;
        field.field.lsb = 0;
        return field;
    }

    throw std::runtime_error("unsupported bitfield spec: " + spec);
}

std::vector<bit_field_desc> parse_bitfields(const YAML::Node& nodes, unsigned instr_size, const std::string& mnemonic) {
    if(!nodes || !nodes.IsSequence())
        throw std::runtime_error("instruction " + mnemonic + " has no bitfields sequence");

    std::vector<bit_field_desc> fields;
    unsigned next_lsb = instr_size;

    for(const auto& node : nodes) {
        auto field = parse_bitfield_spec(node.as<std::string>());
        if(field.width > next_lsb)
            throw std::runtime_error("bitfields of " + mnemonic + " exceed instruction size");
        field.instr.msb = next_lsb - 1;
        field.instr.lsb = next_lsb - field.width;
        next_lsb -= field.width;
        if(!field.is_constant) {
            if(field.name == "rsd")
                field.type = field_type::SRC_DST;
            else {
                auto prefix = field.name.substr(0, 2);
                if(prefix == "rs")
                    field.type = field_type::SRC;
                else if(prefix == "rd")
                    field.type = field_type::DST;
            }
            fields.push_back(std::move(field));
        }
    }

    if(next_lsb != 0)
        throw std::runtime_error("bitfields of " + mnemonic + " cover only " + std::to_string(instr_size - next_lsb) + " of " +
                                 std::to_string(instr_size) + " bits");

    return fields;
}
} // namespace

std::tuple<std::vector<instruction_desc>, std::array<std::vector<instruction_pattern>, 4>> parse_isa_yaml(std::string isa_file) {
    std::array<std::vector<instruction_pattern>, 4> qlut;
    std::vector<instruction_desc> instr_desc;
    std::ifstream input(isa_file);
    if(!input.is_open())
        throw std::runtime_error("could not open YAML file: " + isa_file);
    const auto roots = YAML::LoadAll(input);
    if(roots.size() != 1)
        throw std::runtime_error("expected exactly one YAML document in: " + isa_file);

    for(const auto& subset_node : roots[0]) {
        const auto isa_subset = subset_node.first.as<std::string>();
        const auto instructions = subset_node.second;
        for(const auto& instr_node : instructions) {
            instruction_desc desc;
            desc.isa_subset = isa_subset;
            desc.mnemonic = instr_node.first.as<std::string>();
            desc.index = instr_node.second["index"].as<uint32_t>();
            desc.size = instr_node.second["size"].as<unsigned>();
            desc.pattern = parse_binary_u32(instr_node.second["encoding"].as<std::string>());
            desc.mask = parse_binary_u32(instr_node.second["mask"].as<std::string>());
            desc.branch = instr_node.second["branch"].as<bool>();
            desc.bitfields = parse_bitfields(instr_node.second["bitfields"], desc.size, desc.mnemonic);
            auto& bf_sizes = desc.bitfield_sizes;
            for(auto const& b : desc.bitfields) {
                auto& bf_size = bf_sizes[b.name];
                bf_size.msb = std::max(bf_size.msb, b.field.msb);
                bf_size.lsb = std::min(bf_size.lsb, b.field.lsb);
            }
            instr_desc.push_back(std::move(desc));
            instruction_pattern inst{parse_binary_u32(instr_node.second["encoding"].as<std::string>()),
                                     parse_binary_u32(instr_node.second["mask"].as<std::string>()), desc.index, desc.size};
            qlut[inst.value & 0x3].push_back(std::move(inst));
        }
    }
    std::sort(std::begin(instr_desc), std::end(instr_desc),
              [](instruction_desc const& a, instruction_desc const& b) { return a.index < b.index; });
    for(auto& lut : qlut) {
        std::sort(std::begin(lut), std::end(lut), [](instruction_pattern const& a, instruction_pattern const& b) {
            return util::bit_count(a.mask) > util::bit_count(b.mask);
        });
    }
    return {instr_desc, qlut};
}
} // namespace components
