#include "components/yaml_instruction_parser.h"
#include <algorithm>
#include <csr.h>
#include <functional>
#include <instr.h>
#include <instr_encoding.h>
#include <scc/report.h>
#include <seq/instr_gen.h>
#include <stdint.h>
#include <unordered_set>
#include <vector>

namespace seq {

#define RO_CSR_MASK 0xC00
std::unordered_set<std::string> skip_instructions = {"WFI"};
std::unordered_set<std::string> branching_instructions = {"MRET", "SRET", "URET", "ECALL", "EBREAK", "C:EBREAK"};

instr_gen::instr_gen(std::string const& nm)
: name(nm) {}

void instr_gen::initialize(std::string const& isa_file) {
    std::vector<components::instruction_desc> instr_desc;
    std::tie(instr_desc, qlut) = components::parse_isa_yaml(isa_file);
    for(auto const& desc : instr_desc) {
        if(skip_instructions.count(desc.mnemonic))
            continue;
        auto constaint_index = generate_field_constraints(desc);
        all_instruction_index.push_back(constaint_index);
        if(!desc.branch && branching_instructions.count(desc.mnemonic) == 0)
            linear_instruction_index.push_back(constaint_index);
    }
    linear_idx_gen(dist(linear_idx(), distribution<uint8_t>::simple_range(0, linear_instruction_index.size() - 1)));
    all_idx_gen(dist(all_idx(), distribution<uint8_t>::simple_range(0, all_instruction_index.size() - 1)));
}

template <typename T> size_t instr_gen::generate_imm_constraint(std::string const& name, components::bit_range bf_sz) {
    auto& ic = constraints.back();
    ic.field_rand_vars.emplace_back<randv<T>>(nullptr);
    auto& rnd = std::get<randv<T>>(ic.field_rand_vars.back());
    ic.field_rand_gen.emplace_back();
    auto& constr = ic.field_rand_gen.back();
    constr(name, dist(rnd(), distribution<T>::simple_range(0, (1ull << (bf_sz.msb + 1)) - 1)));
    return ic.field_rand_vars.size() - 1;
}

template <> size_t instr_gen::generate_imm_constraint<bool>(std::string const& name, components::bit_range bf_sz) {
    auto& ic = constraints.back();
    ic.field_rand_vars.emplace_back<randv<bool>>(nullptr);
    auto& rnd = std::get<randv<bool>>(ic.field_rand_vars.back());
    ic.field_rand_gen.emplace_back();
    auto& constr = ic.field_rand_gen.back();
    constr(name, dist(rnd(), distribution<bool>::create(0.5)));
    return ic.field_rand_vars.size() - 1;
}

size_t instr_gen::generate_reg_constraint(std::string const& name, components::bit_range bf_sz) {
    auto& ic = constraints.back();
    ic.field_rand_vars.emplace_back<randv<uint8_t>>(nullptr);
    auto& rnd = std::get<randv<uint8_t>>(ic.field_rand_vars.back());
    ic.field_rand_gen.emplace_back();
    auto& constr = ic.field_rand_gen.back();
    auto field_size = bf_sz.msb - bf_sz.lsb + 1;
    auto max_value = (1u << field_size) - 1;
    constr(name, dist(rnd(), distribution<uint8_t>::simple_range(0, max_value << bf_sz.lsb)));
    return ic.field_rand_vars.size() - 1;
}

struct random_value_reader {
    uint64_t operator()(randv<uint64_t> const& random_value) const {
        uint64_t res = random_value;
        return res;
    }
    uint64_t operator()(randv<uint32_t> const& random_value) const {
        uint32_t res = random_value;
        return res;
    }
    uint64_t operator()(randv<uint16_t> const& random_value) const {
        uint16_t res = random_value;
        return res;
    }
    uint64_t operator()(randv<uint8_t> const& random_value) const {
        uint8_t res = random_value;
        return res;
    }
    uint64_t operator()(randv<bool> const& random_value) const {
        bool res = random_value;
        return res ? 1 : 0;
    }
};

struct instruction_field_mapper {
    components::bit_range source_range;
    components::bit_range target_range;
    rand_var& value;

    uint32_t operator()(uint32_t target_data) {
        const unsigned target_width = target_range.msb - target_range.lsb + 1;
        const uint32_t field_mask =
            target_width == sizeof(uint32_t) * 8 ? ~uint32_t{0} : ((uint32_t{1} << target_width) - 1) << target_range.lsb;
        const unsigned source_width = source_range.msb - source_range.lsb + 1;
        const uint32_t mask = source_width == sizeof(uint32_t) * 8 ? ~uint32_t{0} : (uint32_t{1} << source_width) - 1;
        const uint64_t insert_value = std::visit(random_value_reader{}, value);
        const uint32_t extracted = (insert_value >> source_range.lsb) & mask;
        return (target_data & ~field_mask) | (extracted << target_range.lsb);
    }
};

size_t instr_gen::generate_field_constraints(components::instruction_desc desc) {
    std::unordered_map<std::string, size_t> bf_name2idx;
    auto index = constraints.size();
    constraints.emplace_back(std::move(desc));
    auto& ic = constraints.back();
    if(auto num_bf = desc.bitfield_sizes.size()) {
        ic.field_rand_gen.reserve(num_bf);
        ic.field_rand_vars.reserve(num_bf);
        for(auto b : desc.bitfield_sizes) {
            auto& name = b.first;
            auto start = name.substr(0, 2);
            auto& bf_sz = b.second;
            if(start == "rd" || start == "rs") {
                bf_name2idx[name] = generate_reg_constraint(name, bf_sz); // this is for registers
            } else if(bf_sz.msb > 31) {
                bf_name2idx[name] = generate_imm_constraint<uint64_t>(name, bf_sz);
            } else if(bf_sz.msb > 15) {
                bf_name2idx[name] = generate_imm_constraint<uint32_t>(name, bf_sz);
            } else if(bf_sz.msb > 7) {
                bf_name2idx[name] = generate_imm_constraint<uint16_t>(name, bf_sz);
            } else if(bf_sz.msb == 0) {
                bf_name2idx[name] = generate_imm_constraint<bool>(name, bf_sz);
            } else {
                bf_name2idx[name] = generate_imm_constraint<uint8_t>(name, bf_sz);
            }
        }
    }
    unsigned imm_index = std::numeric_limits<unsigned>::max();
    std::string imm_name;
    for(auto const& bf : desc.bitfields) {
        auto source_range = bf.field;
        auto target_range = bf.instr;
        auto idx = bf_name2idx[bf.name];
        ic.mapper.push_back(std::move(
            instruction_field_mapper{.source_range = source_range, .target_range = target_range, .value = ic.field_rand_vars[idx]}));
    }
    return index;
}

void instr_gen::add_csr_to_ignore(unsigned short addr) { unsupported_csrs.insert(addr); }

bool instr_gen::is_unsupported(uint32_t x) {
    auto it = std::find_if(std::begin(disabled_instr), std::end(disabled_instr),
                           [x](std::pair<uint32_t, uint32_t> const& p) { return (x & p.first) == (p.second); });
    if(it != std::end(disabled_instr))
        return true;

    Instruction i(x);
    bool is_csr = ((x & CSRRW_MASK) == CSRRW_ENCODING)|| ((x & CSRRS_MASK) == CSRRS_ENCODING)||((x & CSRRC_MASK) == CSRRC_ENCODING)||
            ((x & CSRRWI_MASK) == CSRRWI_ENCODING)||((x & CSRRSI_MASK) == CSRRSI_ENCODING)||((x & CSRRCI_MASK) == CSRRCI_ENCODING);


    if(is_csr) {
        auto csr = bit_sub<20, 12>(x);
        if(unsupported_csrs.find(csr) != unsupported_csrs.end())
            return true;
        if(volatile_csrs.find(csr) != volatile_csrs.end())
            // NOTE: time and cycles will differ on ISS and RTL core, so only access cycles if result is dropped
            return i.rd() != 0;
    }
    return false;
}

uint32_t instr_gen::next(uint64_t addr) {
    CHECK(linear_idx_gen.next());
    size_t idx = linear_idx;
    auto& c = constraints.at(linear_instruction_index.at(idx));
    do{
        CHECK(c.next());
    } while(is_unsupported(c.get_instruction()));
    return c.get_instruction();
}

void instr_gen::setup_regs(uint8_t* regs, uint32_t rfs, uint32_t len) {
    if(len == 64) {
        regs_accessor = std::make_unique<::seq::regs_accessor<uint64_t>>(regs);
    } else {
        regs_accessor = std::make_unique<::seq::regs_accessor<uint32_t>>(regs);
    }
    num_regs = rfs;
    regs_len = len;
}

} // namespace seq
