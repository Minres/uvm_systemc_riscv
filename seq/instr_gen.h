#pragma once

#include "risc-v.h"
#include <array>
#include <atomic>
#include <cassert>
#include <components/yaml_instruction_parser.h>
#include <core_config.h>
#include <coverage.h>
#include <crave2uvm/crave2uvm.h>
#include <cstdint>
#include <deque>
#include <isa_config.h>
#include <memory>
#include <scc/mt19937_rng.h>
#include <scc/report.h>
#include <seq/regs_accessor.h>
#include <unordered_map>
#include <unordered_set>
#include <variant>

namespace seq {
using namespace crave;

using rand_var = std::variant<randv<uint64_t>, randv<uint32_t>, randv<uint16_t>, randv<uint8_t>, randv<bool>>;
struct instr_gen {

    instr_gen(std::string const& nm);

    void add_csr_to_ignore(unsigned short addr);

    uint32_t next(uint64_t addr);

    void setup_regs(uint8_t* regs, uint32_t rfs, uint32_t len);

    void initialize(std::string const& isa_file);

private:
    struct instr_constraint {
        std::vector<rand_var> field_rand_vars;
        std::vector<crave::Generator> field_rand_gen;

        std::vector<std::function<uint32_t(uint32_t)>> mapper;
        const components::instruction_desc desc;

        instr_constraint(components::instruction_desc const& desc)
        : desc(desc) {}
        instr_constraint(components::instruction_desc&& desc)
        : desc(desc) {}

        bool next() {
            auto ret = true;
            for(auto& c : field_rand_gen)
                ret &= c.next();
            return ret;
        }

        uint32_t get_instruction() {
            uint32_t machine_word = desc.pattern;
            for(auto& m : mapper)
                machine_word = m(machine_word);
            return machine_word;
        }
    };

    size_t generate_field_constraints(components::instruction_desc idesc);

    template <typename T> size_t generate_imm_constraint(std::string const&, components::bit_range);

    size_t generate_reg_constraint(std::string const&, components::bit_range);

    bool is_unsupported(uint32_t x);

    const std::string name;
    crave::randv<size_t> linear_idx;
    crave::Generator linear_idx_gen;
    crave::randv<size_t> all_idx;
    crave::Generator all_idx_gen;

    std::deque<instr_constraint> constraints;
    std::vector<unsigned> all_instruction_index;
    std::vector<unsigned> linear_instruction_index;
    std::array<std::vector<components::instruction_pattern>, 4> qlut;
    std::unique_ptr<regs_accessor_base> regs_accessor;
    uint32_t num_regs{31};
    uint32_t regs_len{32};
    std::unordered_set<short> unsupported_csrs{{// skip mstatus so that MIE is never set
                                                riscv::MSTATUS_ADDR, riscv::MIP_ADDR, riscv::USTATUS_ADDR, riscv::UIP_ADDR,
                                                riscv::PMPCFG0_ADDR, riscv::PMPCFG1_ADDR, riscv::PMPCFG2_ADDR, riscv::PMPCFG3_ADDR,
                                                riscv::DCSR_ADDR}};
    std::unordered_set<short> volatile_csrs{{riscv::MCYCLE_ADDR, riscv::MCYCLEH_ADDR, riscv::MINSTRET_ADDR, riscv::MINSTRETH_ADDR,
                                             riscv::CYCLE_ADDR, riscv::CYCLEH_ADDR, riscv::INSTRET_ADDR, riscv::INSTRETH_ADDR,
                                             riscv::TIME_ADDR, riscv::TIMEH_ADDR}};
    std::vector<std::pair<uint32_t, uint32_t>> disabled_instr{{riscv::WFI_MASK, riscv::WFI_ENCODING}};
};

} // namespace seq
