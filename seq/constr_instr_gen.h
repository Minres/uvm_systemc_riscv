#pragma once

#include <array>
#include <atomic>
#include <cassert>
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

namespace seq {
using namespace crave;

struct instr_constr : public rand_obj {
    randv<uint32_t> instr_idx;
    randv<uint32_t> rs1;
    randv<uint32_t> rs2;
    randv<uint32_t> c_rs1;
    randv<uint32_t> c_rs2;
    randv<uint32_t> rd;
    randv<uint32_t> addr;

    instr_constr(uint32_t lower_bound, uint32_t upper_bound, uint32_t num_regs)
    : rand_obj()
    , instr_idx(this)
    , rs1(this)
    , rs2(this)
    , rd(this)
    , addr(this)
    , address_store(16, 0) {
        constraint("rs1", dist(rs1(), distribution<uint32_t>::simple_range(0, num_regs)));
        constraint("rs2", dist(rs2(), distribution<uint32_t>::simple_range(0, num_regs)));
        constraint("c_rs1", dist(c_rs1(), distribution<uint32_t>::simple_range(8, 15)));
        constraint("c_rs2", dist(c_rs2(), distribution<uint32_t>::simple_range(8, 15)));
        constraint("rd", dist(rd(), distribution<uint32_t>::simple_range(0, num_regs)));
        constraint("instr_idx", dist(instr_idx(), distribution<uint32_t>::simple_range(lower_bound, upper_bound)));
        for(int i = 0; i < address_store.size(); i++) {
            constraint(reference(address_store[i]) != addr());
        }
    }

    void update_addr_list(uint32_t new_addr) {
        address_store.pop_front();
        address_store.push_back(new_addr);
    }

private:
    std::deque<uint32_t> address_store;
};

struct csr_constr : public rand_obj {
    randv<uint32_t> csr_idx;
    uint32_t get_csr_addr() { return csr_registers[csr_idx].addr; }
    csr_constr()
    : rand_obj()
    , csr_idx(this) {
        constraint("csr", dist(csr_idx(), distribution<uint32_t>::simple_range(0, csr_registers.size() - 1)));
    }
};

struct constr_instr_gen {

    constr_instr_gen(std::string name);

    void read_isa_config(std::unordered_map<std::string, std::vector<aging::instruction>> const& isa_config);
    void add_csr_to_ignore(unsigned addr);
    uint32_t next(uint64_t addr);

    void setup_regs(uint8_t* regs, uint32_t rfs, uint32_t len);

    bool enable_compressed = false;

private:
    bool is_unsupported(uint32_t);
    struct instr_info {
        const char* name;
        uint32_t mask;
        uint32_t encoding;
        bool branch;
    };

    std::unordered_map<uint8_t, instr_info> all_instructions;
    std::unordered_set<unsigned> unsupported_csrs;
    std::vector<std::pair<uint32_t, uint32_t>> skipped_instr;
    std::unique_ptr<regs_accessor_base> regs_accessor;
    uint32_t num_regs{31};
    uint32_t regs_len{32};
    // constraints
    instr_constr* iconstr{nullptr};
    csr_constr csrconstr;
};

} // namespace crig
