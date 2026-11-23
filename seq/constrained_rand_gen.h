#pragma once

#include <deque>
#define INSTR_GEN
#include "constr_instr_gen.h"
#include "instr_gen.h"
#include "types.h"
#include <cci_configuration>
#include <core_mapper.h>
#include <cstdint>
#include <iss_if.h>
#include <scc/utilities.h>
#include <tlm>
#include <types.h>
#include <uvm>

namespace seq {
struct iss_plugin;
class constrained_rand_gen : public uvm::uvm_component, public seq_if, public iss_if, public irq_push_if {
public:
    sc_core::sc_export<seq_if> mem_p{"mem_p"};

    constrained_rand_gen(uvm::uvm_component_name name);

    virtual ~constrained_rand_gen();

    UVM_COMPONENT_UTILS(constrained_rand_gen);

    void build_phase(uvm::uvm_phase& phase) override;

    mem_rsp transport(const mem_req&) override;

    iss::status read_mem(phys_addr_t addr, unsigned len, uint8_t* const data) override;
    iss::status write_mem(phys_addr_t addr, unsigned len, uint8_t const* const data) override { return iss::Ok; }

    char const* instance_name() { return name(); }

private:
#ifdef INSTR_GEN
    instr_gen i_gen{"i_gen"};
#else
    constr_instr_gen i_gen{"i_gen"};
#endif
    std::deque<uint32_t> instructions;
    std::vector<uint8_t> data_buffer;

    bool enable_disass{false};
    bool heart_beat{false};

    cpu_ptr cpu;
    iss::instrumentation_if* cpu_instrumentation_if{nullptr};
    vm_ptr vm;
    std::unique_ptr<iss_plugin> plugin;
    std::function<uint32_t(unsigned, bool)> irq_fct;

    void run();
    void before_end_of_elaboration() override;
    void end_of_elaboration() override;
    void start_of_simulation_phase(uvm::uvm_phase& phase) override;
    void put_irq_to_trigger(unsigned) override;
    void put_trigger_delay_cnt(unsigned) override;

    std::vector<unsigned> irq_to_trigger; // bit 31: set/reset, bit 30:0 irq number
    unsigned trigger_delay_cnt{0};

    uint32_t get_next_asm_instr(std::vector<std::string> const& asm_code, uint64_t& idx);

    void gen_startup_code();
    std::vector<std::string> startup_asm;
    uint64_t startup_instr_count = 0;
    void gen_trap_handler_mc();
    std::vector<uint8_t> trap_handler_buffer;
    sc_core::sc_fifo<mem_req> request_fifo{"request_fifo", 1};
    sc_core::sc_fifo<mem_rsp> response_fifo{"response_fifo", 1};
};

} // namespace seq
