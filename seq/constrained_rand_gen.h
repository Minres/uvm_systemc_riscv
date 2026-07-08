#pragma once

#include <cci_configuration>
#include <cstdint>
#include <limits>
#include <scc/utilities.h>
#include <tlm_core/tlm_1/tlm_req_rsp/tlm_1_interfaces/tlm_core_ifs.h>
#include <uvm>

#include <instr_gen.h>
#include <iss_if.h>
#include <seq/constr_instr_gen.h>
#include <seq/types.h>
#include <types.h>

namespace seq {
class constrained_rand_gen : public uvm::uvm_component, public seq_if, public iss_if, public irq_push_if {
public:
    sc_core::sc_export<seq_if> mem_p{"mem_p"};

    constrained_rand_gen(uvm::uvm_component_name name)
    : uvm::uvm_component(name) {
        mem_p(*this);
        gen_startup_code();
        gen_trap_handler_code();
        SC_HAS_PROCESS(constrained_rand_gen);
        SC_THREAD(run);
    }

    virtual ~constrained_rand_gen() = default;

    UVM_COMPONENT_UTILS(constrained_rand_gen);

    mem_rsp transport(const mem_req&) override;

    iss::status read_mem(phys_addr_t addr, unsigned len, uint8_t* const data) override;
    iss::status write_mem(phys_addr_t addr, unsigned len, uint8_t const* const data) override { return iss::Ok; }

    char const* instance_name() { return name(); }

private:
    crig::ConstrInstrGen i_gen{"i_gen"};
    std::vector<uint8_t> instr_buffer;
    std::vector<uint8_t> data_buffer;

    bool enable_disass{false};
    bool heart_beat{false};

    cpu_ptr cpu;
    iss::instrumentation_if* cpu_instrumentation_if{nullptr};
    vm_ptr vm;
    std::function<uint32_t(unsigned, bool)> irq_fct;

    void run();
    uint64_t exec_iss();
    void before_end_of_elaboration() override;
    void end_of_elaboration() override;
    void start_of_simulation_phase(uvm::uvm_phase& phase) override;
    void put_irq_to_trigger(unsigned) override;
    void put_trigger_delay_cnt(unsigned) override;

    void get_instr(uint64_t addr, unsigned len, uint8_t* const data);
    std::vector<unsigned> irq_to_trigger; // bit 31: set/reset, bit 30:0 irq number
    unsigned trigger_delay_cnt{0};

    void exec_asm(std::vector<std::string> asm_code, uint64_t idx, unsigned len, uint8_t* const data);

    void gen_startup_code();
    std::vector<std::string> startup_asm;

    void gen_trap_handler_code();
    std::vector<std::string> trap_handler_asm;
    sc_core::sc_fifo<mem_req> request_fifo{"request_fifo", 1};
    sc_core::sc_fifo<mem_rsp> response_fifo{"response_fifo", 1};
};

} // namespace seq
