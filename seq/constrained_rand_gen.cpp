#include <algorithm>
//#include <assembler.h>
#include <core_mapper.h>
#include <elfio/elfio.hpp>
#include <fmt/format.h>
#include <functional>
#include <iss/vm_plugin.h>
//#include <rv32_iss/to_string.h>
#include <scc/mt19937_rng.h>
#include <scc/report.h>
#include <src/uvm_systemc_riscv/iss_if.h>
#include <src/uvm_systemc_riscv/seq/constrained_rand_gen.h>
#include <tuple>

using namespace sc_core;
using namespace util;
using namespace seq;

constexpr uint32_t word_size = 4;
constexpr uint32_t trap_handler_addr = 0x4c0;
uint32_t process_line(std::string const& line, uint64_t line_no);

mem_rsp seq::constrained_rand_gen::transport(const mem_req& tx) {
    request_fifo.write(tx);
    auto resp = response_fifo.read();
    return resp;
}

uint64_t constrained_rand_gen::exec_iss() {
    vm->start(cpu_instrumentation_if->get_instr_count() + 1, false, iss::finish_cond_e::ICOUNT_LIMIT);
    return cpu_instrumentation_if->get_next_pc();
}

void constrained_rand_gen::run() {
    while(true) {
        auto tx = request_fifo.read();
        switch(tx.type) {
        case iss::access_type::FETCH: {
            mem_rsp resp;
            if(trap_handler_addr <= tx.addr && tx.addr < trap_handler_addr + trap_handler_asm.size() * word_size) {
                auto trap_asm_idx = (tx.addr - trap_handler_addr) / word_size;
                tx.data.resize(tx.len);
                exec_asm(trap_handler_asm, trap_asm_idx, tx.len, tx.data.data());
                resp.data = tx.data;
            } else {
                uint64_t next_pc = 0;
                next_pc = exec_iss();
                if(tx.len > 4) {
                    while((tx.addr < next_pc && next_pc < tx.addr + tx.len) ||
                          (trap_handler_addr <= next_pc && next_pc < trap_handler_addr + trap_handler_asm.size() * word_size)) {
                        next_pc = exec_iss();
                    }
                }
                while(trap_handler_addr <= next_pc && next_pc < trap_handler_addr + trap_handler_asm.size() * word_size) {
                    next_pc = exec_iss();
                }
                resp.data = instr_buffer;
                instr_buffer.clear();
            }
            response_fifo.write(resp);
            break;
        }
        case iss::access_type::READ: {
            mem_rsp resp;
            resp.data = data_buffer;
            data_buffer.clear();
            response_fifo.write(resp);
            data_buffer.clear();
            break;
        }
        case iss::access_type::WRITE: {
            mem_rsp resp;
            response_fifo.write(resp);
            break;
        }
        default:
            UVM_ERROR("constrained_rand_gen", "Unsupported mem access type");
        }
    }
}

template <typename T = traits::reg_t> inline T& get_reg(iss::arch_if& cpu, unsigned r) {
    return *reinterpret_cast<T*>(cpu.get_regs_base_ptr() + traits::reg_byte_offsets[r]);
}

void constrained_rand_gen::before_end_of_elaboration() {
    std::vector<std::tuple<unsigned, uint32_t>> csr_reset_vals = {{
        {0x305, 0x20} // MTVEC
    }};
    std::tie(cpu, vm, irq_fct) = create_cpu("interp", 0U, *this, csr_reset_vals);
    cpu_instrumentation_if = cpu->get_instrumentation_if();

    uvm::uvm_config_db<bool>::get(this, "", "constrained_rand_gen_disass", enable_disass);
    uvm::uvm_config_db<bool>::get(this, "", "heart_beat", heart_beat);
    uvm::uvm_config_db<bool>::get(this, "", "compressed_instr", compressed_instr);

    if(enable_disass) {
        vm->setDisassEnabled(true);
        //        LOGGER(disass)::set_reporting_level(logging::INFO);
        //        LOGGER(disass)::print_time() = false;
    }
}

void constrained_rand_gen::end_of_elaboration() {
    uint64_t start_addr{0};
    uvm::uvm_config_db<uint64_t>::get(this, "*", "reset_address", start_addr);
    cci::cci_broker_handle broker = cci::cci_get_broker();
    auto hndl = broker.get_param_handle("adapter.reset_address");
    if(hndl.is_valid())
        hndl.set_cci_value(cci::cci_value{start_addr});
    vm->reset(start_addr);
}

void constrained_rand_gen::start_of_simulation_phase(uvm::uvm_phase& phase) {
    bool has_hwl{false};
    uvm::uvm_config_db<bool>::get(this, "", "hw_loops", has_hwl);
    if(has_hwl) { // skip the hwl CSRs
        UVM_INFO("uvm_tb", "enabled HW loops", uvm::UVM_MEDIUM);
        for(auto addr : std::array<unsigned, 6>({0x800, 0x801, 0x802, 0x804, 0x805, 0x806}))
            i_gen.add_csr_to_ignore(addr);
    }
    uvm::uvm_config_db<bool>::get(this, "", "compressed_instr", i_gen.enable_compressed);
    i_gen.setup_regs(cpu->get_regs_base_ptr(), traits::RFS, traits::XLEN);
}

void constrained_rand_gen::exec_asm(std::vector<std::string> asm_code, uint64_t idx, unsigned len, uint8_t* const data) {
    try {
        for(int i = 0; i < len / word_size; i++) {
            uint32_t retval{0};
            if(idx + i < asm_code.size()) {
                retval = process_line(asm_code[idx + i], idx + i);
            } else {
                retval = process_line("addi x1, x0, 0", idx + i); // fill up the cacheline
            }
            auto* src = reinterpret_cast<uint8_t*>(&retval);
            std::copy(src, src + word_size, data + i * word_size);
        }
    } catch(std::range_error& e) {
        SCCFATAL(SCMOD) << "Could not assemble line: " << asm_code[idx];
    }
}

iss::status constrained_rand_gen::read_mem(phys_addr_t addr, unsigned len, uint8_t* const data) {
    auto instr_count = cpu_instrumentation_if->get_instr_count();
    if(instr_count < startup_asm.size()) {
        exec_asm(startup_asm, instr_count, len, data);
        std::copy(data, data + len, std::back_inserter(instr_buffer));
    } else if(trap_handler_addr <= addr.val && addr.val <= trap_handler_addr + trap_handler_asm.size() * word_size) {
        auto trap_asm_idx = (addr.val - trap_handler_addr) / word_size;
        exec_asm(trap_handler_asm, trap_asm_idx, len, data);
    } else {
        if(is_fetch(addr.access)) {
            if(len > word_size) {
                exec_trace<traits::reg_t> cache_entry;
                cache_entry.bus_accesses.resize(1);
                dbus_access& access = cache_entry.bus_accesses.front();
                access.bus_data.reserve(64);
                access.bus_data.resize(len);
                get_instr(addr.val, len, access.bus_data.data());
                std::copy(std::begin(access.bus_data), std::end(access.bus_data), data);
                cache_entry.type = fetch_type_e::FETCH_CL;
                access.access_type = dBus_access_e::FETCH;
                access.bus_addr = addr.val;
            } else {
                get_instr(addr.val, len, data);
            }
        } else if(addr.access == iss::access_type::READ || addr.access == iss::access_type::DEBUG_READ) {
            for(size_t i = 0; i < len; i++)
                data_buffer.push_back(scc::MT19937::uniform() % 256);
            std::copy(data_buffer.begin(), data_buffer.end(), data);
        }
    }
    return iss::status::Ok;
}

void constrained_rand_gen::get_instr(uint64_t addr, unsigned len, uint8_t* const instr) {
    for(int i = 0; i < len; i += word_size) {
        auto retval = i_gen.next(addr);
        auto* src = reinterpret_cast<uint8_t*>(&retval);
        instr_buffer.insert(instr_buffer.end(), src, src + sizeof(retval));
    }
    std::copy(instr_buffer.begin(), instr_buffer.end(), instr);
}

void constrained_rand_gen::put_irq_to_trigger(unsigned value) { irq_to_trigger.push_back(value); }

void constrained_rand_gen::put_trigger_delay_cnt(unsigned value) { trigger_delay_cnt = value; }

void constrained_rand_gen::gen_startup_code() {
    startup_asm.emplace_back(fmt::format("addi x{}, x0, {:#x}", 1, 0x800));
    startup_asm.emplace_back(fmt::format("csrrw x0, mie, x{}", 1));
    startup_asm.emplace_back(fmt::format("csrrs x{}, mstatus, x0", 1));
    startup_asm.emplace_back(fmt::format("ori x{}, x0, {:#x}", 1, 0x8));
    startup_asm.emplace_back(fmt::format("csrrw x0, mstatus, x{}", 1));
    // Assign the trap handler address directly to t0
    startup_asm.emplace_back(fmt::format("lui x5, {:#x}", 0));
    startup_asm.emplace_back(fmt::format("ori x5, x5, {:#x}", trap_handler_addr & 0xfff));
    // Write the contents of t0 to the mtvec register
    startup_asm.emplace_back(fmt::format("csrrw x0, mtvec, x{}", 5));
    for(auto i = 1U; i < traits::RFS; ++i) {
        uint32_t x = scc::MT19937::uniform<uint32_t>();
        startup_asm.emplace_back(fmt::format("lui x{}, {:#x}", i, x >> 12));
        startup_asm.emplace_back(fmt::format("ori x{}, x{}, {:#x}", i, i, x & 0xfff));
    }
}

void constrained_rand_gen::gen_trap_handler_code() {
    // Read the mepc registers into t1
    trap_handler_asm.emplace_back(fmt::format("csrrw x{}, mepc, x0", 6));
    // Add 4 to t2, which is the address of the next instruction
    trap_handler_asm.emplace_back(fmt::format("addi x{}, x{}, {:#x}", 6, 6, 4));
    // Write the contents of t2 back to mepc
    trap_handler_asm.emplace_back(fmt::format("csrrw x0, mepc, x{}", 6));
    // Return from the trap
    trap_handler_asm.emplace_back("mret x0, x0, 0");
}
