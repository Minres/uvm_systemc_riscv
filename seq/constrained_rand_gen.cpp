#include <algorithm>
// #include <assembler.h>
#include <core_mapper.h>
#include <cstring>
#include <elfio/elfio.hpp>
#include <fmt/format.h>
#include <functional>
#include <iss/vm_plugin.h>
#include <scc/mt19937_rng.h>
#include <scc/report.h>
#include <src/uvm_systemc_riscv/iss_if.h>
#include <src/uvm_systemc_riscv/seq/constrained_rand_gen.h>
#include <tuple>
#include <util/ities.h>

using namespace sc_core;
using namespace util;
using namespace seq;

constexpr uint32_t word_size = 4;
constexpr uint32_t trap_handler_addr = 0xffff04c0;
uint32_t process_line(std::string const& line, uint64_t line_no);

inline unsigned copy_into(uint32_t instr, uint8_t* data) {
    assert(data);
    if constexpr(util::endian::little) {
        memcpy(data, &instr, 4);
    } else {
        data[0] = instr % 256;
        data[1] = instr % (256 * 256) / 256;
        data[2] = instr % (256 * 256 * 256) / (256 * 256);
        data[3] = instr / (256 * 256 * 256);
    }
    return (instr & 0x3) == 0x3 ? 4 : 2;
}

inline uint32_t instr_from(size_t len, uint8_t* data) {
    assert(data);
    uint32_t res = 0;
    if constexpr(util::endian::little) {
        memcpy(&res, data, len);
    } else {
        res |= (static_cast<uint32_t>(data[1]) << 8) | data[0];
        if(len == 4)
            res |= (static_cast<uint32_t>(data[3] << 24)) | (static_cast<uint32_t>(data[2]) << 16);
    }
    return res;
}

mem_rsp seq::constrained_rand_gen::transport(const mem_req& tx) {
    request_fifo.write(tx);
    auto resp = response_fifo.read();
    return resp;
}

void constrained_rand_gen::run() {
    while(true) {
        auto tx = request_fifo.read();
        switch(tx.type) {
        case iss::access_type::FETCH: {
            mem_rsp resp;
            resp.data.resize(tx.len);
            vm->start(cpu_instrumentation_if->get_instr_count() + 1, false, iss::finish_cond_e::ICOUNT_LIMIT);
            auto next_pc = cpu_instrumentation_if->get_next_pc();
            auto instr = instructions.front();
            instructions.pop_front();
            auto ilen = copy_into(instr, resp.data.data());
            assert(ilen <= tx.len);
            response_fifo.write(resp);
            break;
        }
        case iss::access_type::READ: {
            mem_rsp resp;
            resp.data = data_buffer;
            data_buffer.clear();
            response_fifo.write(resp);
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

void constrained_rand_gen::build_phase(uvm::uvm_phase& phase) {
#ifdef INSTR_GEN
    std::string isa_yaml_file_name;
    uvm::uvm_config_db<std::string>::get(this, "", "isa_yaml_file_name", isa_yaml_file_name);
    i_gen.initialize(isa_yaml_file_name);
#endif
}

void constrained_rand_gen::before_end_of_elaboration() {
    std::vector<std::tuple<unsigned, uint32_t>> csr_reset_vals = {{
        {0x305, 0x20} // MTVEC
    }};
    std::tie(cpu, vm, irq_fct) = create_cpu("interp", 0U, *this, csr_reset_vals);
    cpu_instrumentation_if = cpu->get_instrumentation_if();

    uvm::uvm_config_db<bool>::get(this, "", "constrained_rand_gen_disass", enable_disass);
    uvm::uvm_config_db<bool>::get(this, "", "heart_beat", heart_beat);

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
    i_gen.setup_regs(cpu->get_regs_base_ptr(), traits::RFS, traits::XLEN);
}

iss::status constrained_rand_gen::read_mem(phys_addr_t addr, unsigned len, uint8_t* const data) {
    // this is a read from our reference iss
    if(is_fetch(addr.access)) {
        if(len == 4) {
            uint32_t instr = 0;
            if(startup_instr_count < startup_asm.size()) {
                instr = get_next_asm_instr(startup_asm, startup_instr_count);
            } else if(trap_handler_addr <= addr.val && (addr.val + len) <= (trap_handler_addr + trap_handler_buffer.size())) {
                auto offset = addr.val - trap_handler_addr;
                auto start = trap_handler_buffer.data() + offset;
                std::copy(start, start + len, data);
                instr = instr_from(len, data);
            } else {
                instr = i_gen.next(addr.val);
            }
            auto ilen = copy_into(instr, data);
            instructions.push_back(instr);
        }
    } else if(addr.access == iss::access_type::READ || addr.access == iss::access_type::DEBUG_READ) {
        data_buffer.clear();
        for(size_t i = 0; i < len; i++)
            data_buffer.push_back(scc::MT19937::uniform() % 256);
        std::copy(data_buffer.begin(), data_buffer.end(), data);
    }
    return iss::status::Ok;
}

uint32_t constrained_rand_gen::get_next_asm_instr(std::vector<std::string> const& asm_code, uint64_t& idx) {
    try {
        uint32_t instr = 0;
        if(idx < asm_code.size())
            instr = process_line(asm_code[idx], idx);
        else
            instr = process_line("addi x1, x0, 0", idx);
        idx++;
        return instr;
    } catch(std::range_error& e) {
        SCCFATAL(SCMOD) << "Could not assemble line: " << asm_code[idx];
    }
    return 0;
}

void constrained_rand_gen::put_irq_to_trigger(unsigned value) { irq_to_trigger.push_back(value); }

void constrained_rand_gen::put_trigger_delay_cnt(unsigned value) { trigger_delay_cnt = value; }

void constrained_rand_gen::gen_startup_code() {
    startup_asm.emplace_back(fmt::format("addi x1, x0, {:#x}", 0x800));
    startup_asm.emplace_back("csrrw x0, mie, x1");
    startup_asm.emplace_back("csrrs x1, mstatus, x0");
    startup_asm.emplace_back("ori x1, x0, 8");
    startup_asm.emplace_back("csrrw x0, mstatus, x1");
    // Assign the trap handler address directly to t0
    startup_asm.emplace_back(fmt::format("lui x5, {:#x}", (trap_handler_addr & 0xfffff000) >> 12));
    startup_asm.emplace_back(fmt::format("ori x5, x5, {:#x}", trap_handler_addr & 0xfff));
    // Write the contents of t0 to the mtvec register
    startup_asm.emplace_back("csrrw x0, mtvec, x5");
    for(auto i = 1U; i < traits::RFS; ++i) {
        uint32_t x = scc::MT19937::uniform<uint32_t>();
        startup_asm.emplace_back(fmt::format("lui x{}, {:#x}", i, x >> 12));
        startup_asm.emplace_back(fmt::format("ori x{}, x{}, {:#x}", i, i, x & 0xfff));
    }
}

void constrained_rand_gen::gen_trap_handler_mc() {
    std::vector<std::string> trap_handler_asm;
    trap_handler_asm.emplace_back("csrrw x6, mepc, x0"); // Read the mepc registers into t1
    trap_handler_asm.emplace_back("addi x6, x6, 4");     // Add 4 to t2, which is the address of the next instruction
    trap_handler_asm.emplace_back("csrrw x0, mepc, x6"); // Write the contents of t2 back to mepc
    trap_handler_asm.emplace_back("mret x0, x0, 0");     // Return from the trap
    auto idx = 0u;
    trap_handler_buffer.resize(trap_handler_asm.size() * 4);
    auto data = trap_handler_buffer.data();
    for(auto& i : trap_handler_asm) {
        auto mc = process_line(i, idx++);
        auto size = copy_into(mc, data);
        data += size;
    }
}
