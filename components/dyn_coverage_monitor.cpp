/*
 * dyn_coverage_monitor.cpp
 *
 *  Created on: Jun 18, 2022
 *      Author: eyck
 */

#include "components/dyn_coverage_monitor.h"
#include "components/coverage_monitor/instr.h"
#include "yaml_instruction_parser.h"
#include <cstdint>
#include <cstdlib>
#include <fc4sc.hpp>
#include <regex>
#include <scc/report.h>
#include <systemc>
#include <types.h>
#include <unordered_map>
#include <util/ities.h>
#include <variant>
#include <vector>
#include <yaml-cpp/yaml.h>

namespace components {
using i32_limits = std::numeric_limits<int32_t>;
using u32_limits = std::numeric_limits<uint32_t>;
enum hazard_e { NO_HAZARD = 0, RAW = 1, WAW = 2, WAR = 4 };

struct hazard_type {
    bool raw{false};
    bool waw{false};
    bool war{false};
};

struct instr_cg : public covergroup {
    using data_type = std::variant<bool, int8_t, int16_t, int32_t, int64_t, uint8_t, uint16_t, uint32_t, uint64_t>;
    using cvp_data_type = std::variant<coverpoint<bool>, coverpoint<int8_t>, coverpoint<int16_t>, coverpoint<int32_t>, coverpoint<int64_t>,
                                       coverpoint<uint8_t>, coverpoint<uint16_t>, coverpoint<uint32_t>, coverpoint<uint64_t>>;
    using imm_cross_data_type =
        std::variant<cross<uint8_t, uint8_t>, cross<uint16_t, uint8_t>, cross<uint32_t, uint8_t>, cross<uint64_t, uint8_t>>;

    instr_cg(std::string inst_name, instruction_desc const& desc)
    : fc4sc::covergroup("instr_coverage", __FILE__, __LINE__, inst_name)
    , desc(desc) {
        regs_rd.reserve(4);
        regs_wr.reserve(4);
        initialize_cvps();
        option.per_instance = true;
    }

    void sample(unsigned last_written_reg, uint32_t instr, bool branch_taken) {
        // clean the queue holding the data accesses
        for(auto& d : data)
            std::visit([](auto& value) { value = {}; }, d);
        // extract the instruction information and store in variables being sampled
        if(desc.bitfield_sizes.size())
            for(auto bf : desc.bitfields) {
                auto& d = data[bf.index];
                if(bf.total_size > 32) {
                    std::get<uint64_t>(d) |= extract_bits(instr, bf.instr.lsb, bf.width) << bf.field.lsb;
                } else if(bf.total_size > 16) {
                    std::get<uint32_t>(d) |= extract_bits(instr, bf.instr.lsb, bf.width) << bf.field.lsb;
                } else if(bf.total_size > 8) {
                    std::get<uint16_t>(d) |= extract_bits(instr, bf.instr.lsb, bf.width) << bf.field.lsb;
                } else if(bf.total_size > 5) {
                    std::get<uint8_t>(d) |= extract_bits(instr, bf.instr.lsb, bf.width) << bf.field.lsb;
                } else if(bf.total_size == 1) {
                    std::get<bool>(d) |= extract_bits(instr, bf.instr.lsb, bf.width) << bf.field.lsb;
                } else {
                    std::get<uint8_t>(d) |= extract_bits(instr, bf.instr.lsb, bf.width) << bf.field.lsb;
                }
                switch(bf.type) {
                case field_type::DST:
                    regs_wr.push_back(bf.width == 3 ? (std::get<uint8_t>(d) + 8) : std::get<uint8_t>(d));
                    break;
                case field_type::SRC:
                    regs_rd.push_back(bf.width == 3 ? (std::get<uint8_t>(d) + 8) : std::get<uint8_t>(d));
                    break;
                case field_type::SRC_DST:
                    auto val = bf.width == 3 ? (std::get<uint8_t>(d) + 8) : std::get<uint8_t>(d);
                    regs_rd.push_back(val);
                    regs_wr.push_back(val);
                    break;
                }
                hazard_s.raw = std::any_of(last_regs_wr.begin(), last_regs_wr.end(), [this](unsigned element) {
                    return std::find(regs_rd.begin(), regs_rd.end(), element) != regs_rd.end();
                });
                hazard_s.waw = std::any_of(last_regs_wr.begin(), last_regs_wr.end(), [this](unsigned element) {
                    return std::find(regs_wr.begin(), regs_wr.end(), element) != regs_wr.end();
                });
                hazard_s.war = std::any_of(last_regs_rd.begin(), last_regs_rd.end(), [this](unsigned element) {
                    return std::find(regs_wr.begin(), regs_wr.end(), element) != regs_wr.end();
                });
                last_regs_rd = regs_rd;
                last_regs_wr = regs_wr;
                regs_rd.clear();
                regs_wr.clear();
            }
        else { // create a dummy coverpoint if we do not have any variable bitfields
            std::get<uint64_t>(data[0])++;
        }
        this->branch_taken = branch_taken;
        covergroup::sample();
    }

    //! create a coverpoint and the data of type T to be observed
    template <typename T> coverpoint<T>& create_cvp(std::string const& name) {
        constexpr T dummy = 0;
        data.emplace_back(dummy);
        auto& d = std::get<T>(data.back());
        cvp.emplace_back(coverpoint<T>({}));
        auto* c = &std::get<coverpoint<T>>(cvp.back());
        // covergroup::register_cvp is a horrible hack to implement the COVERPOINT macro
        // it takes the address of a (future) coverpoint instance and uses it only to register the coverpoint. The return
        // value is then used to construct the coverpoint. We need to mimick this behavior
        auto x = covergroup::register_cvp<T>(
            c, std::string(name), [&d]() -> T { return d; }, name + "_s", []() -> bool { return (true); }, name + "_c");
        // now copy the newly created coverpoint into the memeory location of the old one
        new(c) coverpoint<T>(x);
        return *c;
    }

    coverpoint<bool>& create_hazard_cvp(std::string const& name, bool& d) {
        hazard_cvp.emplace_back(coverpoint<bool>({}));
        auto* c = &hazard_cvp.back();
        auto x = covergroup::register_cvp<bool>(
            c, std::string(name), [&d]() -> bool { return d; }, name + "_s", []() -> bool { return (true); }, name + "_c");
        new(c) coverpoint<bool>(x);
        return *c;
    }
    //! create a coverpoint and the data of type T to be observed and add bins for various ranges and specific values
    template <typename T> void create_cvp_for(std::string const& name, bit_range& bf_sz) {
        constexpr T zero = 0;
        constexpr T one = 1;
        auto width = bf_sz.msb - bf_sz.lsb + 1;
        auto u_upper = (one << width) - 1;
        auto u_middle = (one << (width - 1));
        auto s_upper = ((one << width - 1) - 1);
        auto s_lower = ((one << width - 1));
        create_cvp<T>(name) = {fc4sc::bin<T>("umin", zero),
                               fc4sc::bin<T>("umax", u_upper << bf_sz.lsb),
                               fc4sc::bin<T>("smin", s_lower << bf_sz.lsb),
                               fc4sc::bin<T>("sneg", fc4sc::interval<T>(s_lower + 1, u_upper - 1)),
                               fc4sc::bin<T>("spos", interval<T>(1ull, s_upper - 1)),
                               fc4sc::bin<T>("smax", s_upper << bf_sz.lsb)};
    }

    template <typename T> void create_imm_cross(std::string name, coverpoint<T>* imm, coverpoint<uint8_t>* rs1) {
        imm_crosses.emplace_back(std::in_place_type<cross<T, uint8_t>>, this, std::move(name), imm, rs1);
    }

    //! create coverpoints with bins for all variable bitfields in the instruction
    void initialize_cvps() {
        if(desc.bitfield_sizes.size()) {
            bool cr_w = false;
            bool cr_r = false;
            for(auto b : desc.bitfield_sizes) {
                auto& name = b.first;
                auto& bf_sz = b.second;
                if(bf_sz.msb > 31) {
                    create_cvp_for<uint64_t>(name, bf_sz);
                } else if(bf_sz.msb > 15) {
                    create_cvp_for<uint32_t>(name, bf_sz);
                } else if(bf_sz.msb > 7) {
                    create_cvp_for<uint16_t>(name, bf_sz);
                } else if(bf_sz.msb > 4) {
                    create_cvp_for<uint8_t>(name, bf_sz);
                } else if(bf_sz.msb == 0) {
                    create_cvp<bool>(name) = {bin<bool>("no", false), bin<bool>("yes", false)};
                } else {
                    auto& c = create_cvp<uint8_t>(name);
                    auto count = 1u << (bf_sz.msb - bf_sz.lsb + 1);
                    c = {bin_array<uint8_t>(name, count, interval(0u, count - 1))};
                    if(name == "rd" || name == "rsd") {
                        cr_w = true;
                    } else if(name.substr(0, 2) == "rs")
                        cr_r = true;
                }
                auto data_idx = data.size() - 1;
                for(auto& bf : desc.bitfields) {
                    if(bf.name == name) {
                        bf.index = data_idx;
                        bf.total_size = bf_sz.msb + 1;
                    }
                }
            }
            if(cr_w) {
                create_hazard_cvp("war", hazard_s.war) = {bin<bool>("no", false), bin<bool>("yes", true)};
                create_hazard_cvp("waw", hazard_s.waw) = {bin<bool>("no", false), bin<bool>("yes", true)};
            }
            if(cr_r)
                create_hazard_cvp("raw", hazard_s.raw) = {bin<bool>("no", false), bin<bool>("yes", true)};
        } else {
            create_cvp<uint64_t>("hit") = {fc4sc::bin<uint64_t>("hit", interval<uint64_t>(1ull, std::numeric_limits<uint64_t>::max()))};
        }
        if(desc.branch)
            create_cvp<bool>("branch taken") = {bin<bool>("no", false), bin<bool>("yes", false)};
        coverpoint<uint8_t>* rd = nullptr;
        coverpoint<uint8_t>* rs1 = nullptr;
        coverpoint<uint8_t>* rs2 = nullptr;
        unsigned imm_index = std::numeric_limits<unsigned>::max();
        std::string imm_name;
        for(auto const& bf : desc.bitfields) {
            if(bf.name == "rd")
                rd = &std::get<coverpoint<uint8_t>>(cvp[bf.index]);
            else if(bf.name == "rs1")
                rs1 = &std::get<coverpoint<uint8_t>>(cvp[bf.index]);
            else if(bf.name == "rs2")
                rs2 = &std::get<coverpoint<uint8_t>>(cvp[bf.index]);
            else if(bf.name.size() >= 3 && bf.name.compare(bf.name.size() - 3, 3, "imm") == 0 &&
                    imm_index == std::numeric_limits<unsigned>::max()) {
                imm_index = bf.index;
                imm_name = bf.name;
            }
        }
        if(rd && rs1)
            reg_crosses.emplace_back(this, "rd_rs1", rs1, rd);
        if(rd && rs2)
            reg_crosses.emplace_back(this, "rd_rs2", rs2, rd);
        if(rs1 && rs2)
            reg_crosses.emplace_back(this, "rs1_rs2", rs2, rs1);
        if(rs1 && imm_index != std::numeric_limits<unsigned>::max()) {
            std::visit(
                [this, rs1, &imm_name](auto& imm) {
                    using imm_cvp_type = std::decay_t<decltype(imm)>;
                    if constexpr(std::is_same_v<imm_cvp_type, coverpoint<uint8_t>> || std::is_same_v<imm_cvp_type, coverpoint<uint16_t>> ||
                                 std::is_same_v<imm_cvp_type, coverpoint<uint32_t>> || std::is_same_v<imm_cvp_type, coverpoint<uint64_t>>)
                        create_imm_cross("rs1_" + imm_name, &imm, rs1);
                },
                cvp[imm_index]);
        }
    }

    static inline std::vector<unsigned> last_regs_rd = {}, last_regs_wr = {};
    std::vector<unsigned> regs_rd, regs_wr;

    bool branch_taken = false;
    hazard_type hazard_s;
    // we use deque since reallocating the content kills the fc4sc stuff as it relies on pointers
    std::deque<data_type> data;

    std::deque<coverpoint<bool>> hazard_cvp;
    std::deque<cvp_data_type> cvp;
    std::deque<cross<uint8_t, uint8_t>> reg_crosses;
    std::deque<imm_cross_data_type> imm_crosses;

    instruction_desc desc;
};

struct illegal_coverage : public covergroup {
    CG_CONS(illegal_coverage) {}

    uint64_t inst_s{0};
    void sample(uint32_t inst) {
        this->inst_s = inst;
        covergroup::sample();
    }

    COVERPOINT(uint64_t, inst, inst_s) { bin_array<uint64_t>("illegal_instr", 64, interval(u32_limits::min(), u32_limits::max())) };
};

struct trap_coverage : public covergroup {
    CG_CONS(trap_coverage) {}

    int trap_id_s{0};
    void sample(int trap_id) {
        this->trap_id_s = trap_id;
        covergroup::sample();
    }

    COVERPOINT(int, trap_id, trap_id_s) {
        fc4sc::bin<int>("Instruction address misaligned", 0),
        fc4sc::bin<int>("Instruction access fault", 1),
        fc4sc::bin<int>("Illegal instruction", 2),
        fc4sc::bin<int>("Breakpoint", 3),
        fc4sc::bin<int>("Load address misaligned", 4),
        fc4sc::bin<int>("Load access fault", 5),
        fc4sc::bin<int>("Store/AMO address misaligned", 6),
        fc4sc::bin<int>("Store/AMO access fault", 7),
        fc4sc::bin<int>("Environment call from U-mode", 8),
        fc4sc::bin<int>("Environment call from S-mode", 9),
        fc4sc::illegal_bin<int>("Reserved", 10),
        fc4sc::bin<int>("Environment call from M-mode", 11),
        fc4sc::bin<int>("Instruction page fault", 12),
        fc4sc::bin<int>("Load page fault", 13),
        fc4sc::illegal_bin<int>("Reserved", 14),
        fc4sc::bin<int>("Store/AMO page fault", 15)
    };
};

struct dbus_access_coverage : public covergroup {
    CG_CONS(dbus_access_coverage) {}

    hazard_type hazard_s;
    uint64_t addr_s{0};
    int rw_s{0};
    uint8_t size_s{0};
    void sample(hazard_type hazard, uint32_t addr, bool write, unsigned size) {
        this->hazard_s = hazard;
        this->addr_s = addr;
        this->rw_s = write ? 1 : 0;
        this->size_s = size;
        covergroup::sample();
    }

    COVERPOINT(uint64_t, addr, addr_s) { bin_array<uint64_t>("segments", 16, interval(u32_limits::min(), u32_limits::max())) };
    COVERPOINT(int32_t, size, size_s) {
        fc4sc::bin<int>("1B", 1),
        fc4sc::bin<int>("2B", 2),
        fc4sc::bin<int>("4B", 4),
        fc4sc::bin<int>("8B", 8)
    };
    COVERPOINT(int, rw, rw_s) { fc4sc::bin<int>("wr", 1), fc4sc::bin<int>("rd", 0) };
    COVERPOINT(bool, raw, hazard_s.raw) { bin<bool>("no", false), bin<bool>("yes", true) };
    COVERPOINT(bool, waw, hazard_s.waw) { bin<bool>("no", false), bin<bool>("yes", true) };
    COVERPOINT(bool, war, hazard_s.war) { bin<bool>("no", false), bin<bool>("yes", true) };

    cross<int32_t, int32_t> access_types_cross = cross<int32_t, int32_t>(this, "access_types", &size, &rw);
    cross<int32_t, int32_t, uint64_t> access_cross = cross<int32_t, int32_t, uint64_t>(this, "accesses", &size, &rw, &addr);
};

struct dyn_coverage_monitor::impl {

    void parse_YAML_ISA(std::string isa_file) {
        std::vector<instruction_desc> instr_desc;
        std::tie(instr_desc, qlut) = components::parse_isa_yaml(isa_file);
        for(auto& desc : instr_desc) {
            cgs.emplace_back(desc.isa_subset + ":" + desc.mnemonic, desc);
        }
    }

    unsigned decode_instruction(uint32_t instr) {
        auto res = std::find_if(std::begin(qlut[instr & 0x3]), std::end(qlut[instr & 0x3]),
                                [instr](instruction_pattern const& e) { return !((instr & e.mask) ^ e.value); });
        return res != std::end(qlut[instr & 0x3]) ? res->id : std::numeric_limits<unsigned>::max();
    }

    void process(const exec_trace<traits::reg_t>& exc) {
        auto inst_id = decode_instruction(exc.fetch_value);
        if(exc.trap >= 0)
            trap_cg.sample(exc.trap /*, exc.insn*/);
        if(inst_id >= cgs.size()) {
            ill_cg.sample(exc.fetch_value);
            return;
        }
        cgs[inst_id].sample(last_written_reg, exc.fetch_value, exc.br_taken);
    }

    unsigned last_written_reg = -1;
    uint64_t last_address = 0;
    bool last_dbus_access_was_wr = false;
    int last_rd;
    std::array<std::vector<instruction_pattern>, 4> qlut;
    // std::vector<instruction_desc> instr_desc;
    std::deque<instr_cg> cgs;
    illegal_coverage ill_cg;
    dbus_access_coverage dbus_cg;
    trap_coverage trap_cg;
};

dyn_coverage_monitor::dyn_coverage_monitor(uvm::uvm_component_name const& nm)
: uvm::uvm_subscriber<exec_trace<traits::reg_t>>(nm)
, pimpl(new impl()) {}

dyn_coverage_monitor::~dyn_coverage_monitor() {
    if(report_file_name.size()) {
        SCCINFO(SCMOD) << "Writing coverage info to " << report_file_name;
        fc4sc::global::coverage_save(report_file_name.c_str());
    }
}

void dyn_coverage_monitor::build_phase(uvm::uvm_phase& phase) {
    uvm::uvm_config_db<std::string>::get(this, "", "isa_yaml_file_name", isa_yaml_file_name);
    uvm::uvm_config_db<std::string>::get(this, "", "report_file_name", report_file_name);
    if(report_file_name.size()) {
        pimpl->parse_YAML_ISA(isa_yaml_file_name);
        pimpl->trap_cg.option.merge_instances = true;
        pimpl->dbus_cg.option.merge_instances = true;
        pimpl->ill_cg.option.merge_instances = true;
    }
}

void dyn_coverage_monitor::end_of_simulation() {
    if(report_file_name.size()) {
        SCCINFO(SCMOD) << "Writing coverage info to " << report_file_name;
        fc4sc::global::coverage_save(report_file_name.c_str());
        report_file_name = "";
    }
}

void dyn_coverage_monitor::write(exec_trace<traits::reg_t> const& item) {
    if(report_file_name.size()) {
        pimpl->process(item);
        if(item.bus_accesses.size()) {
            for(auto& e : item.bus_accesses) {
                bool is_write = e.access_type == dBus_access_e::WRITE;
                hazard_type hazard{
                    // 4byte wide address bus
                    pimpl->last_dbus_access_was_wr && !is_write && ((pimpl->last_address & ~0x3) == (e.bus_addr & ~0x3)), // RAW
                    pimpl->last_dbus_access_was_wr && is_write && ((pimpl->last_address & ~0x3) == (e.bus_addr & ~0x3)),  // WAW
                    !pimpl->last_dbus_access_was_wr && is_write && ((pimpl->last_address & ~0x3) == (e.bus_addr & ~0x3))  // WAR
                };

                pimpl->dbus_cg.sample(hazard, e.bus_addr, is_write, e.bus_data.size());
                pimpl->last_dbus_access_was_wr = is_write;
            }
        }
    }
}

} // namespace components
