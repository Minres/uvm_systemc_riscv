#include "constr_instr_gen.h"
#include "regs_accessor.h"
#include <algorithm>
#include <csr.h>
#include <functional>
#include <instr.h>
#include <instr_encoding.h>
#include <scc/report.h>
#include <stdint.h>
#include <unordered_set>
#include <vector>

namespace seq {

#define RO_CSR_MASK 0xC00

constr_instr_gen::constr_instr_gen(std::string name)
: all_instructions({{254, {"RANDOM", 0b00000000000000000000000000000000, 0b00000000000000000000000000000000}},
                    {255, {"ILLEGAL", 0b11111111111111111111111111111111, 0b00000000000000000000000000000000}}})
, unsupported_csrs({// skip mstatus so that MIE is never set
                    rv32::csr::MSTATUS_ADDR, rv32::csr::MIP_ADDR, rv32::csr::USTATUS_ADDR, rv32::csr::UIP_ADDR, rv32::csr::PMPCFG0_ADDR,
                    rv32::csr::PMPCFG1_ADDR, rv32::csr::PMPCFG2_ADDR, rv32::csr::PMPCFG3_ADDR, rv32::csr::DCSR_ADDR}) {
    read_isa_config(aging::manager().get_group_map());
}

void constr_instr_gen::add_csr_to_ignore(unsigned addr) { unsupported_csrs.insert(addr); }

void constr_instr_gen::read_isa_config(std::unordered_map<std::string, std::vector<aging::instruction>> const& isa_config) {
    uint32_t lowest_instr_idx{std::numeric_limits<uint32_t>::max()};
    uint32_t highest_instr_idx{0};
    for(auto& subset : isa_config) {
        for(auto& instruction : subset.second) {
            instr_info info = instr_info();
            info.name = instruction.name.c_str();
            info.encoding = instruction.encoding;
            info.mask = instruction.mask;
            all_instructions[instruction.id] = info;
            if(instruction.id < lowest_instr_idx)
                lowest_instr_idx = instruction.id;
            if(instruction.id > highest_instr_idx)
                highest_instr_idx = instruction.id;

            if(instruction.disable || (instruction.name.find("reserved") != std::string::npos)) {
                skipped_instr.emplace_back(instruction.mask, instruction.encoding);
            }
        }
    }
    iconstr = new instr_constr(lowest_instr_idx, highest_instr_idx, num_regs);
}

bool constr_instr_gen::is_unsupported(uint32_t x) {
    auto it = std::find_if(std::begin(skipped_instr), std::end(skipped_instr),
                           [x](std::pair<uint32_t, uint32_t> const& p) { return (x & p.first) == (p.second); });
    if(it != std::end(skipped_instr))
        return true;

    Instruction i(x);
    bool is_csr = false;

    if(((x & CSRRW_MASK) == CSRRW_ENCODING)) {
        is_csr = true;
    } else if(((x & CSRRS_MASK) == CSRRS_ENCODING)) {
        is_csr = true;
    } else if(((x & CSRRC_MASK) == CSRRC_ENCODING)) {
        is_csr = true;
    } else if(((x & CSRRWI_MASK) == CSRRWI_ENCODING)) {
        is_csr = true;
    } else if(((x & CSRRSI_MASK) == CSRRSI_ENCODING)) {
        is_csr = true;
    } else if(((x & CSRRCI_MASK) == CSRRCI_ENCODING)) {
        is_csr = true;
    }

    if(is_csr) {
        auto csr = i.csr();
        if(unsupported_csrs.find(csr) != unsupported_csrs.end())
            return true;
        switch(csr) {
        case rv32::csr::MCYCLE_ADDR:
        case rv32::csr::MCYCLEH_ADDR:
        case rv32::csr::MINSTRET_ADDR:
        case rv32::csr::MINSTRETH_ADDR:
        case rv32::csr::CYCLE_ADDR:
        case rv32::csr::CYCLEH_ADDR:
        case rv32::csr::INSTRET_ADDR:
        case rv32::csr::INSTRETH_ADDR:
        case rv32::csr::TIME_ADDR:
        case rv32::csr::TIMEH_ADDR:
            // NOTE: time and cycles will differ on ISS and RTL core, so only access cycles if result is dropped
            return i.rd() != 0;
        }
    }
    return false;
}

uint32_t constr_instr_gen::next(uint64_t addr) {
    crave::randv<int32_t> imm;
    crave::Generator gen;
    auto adr_offset = regs_len / 8;
    uint64_t rs1_val{0};

    for(;;) {
        CHECK(iconstr->next());

        auto& s = all_instructions.at(iconstr->instr_idx);
        uint32_t r = scc::MT19937::uniform<uint32_t>();
        uint32_t x = (r & ~s.mask) | s.encoding;

        Instruction instr(x);
        switch(s.encoding) {
        case JAL_ENCODING:
            gen(imm() % adr_offset == 0 && imm() != 0); // don't jumps to self to avoid endless loop
            gen.next();
            instr.set_J_imm(imm);
            instr.set_rd(iconstr->rd);
            break;
        case JALR_ENCODING:
            gen((imm() + regs_accessor->get_reg(iconstr->rs1)) % adr_offset == 0);
            gen.next();
            instr.set_I_imm(imm);
            instr.set_rd(iconstr->rd);
            instr.set_rs1(iconstr->rs1);
            break;
        case BEQ_ENCODING:
        case BNE_ENCODING:
        case BLT_ENCODING:
        case BLTU_ENCODING:
        case BGE_ENCODING:
        case BGEU_ENCODING:
            instr.set_B_imm(iconstr->addr); // TODO:ensure leaving the cache
            instr.set_rd(iconstr->rd);
            instr.set_rs1(iconstr->rs1);
            instr.set_rs2(iconstr->rs2);
            break;
        case LW_ENCODING:
            gen((imm() + regs_accessor->get_reg(iconstr->rs1)) % adr_offset == 0);
            gen.next();
            instr.set_I_imm(imm);
            instr.set_rd(iconstr->rd);
            instr.set_rs1(iconstr->rs1);
            break;
        case LH_ENCODING:
        case LHU_ENCODING:
            rs1_val = regs_accessor->get_reg(iconstr->rs1);
            gen((imm() + rs1_val) % 2 == 0);
            gen.next();
            SCCDEBUG("Instr Gen") << "Load imm: " << imm << " rs1 :" << iconstr->rs1 << " base " << rs1_val;
            instr.set_I_imm(imm);
            instr.set_rd(iconstr->rd);
            instr.set_rs1(iconstr->rs1);
            break;
        case LB_ENCODING:
        case LBU_ENCODING:
            instr.set_I_imm(iconstr->addr);
            instr.set_rd(iconstr->rd);
            instr.set_rs1(iconstr->rs1);
            break;
        case SW_ENCODING:
            // Stores the value in register rs2 to memory
            rs1_val = regs_accessor->get_reg(iconstr->rs1);
            gen((imm() + rs1_val) % adr_offset == 0);
            gen.next();
            SCCDEBUG("Instr Gen") << "Store imm: " << imm << " rs1 :" << iconstr->rs1 << " base " << rs1_val;

            instr.set_S_imm(imm);
            instr.set_rs1(iconstr->rs1);
            instr.set_rs2(iconstr->rs2);
            break;
        case SH_ENCODING:
            gen((imm() + regs_accessor->get_reg(iconstr->rs1)) % 2 == 0);
            gen.next();
            instr.set_S_imm(imm);
            instr.set_rs1(iconstr->rs1);
            instr.set_rs2(iconstr->rs2);
            break;
        case SB_ENCODING:
            instr.set_S_imm(iconstr->addr);
            instr.set_rs1(iconstr->rs1);
            instr.set_rs2(iconstr->rs2);
            break;
        case C_LW_ENCODING:
        case C_SW_ENCODING:
            if((regs_accessor->get_reg(iconstr->c_rs1) + iconstr->addr) % adr_offset != 0)
                continue; // skip if the RS1' value is not word aligned
            instr.set_c_LW_imm(iconstr->addr);
            instr.set_c_rs2_small(iconstr->c_rs2);
            instr.set_c_rs1_small(iconstr->c_rs1);
            break;
        case C_LWSP_ENCODING:
        case C_SWSP_ENCODING:
            if(regs_accessor->get_reg(2) % adr_offset != 0 || instr.rd() == 0)
                continue; // skip if the Stack Pointer value is not word aligned
            break;
        case CSRRW_ENCODING:
        case CSRRWI_ENCODING:
        case CSRRS_ENCODING:
        case CSRRC_ENCODING:
            do {
                CHECK(csrconstr.next());
            } while((csrconstr.get_csr_addr() & RO_CSR_MASK) == RO_CSR_MASK);
            instr.set_csr(csrconstr.get_csr_addr());
            instr.set_rs1(iconstr->rs1);
            instr.set_rd(iconstr->rd);
            break;
        case CSRRSI_ENCODING:
        case CSRRCI_ENCODING:
            CHECK(csrconstr.next());
            instr.set_csr(csrconstr.get_csr_addr());
            instr.set_rs1(0);
            instr.set_rd(iconstr->rd);
            break;
        case C_ADDI4SPN_ENCODING:
            if(C_ADDI4SPN_NZUIMM(instr.data()) == 0)
                continue; // only valid when nzuimm≠0
            break;
        case MRET_ENCODING:
        case URET_ENCODING:
        case SRET_ENCODING:
        case WFI_ENCODING:
            continue; // unsupported instruction
        case EBREAK_ENCODING:
        case ECALL_ENCODING:
        case C_EBREAK_ENCODING:
            continue; // TODO:avoid traps for now, because ISS does not count them as instructions
        default:
            break;
        }

        if(!is_unsupported(instr.data())) {
            SCCDEBUG("Instr Gen") << "Next RND Instr: " << iconstr->instr_idx << " name " << s.name;
            iconstr->update_addr_list(iconstr->addr);
            return instr.data();
        }
    };
    return 0;
}

void constr_instr_gen::setup_regs(uint8_t* regs, uint32_t rfs, uint32_t len) {
    if(len == 64) {
        regs_accessor = std::make_unique<regs_accessor_64>(regs);
    } else {
        regs_accessor = std::make_unique<regs_accessor_32>(regs);
    }
    num_regs = rfs;
    regs_len = len;
}

} // namespace seq
