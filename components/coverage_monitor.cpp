/*
 * coverage_monitor.cpp
 *
 *  Created on: Jun 18, 2022
 *      Author: eyck
 */

#include "components/coverage_monitor.h"
#include "components/coverage_monitor/instr.h"
#include <cstdlib>
#include <cstdint>
#include <fc4sc.hpp>
#include <scc/report.h>
#include <types.h>
#include <systemc>
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
struct illegal_coverage : public covergroup {
    CG_CONS(illegal_coverage) {}

    uint64_t inst_s{0};
    void sample(uint32_t inst) {
        this->inst_s = inst;
        covergroup::sample();
    }

    COVERPOINT(uint64_t, inst, inst_s){bin_array<uint64_t>("illegal_instr", 64, interval(u32_limits::min(), u32_limits::max()))};
};

struct trap_coverage : public covergroup {
    CG_CONS(trap_coverage) {}

    int trap_id_s{0};
    void sample(int trap_id) {
        this->trap_id_s = trap_id;
        covergroup::sample();
    }

    COVERPOINT(int, trap_id, trap_id_s){fc4sc::bin<int>("Instruction address misaligned", 0),
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
                                        fc4sc::bin<int>("Store/AMO page fault", 15)};
};

struct no_regular_type_coverage : public covergroup {
    CG_CONS(no_regular_type_coverage) {}

    int32_t hit_s{0};
    void sample() {
        this->hit_s++;
        covergroup::sample();
    }

    COVERPOINT(int32_t, hit, hit_s){
        fc4sc::bin<int32_t>("hit", 1),
    };
};

struct u_type_coverage : public covergroup {
    CG_CONS(u_type_coverage) {}

    bool waw_hazard_s{false};
    uint32_t rd_s{0};
    int32_t imm20_s{0};
    void sample(bool waw_hazard, uint32_t rd, int32_t imm20) {
        this->waw_hazard_s = waw_hazard;
        this->rd_s = rd;
        this->imm20_s = imm20;
        covergroup::sample();
    }
    COVERPOINT(int32_t, imm20, imm20_s){fc4sc::bin<int32_t>("umin", 0),
                                        fc4sc::bin<int32_t>("spos", interval(1, 0x7fffe)),
                                        fc4sc::bin<int32_t>("smax", 0x7ffff),
                                        fc4sc::bin<int32_t>("smin", 0xfff80000),
                                        fc4sc::bin<int32_t>("sneg", interval(0xfff80001, 0xfffffffe)),
                                        fc4sc::bin<int32_t>("umax", 0xffffffff)};
    COVERPOINT(uint32_t, rd, rd_s){bin_array<uint32_t>("rd", 32, interval(0U, 31U))};
    COVERPOINT(bool, waw_hazard, waw_hazard_s){bin<bool>("no", false), bin<bool>("yes", true)};

    cross<int32_t, uint32_t> rd_imm20_cross = cross<int32_t, uint32_t>(this, "rd_imm20", &imm20, &rd);
};

struct i_type_coverage : public covergroup {
    CG_CONS(i_type_coverage) {}

    hazard_type hazard_s;
    uint32_t rd_s{0};
    uint32_t rs1_s{0};
    int32_t imm12_s{0};
    void sample(hazard_type hazard, uint32_t rd, uint32_t rs1, int32_t imm12) {
        this->hazard_s = hazard;
        this->rd_s = rd;
        this->rs1_s = rs1;
        this->imm12_s = imm12;
        covergroup::sample();
    }

    COVERPOINT(uint32_t, rd, rd_s){bin_array<uint32_t>("rd", 32, interval(0U, 31U))};
    COVERPOINT(uint32_t, rs1, rs1_s){bin_array<uint32_t>("rs1", 32, interval(0U, 31U))};
    COVERPOINT(bool, raw_hazard, hazard_s.raw){bin<bool>("no", false), bin<bool>("yes", true)};
    COVERPOINT(bool, waw_hazard, hazard_s.waw){bin<bool>("no", false), bin<bool>("yes", true)};
    COVERPOINT(bool, war_hazard, hazard_s.war){bin<bool>("no", false), bin<bool>("yes", true)};
    COVERPOINT(int32_t, imm12, imm12_s){
        fc4sc::bin<int32_t>("umin", 0),     fc4sc::bin<int32_t>("spos", interval(1, 2046)),   fc4sc::bin<int32_t>("smax", 2047),
        fc4sc::bin<int32_t>("smin", 12048), fc4sc::bin<int32_t>("sneg", interval(12047, -2)), fc4sc::bin<int32_t>("umax", -1)};

    cross<uint32_t, uint32_t> reg_cross = cross<uint32_t, uint32_t>(this, "rd_rs", &rs1, &rd);
};

struct ci_type_coverage : public covergroup {

    static inline std::vector<uint32_t> get_interval() {
        std::vector<uint32_t> ret = {0U, 1U};
        for(auto idx = 3U; idx < 32; idx++)
            ret.push_back(idx);
        return ret;
    }
    enum rd_type { FULL, NO_X0, ONLY_X0, NO_X2, ONLY_X2 };
    CG_CONS(ci_type_coverage, unsigned var = FULL)
    , rd(covergroup::register_cvp<uint32_t>(
          &rd, "rd", [this]() -> uint32_t { return (rd_s); }, "rd_s", [this]() -> bool { return (true); }, std::string(""))) {
        switch(var) {
        case FULL:
            rd = coverpoint<uint32_t>{bin_array<uint32_t>("rd", 32, interval(0U, 31U))};
            break;
        case NO_X0:
            rd = coverpoint<uint32_t>{bin_array<uint32_t>("rd", 31, interval(1U, 31U))};
            break;
        case ONLY_X0:
            rd = coverpoint<uint32_t>{bin_array<uint32_t>("rd", 1, interval(0U, 0U))};
            break;
        case NO_X2:
            rd = coverpoint<uint32_t>{bin_array<uint32_t>("rd", get_interval())};
            break;
        case ONLY_X2:
            rd = coverpoint<uint32_t>{bin_array<uint32_t>("rd", 1, interval(2U, 2U))};
            break;
        }
    }

    bool waw_hazard_s{false};
    uint32_t rd_s{0};
    uint32_t imm6_s{0};
    void sample(bool waw_hazard, uint32_t rd, uint32_t imm6) {
        this->waw_hazard_s = waw_hazard;
        this->rd_s = rd;
        this->imm6_s = imm6;
        covergroup::sample();
    }

    coverpoint<uint32_t> rd;

    COVERPOINT(bool, waw_hazard, waw_hazard_s){bin<bool>("no", false), bin<bool>("yes", true)};
    COVERPOINT(uint32_t, imm6,
               imm6_s){fc4sc::bin<uint32_t>("umin", 0),  fc4sc::bin<uint32_t>("spos", interval(1, 30)),  fc4sc::bin<uint32_t>("smax", 31),
                       fc4sc::bin<uint32_t>("smin", 32), fc4sc::bin<uint32_t>("sneg", interval(33, 62)), fc4sc::bin<uint32_t>("umax", 63)};
};

struct ciw_type_coverage : public covergroup {
    CG_CONS(ciw_type_coverage) {}

    bool waw_hazard_s{false};
    uint32_t rdt_s{0};
    uint32_t imm8_s{0};
    void sample(bool waw_hazard, uint32_t rdt, uint32_t imm8) {
        this->waw_hazard_s = waw_hazard;
        this->rdt_s = rdt;
        this->imm8_s = imm8;
        covergroup::sample();
    }

    COVERPOINT(uint32_t, rdt, rdt_s){bin_array<uint32_t>("rdt", 8, interval(8U, 15U))};
    COVERPOINT(bool, waw_hazard, waw_hazard_s){bin<bool>("no", false), bin<bool>("yes", true)};
    COVERPOINT(uint32_t, imm8, imm8_s){
        fc4sc::bin<uint32_t>("umin", 0),   fc4sc::bin<uint32_t>("spos", interval(1, 126)),   fc4sc::bin<uint32_t>("smax", 127),
        fc4sc::bin<uint32_t>("smin", 128), fc4sc::bin<uint32_t>("sneg", interval(129, 254)), fc4sc::bin<uint32_t>("umax", 255)};
};

struct cl_type_coverage : public covergroup {
    CG_CONS(cl_type_coverage) {}

    hazard_type hazard_s;
    uint32_t rdt_s{0};
    uint32_t imm5_s{0};
    void sample(hazard_type hazard, uint32_t rs1t, uint32_t rdt, uint32_t imm5) {
        this->hazard_s = hazard;
        this->rdt_s = rdt;
        this->imm5_s = imm5;
        covergroup::sample();
    }

    COVERPOINT(uint32_t, rdt, rdt_s){bin_array<uint32_t>("rdt", 8, interval(8U, 15U))};
    COVERPOINT(bool, raw_hazard, hazard_s.raw){bin<bool>("no", false), bin<bool>("yes", true)};
    COVERPOINT(bool, waw_hazard, hazard_s.waw){bin<bool>("no", false), bin<bool>("yes", true)};
    COVERPOINT(bool, war_hazard, hazard_s.war){bin<bool>("no", false), bin<bool>("yes", true)};
    COVERPOINT(uint32_t, imm5,
               imm5_s){fc4sc::bin<uint32_t>("umin", 0),  fc4sc::bin<uint32_t>("spos", interval(1, 14)),  fc4sc::bin<uint32_t>("smax", 15),
                       fc4sc::bin<uint32_t>("smin", 16), fc4sc::bin<uint32_t>("sneg", interval(17, 30)), fc4sc::bin<uint32_t>("umax", 31)};
};

struct i2_type_coverage : public covergroup {
    CG_CONS(i2_type_coverage) {}

    bool waw_hazard_s{false};
    uint32_t rd_s{0};
    uint32_t uimm5_s{0};
    int32_t imm12_s{0};
    void sample(bool waw_hazard, uint32_t rd, uint32_t uimm5, int32_t imm12) {
        this->waw_hazard_s = waw_hazard;
        this->rd_s = rd;
        this->uimm5_s = uimm5;
        this->imm12_s = imm12;
        covergroup::sample();
    }

    COVERPOINT(uint32_t, rd, rd_s){bin_array<uint32_t>("rd", 32, interval(0U, 31U))};
    COVERPOINT(uint32_t, uimm5, uimm5_s){bin_array<uint32_t>("uimm", 32, interval(0U, 31U))};
    COVERPOINT(int32_t, imm12, imm12_s){
        fc4sc::bin<int32_t>("umin", 0),     fc4sc::bin<int32_t>("spos", interval(1, 2046)),  fc4sc::bin<int32_t>("smax", 2047),
        fc4sc::bin<int32_t>("smin", -2048), fc4sc::bin<int32_t>("sneg", interval(2047, -2)), fc4sc::bin<int32_t>("umax", -1)};
    COVERPOINT(bool, waw_hazard, waw_hazard_s){bin<bool>("no", false), bin<bool>("yes", true)};

    cross<uint32_t, uint32_t> reg_cross = cross<uint32_t, uint32_t>(this, "rd_uimm", &uimm5, &rd);
};

struct s_type_coverage : public covergroup {
    CG_CONS(s_type_coverage) {}

    bool raw_hazard_s{false};
    uint32_t rs1_s{0};
    uint32_t rs2_s{0};
    int32_t imm12_s{0};
    void sample(bool raw_hazard, uint32_t rs1, uint32_t rs2, int32_t imm12) {
        this->raw_hazard_s = raw_hazard;
        this->rs1_s = rs1;
        this->rs2_s = rs2;
        this->imm12_s = imm12;
        covergroup::sample();
    }

    COVERPOINT(uint32_t, rs1, rs1_s){bin_array<uint32_t>("rs1", 32, interval(0U, 31U))};
    COVERPOINT(uint32_t, rs2, rs2_s){bin_array<uint32_t>("rd", 32, interval(0U, 31U))};
    COVERPOINT(bool, raw_hazard, raw_hazard_s){bin<bool>("no", false), bin<bool>("yes", false)};
    COVERPOINT(int32_t, imm12, imm12_s){
        fc4sc::bin<int32_t>("umin", 0),     fc4sc::bin<int32_t>("spos", interval(1, 2046)),   fc4sc::bin<int32_t>("smax", 2047),
        fc4sc::bin<int32_t>("smin", -2048), fc4sc::bin<int32_t>("sneg", interval(-2047, -2)), fc4sc::bin<int32_t>("umax", -1)};

    cross<uint32_t, uint32_t> reg_cross = cross<uint32_t, uint32_t>(this, "rs1_rs2", &rs2, &rs1);
};

struct css_type_coverage : public covergroup {
    CG_CONS(css_type_coverage) {}

    bool raw_hazard_s{false};
    uint32_t rs2_s{0};
    uint32_t imm6_s{0};
    void sample(bool raw_hazard, uint32_t rs2, uint32_t imm6) {
        this->raw_hazard_s = raw_hazard;
        this->rs2_s = rs2;
        this->imm6_s = imm6;
        covergroup::sample();
    }

    COVERPOINT(uint32_t, rs2, rs2_s){bin_array<uint32_t>("rd", 32, interval(0U, 31U))};
    COVERPOINT(bool, raw_hazard, raw_hazard_s){bin<bool>("no", false), bin<bool>("yes", false)};
    COVERPOINT(uint32_t, imm6,
               imm6_s){fc4sc::bin<uint32_t>("umin", 0),  fc4sc::bin<uint32_t>("spos", interval(1, 30)),  fc4sc::bin<uint32_t>("smax", 31),
                       fc4sc::bin<uint32_t>("smin", 32), fc4sc::bin<uint32_t>("sneg", interval(33, 62)), fc4sc::bin<uint32_t>("umax", 63)};
};

struct cs_type_coverage : public covergroup {
    CG_CONS(cs_type_coverage) {}

    bool raw_hazard_s{false};
    uint32_t rs1t_s{0};
    uint32_t rs2t_s{0};
    uint32_t imm5_s{0};
    void sample(bool raw_hazard, uint32_t rs1t, uint32_t rs2t, uint32_t imm5) {
        this->raw_hazard_s = raw_hazard;
        this->rs1t_s = rs1t;
        this->rs2t_s = rs2t;
        this->imm5_s = imm5;
        covergroup::sample();
    }

    COVERPOINT(uint32_t, rs1t, rs1t_s){bin_array<uint32_t>("rs1t", 8, interval(8U, 15U))};
    COVERPOINT(uint32_t, rs2t, rs2t_s){bin_array<uint32_t>("rs2t", 8, interval(8U, 15U))};
    COVERPOINT(bool, raw_hazard, raw_hazard_s){bin<bool>("no", false), bin<bool>("yes", false)};
    COVERPOINT(uint32_t, imm5,
               imm5_s){fc4sc::bin<uint32_t>("umin", 0),  fc4sc::bin<uint32_t>("spos", interval(1, 14)),  fc4sc::bin<uint32_t>("smax", 15),
                       fc4sc::bin<uint32_t>("smin", 16), fc4sc::bin<uint32_t>("sneg", interval(17, 30)), fc4sc::bin<uint32_t>("umax", 31)};

    cross<uint32_t, uint32_t> reg_cross = cross<uint32_t, uint32_t>(this, "rs1t_rs2t", &rs2t, &rs1t);
};

struct r_type_coverage : public covergroup {
    CG_CONS(r_type_coverage) {}

    hazard_type hazard_s;
    uint32_t rd_s{0};
    uint32_t rs1_s{0};
    uint32_t rs2_s{0};
    void sample(hazard_type hazard, uint32_t rd, uint32_t rs1, uint32_t rs2) {
        this->hazard_s = hazard;
        this->rd_s = rd;
        this->rs1_s = rs1;
        this->rs2_s = rs2;
        covergroup::sample();
    }

    COVERPOINT(uint32_t, rd, rd_s){bin_array<uint32_t>("rd", 32, interval(0U, 31U))};
    COVERPOINT(uint32_t, rs1, rs1_s){bin_array<uint32_t>("rs1", 32, interval(0U, 31U))};
    COVERPOINT(uint32_t, rs2, rs2_s){bin_array<uint32_t>("rs2", 32, interval(0U, 31U))};
    COVERPOINT(bool, raw, hazard_s.raw){bin<bool>("no", false), bin<bool>("yes", true)};
    COVERPOINT(bool, waw, hazard_s.waw){bin<bool>("no", false), bin<bool>("yes", true)};
    COVERPOINT(bool, war, hazard_s.war){bin<bool>("no", false), bin<bool>("yes", true)};

    cross<uint32_t, uint32_t> rd_rs1_cross = cross<uint32_t, uint32_t>(this, "rd_rs1", &rs1, &rd);
    cross<uint32_t, uint32_t> rd_rs2_cross = cross<uint32_t, uint32_t>(this, "rd_rs2", &rs2, &rd);
    cross<uint32_t, uint32_t> rs1_rs2_cross = cross<uint32_t, uint32_t>(this, "rs1_rs2", &rs2, &rs1);
};

struct cr_type_coverage : public covergroup {
    enum rd_type { FULL = 0, NO_RD0 = 1, ONLY_RD0 = 2, NO_RS2_0 = 4, ONLY_RS2_0 = 8 };
    CG_CONS(cr_type_coverage, unsigned var = FULL)
    ,
        rd(covergroup::register_cvp<uint32_t>(
            &rd, "rd", [this]() -> uint32_t { return (rd_s); }, "rd_s", [this]() -> bool { return (true); }, std::string(""))),
        rs2(covergroup::register_cvp<uint32_t>(
            &rs2, "rs2", [this]() -> uint32_t { return (rs2_s); }, "rs2_s", [this]() -> bool { return (true); }, std::string(""))) {
        if(var & NO_RD0)
            rd = coverpoint<uint32_t>{bin_array<uint32_t>("rd", 31, interval(1U, 31U))};
        else if(var & ONLY_RD0)
            rd = coverpoint<uint32_t>{bin_array<uint32_t>("rd", 1, interval(0U, 0U))};
        else
            rd = coverpoint<uint32_t>{bin_array<uint32_t>("rd", 32, interval(0U, 31U))};

        if(var & NO_RS2_0)
            rs2 = coverpoint<uint32_t>{bin_array<uint32_t>("rs2", 31, interval(1U, 31U))};
        else if(var & ONLY_RS2_0)
            rs2 = coverpoint<uint32_t>{bin_array<uint32_t>("rs2", 1, interval(0U, 0U))};
        else
            rs2 = coverpoint<uint32_t>{bin_array<uint32_t>("rs2", 32, interval(0U, 31U))};
    }

    hazard_type hazard_s;
    uint32_t rd_s{0};
    uint32_t rs2_s{0};
    void sample(hazard_type hazard, uint32_t rd, uint32_t rs2) {
        this->hazard_s = hazard;
        this->rd_s = rd;
        this->rs2_s = rs2;
        covergroup::sample();
    }

    coverpoint<uint32_t> rd;

    coverpoint<uint32_t> rs2;

    COVERPOINT(bool, raw, hazard_s.raw){bin<bool>("no", false), bin<bool>("yes", true)};
    COVERPOINT(bool, waw, hazard_s.waw){bin<bool>("no", false), bin<bool>("yes", true)};

    cross<uint32_t, uint32_t> rd_rs2_cross = cross<uint32_t, uint32_t>(this, "rd_rs2", &rs2, &rd);
};

struct ca_type_coverage : public covergroup {
    CG_CONS(ca_type_coverage) {}

    hazard_type hazard_s;
    uint32_t rdt_s{0};
    uint32_t rs2t_s{0};
    void sample(hazard_type hazard, uint32_t rdt, uint32_t rs2t) {
        this->hazard_s = hazard;
        this->rdt_s = rdt;
        this->rs2t_s = rs2t;
        covergroup::sample();
    }

    COVERPOINT(uint32_t, rdt, rdt_s){bin_array<uint32_t>("rdt", 8, interval(8U, 15U))};
    COVERPOINT(uint32_t, rs2t, rs2t_s){bin_array<uint32_t>("rs2t", 8, interval(8U, 15U))};
    COVERPOINT(bool, raw, hazard_s.raw){bin<bool>("no", false), bin<bool>("yes", true)};
    COVERPOINT(bool, waw, hazard_s.waw){bin<bool>("no", false), bin<bool>("yes", true)};
    COVERPOINT(bool, war, hazard_s.war){bin<bool>("no", false), bin<bool>("yes", true)};

    cross<uint32_t, uint32_t> rd_rs2_cross = cross<uint32_t, uint32_t>(this, "rd_rs2", &rs2t, &rdt);
};

struct b_type_coverage : public covergroup {
    CG_CONS(b_type_coverage) {}

    bool raw_hazard_s{false};
    uint32_t rs1_s{0};
    uint32_t rs2_s{0};
    uint32_t imm12_s{0};
    void sample(bool raw_hazard, uint32_t rs1, uint32_t rs2, uint32_t imm12) {
        this->raw_hazard_s = raw_hazard;
        this->rs1_s = rs1;
        this->rs2_s = rs2;
        this->imm12_s = imm12;
        covergroup::sample();
    }

    COVERPOINT(uint32_t, rs1, rs1_s){bin_array<uint32_t>("rs1", 32, interval(0U, 31U))};
    COVERPOINT(uint32_t, rs2, rs2_s){bin_array<uint32_t>("rd", 32, interval(0U, 31U))};
    COVERPOINT(bool, raw_hazard, raw_hazard_s){bin<bool>("no", false), bin<bool>("yes", false)};
    COVERPOINT(uint32_t, imm12, imm12_s){
        fc4sc::bin<uint32_t>("umin", 0),    fc4sc::bin<uint32_t>("spos", interval(1, 2046)),    fc4sc::bin<uint32_t>("smax", 2047),
        fc4sc::bin<uint32_t>("smin", 2048), fc4sc::bin<uint32_t>("sneg", interval(2049, 4094)), fc4sc::bin<uint32_t>("umax", 4095)};

    cross<uint32_t, uint32_t> reg_cross = cross<uint32_t, uint32_t>(this, "rs1_rs2", &rs2, &rs1);
};

struct cb_type_coverage : public covergroup {
    CG_CONS(cb_type_coverage) {}

    bool raw_hazard_s{false};
    uint32_t rs1t_s{0};
    int8_t imm8_s{0};
    void sample(bool raw_hazard, uint32_t rs1t, int8_t offs8) {
        this->raw_hazard_s = raw_hazard;
        this->rs1t_s = rs1t;
        this->imm8_s = offs8;
        covergroup::sample();
    }

    COVERPOINT(uint32_t, rs1t, rs1t_s){bin_array<uint32_t>("rs1t", 8, interval(8U, 15U))};
    COVERPOINT(bool, raw_hazard, raw_hazard_s){bin<bool>("no", false), bin<bool>("yes", false)};
    COVERPOINT(int8_t, imm8,
               imm8_s){fc4sc::bin<int8_t>("umin", 0),    fc4sc::bin<int8_t>("spos", interval(1, 126)),   fc4sc::bin<int8_t>("smax", 127),
                       fc4sc::bin<int8_t>("smin", -128), fc4sc::bin<int8_t>("sneg", interval(-127, -2)), fc4sc::bin<int8_t>("umax", -1)};
};

struct j_type_coverage : public covergroup {
    CG_CONS(j_type_coverage) {}

    bool waw_hazard_s{false};
    uint32_t rd_s{0};
    int32_t imm20_s{0};
    void sample(bool waw_hazard, uint32_t rd, int32_t imm20) {
        this->waw_hazard_s = waw_hazard;
        this->rd_s = rd;
        this->imm20_s = imm20;
        covergroup::sample();
    }
    COVERPOINT(uint32_t, rd, rd_s){bin_array<uint32_t>("rd", 32, interval(0U, 31U))};
    COVERPOINT(int32_t, imm20, imm20_s){fc4sc::bin<int32_t>("umin", 0),
                                        fc4sc::bin<int32_t>("spos", interval(1, std::numeric_limits<int32_t>::max() - 1)),
                                        fc4sc::bin<int32_t>("smax", std::numeric_limits<int32_t>::max()),
                                        fc4sc::bin<int32_t>("smin", std::numeric_limits<int32_t>::min()),
                                        fc4sc::bin<int32_t>("sneg", interval(std::numeric_limits<int32_t>::min() + 1, -2)),
                                        fc4sc::bin<int32_t>("umax", -1)};
    COVERPOINT(bool, waw_hazard, waw_hazard_s){bin<bool>("no", false), bin<bool>("yes", true)};

    cross<int32_t, uint32_t> rd_imm20_cross = cross<int32_t, uint32_t>(this, "rd_imm20", &imm20, &rd);
};

struct cj_type_coverage : public covergroup {
    CG_CONS(cj_type_coverage) {}

    bool waw_hazard_s{false};
    uint32_t imm11_s{0};
    void sample(bool waw_hazard, uint32_t imm11) {
        this->waw_hazard_s = waw_hazard;
        this->imm11_s = imm11;
        covergroup::sample();
    }
    COVERPOINT(uint32_t, imm11, imm11_s){
        fc4sc::bin<uint32_t>("umin", 0),    fc4sc::bin<uint32_t>("spos", interval(1, 2022)),    fc4sc::bin<uint32_t>("smax", 1023),
        fc4sc::bin<uint32_t>("smin", 1024), fc4sc::bin<uint32_t>("sneg", interval(1025, 2046)), fc4sc::bin<uint32_t>("umax", 2047)};
    COVERPOINT(bool, waw_hazard, waw_hazard_s){bin<bool>("no", false), bin<bool>("yes", true)};
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

    COVERPOINT(uint64_t, addr, addr_s){bin_array<uint64_t>("segments", 16, interval(u32_limits::min(), u32_limits::max()))};
    COVERPOINT(int32_t, size, size_s){fc4sc::bin<int>("1B", 1), fc4sc::bin<int>("2B", 2), fc4sc::bin<int>("4B", 4),
                                      fc4sc::bin<int>("8B", 8)};
    COVERPOINT(int, rw, rw_s){fc4sc::bin<int>("wr", 1), fc4sc::bin<int>("rd", 0)};
    COVERPOINT(bool, raw, hazard_s.raw){bin<bool>("no", false), bin<bool>("yes", true)};
    COVERPOINT(bool, waw, hazard_s.waw){bin<bool>("no", false), bin<bool>("yes", true)};
    COVERPOINT(bool, war, hazard_s.war){bin<bool>("no", false), bin<bool>("yes", true)};

    cross<int32_t, int32_t> access_types_cross = cross<int32_t, int32_t>(this, "access_types", &size, &rw);
    cross<int32_t, int32_t, uint64_t> access_cross = cross<int32_t, int32_t, uint64_t>(this, "accesses", &size, &rw, &addr);
};

struct coverage_monitor::impl {
    unsigned last_written_reg = -1;
    uint64_t last_address = 0;
    bool last_dbus_access_was_wr = false;
    illegal_coverage ill_cg;
    dbus_access_coverage dbus_cg;
    trap_coverage trap_cg;
    using cg_variant_ptr =
        std::variant<std::unique_ptr<i_type_coverage>, std::unique_ptr<i2_type_coverage>, std::unique_ptr<u_type_coverage>,
                     std::unique_ptr<s_type_coverage>, std::unique_ptr<r_type_coverage>, std::unique_ptr<j_type_coverage>,
                     std::unique_ptr<b_type_coverage>, std::unique_ptr<no_regular_type_coverage>, std::unique_ptr<cr_type_coverage>,
                     std::unique_ptr<ci_type_coverage>, std::unique_ptr<css_type_coverage>, std::unique_ptr<ciw_type_coverage>,
                     std::unique_ptr<cl_type_coverage>, std::unique_ptr<cs_type_coverage>, std::unique_ptr<ca_type_coverage>,
                     std::unique_ptr<cb_type_coverage>, std::unique_ptr<cj_type_coverage>>;
    std::vector<cg_variant_ptr> cgs;
    struct instruction_pattern {
        uint32_t value;
        uint32_t mask;
        unsigned id;
        unsigned length;
    };

    std::array<std::vector<instruction_pattern>, 4> qlut;
    unsigned decode_instruction(uint32_t instr) {
        auto res = std::find_if(std::begin(qlut[instr & 0x3]), std::end(qlut[instr & 0x3]),
                                [instr](instruction_pattern const& e) { return !((instr & e.mask) ^ e.value); });
        return res != std::end(qlut[instr & 0x3]) ? res->id : std::numeric_limits<unsigned>::max();
    }

    using opcode_t = std::variant<Opcode::Mapping, Compressed::Opcode>;
    int prev_rd;
    void process(const exec_trace<traits::reg_t>& exc) {
        auto inst_id = decode_instruction(exc.fetch_value);
        if(exc.trap >= 0)
            trap_cg.sample(exc.trap /*, exc.insn*/);
        if(inst_id >= cgs.size()) {
            ill_cg.sample(exc.fetch_value);
            return;
        }
        Instruction instr(exc.fetch_value);
        auto opcode = instr.is_compressed() ? opcode_t(instr.decode_compressed(RV32)) : opcode_t(instr.decode_normal(RV32));
        switch(cgs[inst_id].index()) {
        case 0: { // std::unique_ptr<i_type_coverage>,
            hazard_type hazard{last_written_reg == instr.rs1(), last_written_reg == instr.rd(), instr.rd() == instr.rs1()};
            std::get<std::unique_ptr<i_type_coverage>>(cgs[inst_id])->sample(hazard, instr.rd(), instr.rs1(), instr.I_imm());
            prev_rd = instr.rd() ? instr.rd() : -1;
            last_written_reg = instr.rd();
        } break;
        case 1: { // std::unique_ptr<i2_type_coverage>,
            bool waw_hazard = last_written_reg == instr.rd();
            std::get<std::unique_ptr<i2_type_coverage>>(cgs[inst_id])->sample(waw_hazard, instr.rd(), /*uimm*/ instr.rs1(), instr.I_imm());
            prev_rd = instr.rd() ? instr.rd() : -1;
            last_written_reg = instr.rd();
        } break;
        case 2: { // std::unique_ptr<u_type_coverage>,
            bool waw_hazard = last_written_reg == instr.rd();
            std::get<std::unique_ptr<u_type_coverage>>(cgs[inst_id])->sample(waw_hazard, instr.rd(), instr.U_imm() >> 12);
            last_written_reg = instr.rd();
        } break;
        case 3: { // std::unique_ptr<s_type_coverage>,
            auto raw_hazard = last_written_reg == instr.rs1() || last_written_reg == instr.rs2();
            std::get<std::unique_ptr<s_type_coverage>>(cgs[inst_id])->sample(raw_hazard, instr.rs1(), instr.rs2(), instr.S_imm());
            last_written_reg = std::numeric_limits<unsigned>::max();
        } break;
        case 4: { // std::unique_ptr<r_type_coverage>,
            hazard_type hazard{last_written_reg == instr.rs1() || last_written_reg == instr.rs2(), last_written_reg == instr.rd(),
                               instr.rd() == instr.rs1() || instr.rd() == instr.rs2()};
            std::get<std::unique_ptr<r_type_coverage>>(cgs[inst_id])->sample(hazard, instr.rd(), instr.rs1(), instr.rs2());
            last_written_reg = instr.rd();
        } break;
        case 5: { // std::unique_ptr<j_type_coverage>,
            bool waw_hazard = last_written_reg == instr.rd();
            std::get<std::unique_ptr<j_type_coverage>>(cgs[inst_id])->sample(waw_hazard, instr.rd(), instr.J_imm());
            last_written_reg = instr.rd();
        } break;
        case 6: { // std::unique_ptr<b_type_coverage>,
            auto raw_hazard = last_written_reg == instr.rs1() || last_written_reg == instr.rs2();
            std::get<std::unique_ptr<b_type_coverage>>(cgs[inst_id])->sample(raw_hazard, instr.rs1(), instr.rs2(), instr.B_imm());
            last_written_reg = std::numeric_limits<unsigned>::max();
        } break;
        case 7: // std::unique_ptr<no_regular_type_coverage>,
            std::get<std::unique_ptr<no_regular_type_coverage>>(cgs[inst_id])->sample();
            last_written_reg = std::numeric_limits<unsigned>::max();
            break;
        case 8: { // std::unique_ptr<cr_type_coverage>,
            hazard_type hazard{last_written_reg == instr.c_rd() || last_written_reg == instr.c_rs2(), last_written_reg == instr.c_rd(),
                               true};
            std::get<std::unique_ptr<cr_type_coverage>>(cgs[inst_id])->sample(hazard, instr.c_rd(), instr.c_rs2());
            last_written_reg = instr.c_rd();
        } break;
        case 9: { // std::unique_ptr<ci_type_coverage>,
            auto waw_hazard = last_written_reg == instr.c_rd();
            std::get<std::unique_ptr<ci_type_coverage>>(cgs[inst_id])->sample(waw_hazard, instr.c_rd(), instr.ci_uimm());
            last_written_reg = instr.c_rd();
        } break;
        case 10: { // std::unique_ptr<css_type_coverage>,
            auto raw_hazard = last_written_reg == instr.c_rs2();
            std::get<std::unique_ptr<css_type_coverage>>(cgs[inst_id])->sample(raw_hazard, instr.c_rs2(), instr.css_uimm());
        } break;
        case 11: { // std::unique_ptr<ciw_type_coverage>,        {
            auto waw_hazard = last_written_reg == (instr.c_rs1_small() * 8);
            std::get<std::unique_ptr<ciw_type_coverage>>(cgs[inst_id])->sample(waw_hazard, instr.c_rs1_small(), instr.cwi_uimm());
            last_written_reg = instr.c_rs1_small() * 8;
        } break;
        case 12: { // std::unique_ptr<cl_type_coverage>,
            hazard_type hazard{last_written_reg == (instr.c_rs1_small() + 8) || last_written_reg == (instr.c_rs2_small() + 8),
                               last_written_reg == (instr.c_rs1_small() + 8), instr.c_rs1_small() == instr.c_rs2_small()};
            std::get<std::unique_ptr<cl_type_coverage>>(cgs[inst_id])
                ->sample(hazard, instr.c_rs1_small(), instr.c_rs2_small(), instr.cl_uimm());
            last_written_reg = instr.c_rs1_small() * 8;
        } break;
        case 13: { // std::unique_ptr<cs_type_coverage>,
            auto raw_hazard = last_written_reg == (instr.c_rs1_small() + 8) || last_written_reg == (instr.c_rs2() + 8);
            std::get<std::unique_ptr<cs_type_coverage>>(cgs[inst_id])
                ->sample(raw_hazard, instr.c_rs1_small(), instr.c_rs2(), instr.cl_uimm());
            last_written_reg = std::numeric_limits<unsigned>::max();
        } break;
        case 14: { // std::unique_ptr<ca_type_coverage>,
            hazard_type hazard{last_written_reg == (instr.c_rs1_small() + 8) || last_written_reg == (instr.c_rs2_small() + 8),
                               last_written_reg == (instr.c_rs1_small() + 8), instr.c_rs1_small() == instr.c_rs2_small()};
            std::get<std::unique_ptr<ca_type_coverage>>(cgs[inst_id])->sample(hazard, instr.c_rs1_small(), instr.c_rs2_small());
            last_written_reg = instr.c_rs1_small() * 8;
        } break;
        case 15: { // std::unique_ptr<cb_type_coverage>,
            auto raw_hazard = last_written_reg == (instr.c_rs1_small() + 8);
            std::get<std::unique_ptr<cb_type_coverage>>(cgs[inst_id])->sample(raw_hazard, instr.c_rs1_small(), instr.cb_uimm());
            last_written_reg = std::numeric_limits<unsigned>::max();
        } break;
        case 16: { // std::unique_ptr<cj_type_coverage>
            auto raw_hazard = last_written_reg == instr.rs1() || last_written_reg == instr.rs2();
            std::get<std::unique_ptr<cj_type_coverage>>(cgs[inst_id])->sample(raw_hazard, instr.cj_uimm());
            last_written_reg = std::get<Compressed::Opcode>(opcode) == Compressed::Opcode::C_JAL ? 1 : std::numeric_limits<unsigned>::max();
        } break;
        }
    }

    void parse_YAML_ISA(std::string isa_file) {
        YAML::Node config = YAML::LoadFile(isa_file);
        unsigned inst_id{0};
        for(auto const& p : config) {
            auto isa_subset = p.first;
            auto instructions = p.second;
            for(auto const& instruction_map : instructions) {
                std::string name = "";
                instruction_pattern inst;
                inst.id = instruction_map.second["index"].as<unsigned>();
                auto encoding = instruction_map.second["encoding"].as<std::string>();
                inst.value = std::strtol(encoding.substr(2).c_str(), nullptr, 2);
                inst.length = (encoding.length() - 2) / 8;
                auto mask = instruction_map.second["mask"].as<std::string>();
                inst.mask = std::strtol(mask.substr(2).c_str(), nullptr, 2);
                name = instruction_map.first.as<std::string>();
                auto itype = inst.length == 2 ? Opcode::getCType(Instruction(inst.value | (0x5555 & ~inst.mask)).decode_compressed(RV32))
                                              : getType(Instruction(inst.value | (0x55555555 & ~inst.mask)).decode_normal(RV32));
                if(itype == Opcode::Type::UNKNOWN) {
                    itype = getType(Instruction(inst.value | (~inst.mask)).decode(RV32));
                }
                switch(itype) {
                default:
                    cgs.emplace_back(std::make_unique<no_regular_type_coverage>(name));
                    std::get<std::unique_ptr<no_regular_type_coverage>>(cgs.back())->option.per_instance = true;
                    break;
                case Opcode::Type::I:
                    cgs.emplace_back(std::make_unique<i_type_coverage>(name));
                    std::get<std::unique_ptr<i_type_coverage>>(cgs.back())->option.per_instance = true;
                    break;
                case Opcode::Type::I2:
                    cgs.emplace_back(std::make_unique<i2_type_coverage>(name));
                    std::get<std::unique_ptr<i2_type_coverage>>(cgs.back())->option.per_instance = true;
                    break;
                case Opcode::Type::U:
                    cgs.emplace_back(std::make_unique<u_type_coverage>(name));
                    std::get<std::unique_ptr<u_type_coverage>>(cgs.back())->option.per_instance = true;
                    break;
                case Opcode::Type::S:
                    cgs.emplace_back(std::make_unique<s_type_coverage>(name));
                    std::get<std::unique_ptr<s_type_coverage>>(cgs.back())->option.per_instance = true;
                    break;
                case Opcode::Type::R:
                    cgs.emplace_back(std::make_unique<r_type_coverage>(name));
                    std::get<std::unique_ptr<r_type_coverage>>(cgs.back())->option.per_instance = true;
                    break;
                case Opcode::Type::J:
                    cgs.emplace_back(std::make_unique<j_type_coverage>(name));
                    std::get<std::unique_ptr<j_type_coverage>>(cgs.back())->option.per_instance = true;
                    break;
                case Opcode::Type::B:
                    cgs.emplace_back(std::make_unique<b_type_coverage>(name));
                    std::get<std::unique_ptr<b_type_coverage>>(cgs.back())->option.per_instance = true;
                    break;
                case Opcode::Type::CR:
                    if(name == "C__JR")
                        cgs.emplace_back(std::make_unique<cr_type_coverage>(name, cr_type_coverage::NO_RD0 | cr_type_coverage::ONLY_RS2_0));
                    else if(name == "C__MV")
                        cgs.emplace_back(std::make_unique<cr_type_coverage>(name, cr_type_coverage::NO_RS2_0));
                    else if(name == "C__ADD")
                        cgs.emplace_back(std::make_unique<cr_type_coverage>(name, cr_type_coverage::NO_RS2_0));
                    else if(name == "C__EBREAK")
                        cgs.emplace_back(
                            std::make_unique<cr_type_coverage>(name, cr_type_coverage::ONLY_RD0 | cr_type_coverage::ONLY_RS2_0));
                    else if(name == "C__JALR")
                        cgs.emplace_back(std::make_unique<cr_type_coverage>(name, cr_type_coverage::NO_RD0 | cr_type_coverage::ONLY_RS2_0));
                    else
                        cgs.emplace_back(std::make_unique<cr_type_coverage>(name));
                    std::get<std::unique_ptr<cr_type_coverage>>(cgs.back())->option.per_instance = true;
                    break;
                case Opcode::Type::CI:
                    if(name == "C__NOP")
                        cgs.emplace_back(std::make_unique<ci_type_coverage>(name, ci_type_coverage::ONLY_X0));
                    else if(name == "C__ADDI")
                        cgs.emplace_back(std::make_unique<ci_type_coverage>(name, ci_type_coverage::NO_X0));
                    else if(name == "C__ADDI16SP")
                        cgs.emplace_back(std::make_unique<ci_type_coverage>(name, ci_type_coverage::ONLY_X2));
                    else if(name == "C__LUI")
                        cgs.emplace_back(std::make_unique<ci_type_coverage>(name, ci_type_coverage::NO_X2));
                    else
                        cgs.emplace_back(std::make_unique<ci_type_coverage>(name));
                    std::get<std::unique_ptr<ci_type_coverage>>(cgs.back())->option.per_instance = true;
                    break;
                case Opcode::Type::CIW:
                    cgs.emplace_back(std::make_unique<ciw_type_coverage>(name));
                    std::get<std::unique_ptr<ciw_type_coverage>>(cgs.back())->option.per_instance = true;
                    break;
                case Opcode::Type::CSS:
                    cgs.emplace_back(std::make_unique<css_type_coverage>(name));
                    std::get<std::unique_ptr<css_type_coverage>>(cgs.back())->option.per_instance = true;
                    break;
                case Opcode::Type::CL:
                    cgs.emplace_back(std::make_unique<cl_type_coverage>(name));
                    std::get<std::unique_ptr<cl_type_coverage>>(cgs.back())->option.per_instance = true;
                    break;
                case Opcode::Type::CS:
                    cgs.emplace_back(std::make_unique<cs_type_coverage>(name));
                    std::get<std::unique_ptr<cs_type_coverage>>(cgs.back())->option.per_instance = true;
                    break;
                case Opcode::Type::CA:
                    cgs.emplace_back(std::make_unique<ca_type_coverage>(name));
                    std::get<std::unique_ptr<ca_type_coverage>>(cgs.back())->option.per_instance = true;
                    break;
                case Opcode::Type::CB:
                    cgs.emplace_back(std::make_unique<cb_type_coverage>(name));
                    std::get<std::unique_ptr<cb_type_coverage>>(cgs.back())->option.per_instance = true;
                    break;
                case Opcode::Type::CJ:
                    cgs.emplace_back(std::make_unique<cj_type_coverage>(name));
                    std::get<std::unique_ptr<cj_type_coverage>>(cgs.back())->option.per_instance = true;
                    break;
                }
                qlut[inst.value & 0x3].emplace_back(inst);
                inst_id++;
            }
        }
        for(auto& lut : qlut) {
            std::sort(std::begin(lut), std::end(lut), [](instruction_pattern const& a, instruction_pattern const& b) {
                return util::bit_count(a.mask) > util::bit_count(b.mask);
            });
        }
    }
};

coverage_monitor::coverage_monitor(uvm::uvm_component_name const& nm)
: uvm::uvm_subscriber<exec_trace<traits::reg_t>>(nm)
, pimpl(new impl()) {}

coverage_monitor::~coverage_monitor() {
    if(report_file_name.size()) {
        SCCINFO(SCMOD) << "Writing coverage info to " << report_file_name;
        fc4sc::global::coverage_save(report_file_name.c_str());
    }
}

void coverage_monitor::build_phase(uvm::uvm_phase& phase) {
    uvm::uvm_config_db<std::string>::get(this, "", "isa_yaml_file_name", isa_yaml_file_name);
    uvm::uvm_config_db<std::string>::get(this, "", "report_file_name", report_file_name);
    if(isa_yaml_file_name.size()) {
        pimpl->parse_YAML_ISA(isa_yaml_file_name);
        pimpl->trap_cg.option.merge_instances = true;
        pimpl->dbus_cg.option.merge_instances = true;
        pimpl->ill_cg.option.merge_instances = true;
    }
}

void coverage_monitor::end_of_simulation() {
    if(report_file_name.size()) {
        SCCINFO(SCMOD) << "Writing coverage info to " << report_file_name;
        fc4sc::global::coverage_save(report_file_name.c_str());
        report_file_name = "";
    }
}

void coverage_monitor::write(exec_trace<traits::reg_t> const& item) {
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
