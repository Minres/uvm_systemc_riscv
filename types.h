#pragma once

#include <array>
#include <iostream>
#include <stdint.h>
#include <tuple>
#include <vector>

enum class fetch_type_e {
    EXEC_INSTR,
    EXEC_JUMP,
    EXEC_CJMP,
    EXEC_ECALL,
    EXEC_EBREAK,
    EXEC_XRET,
    EXEC_FENCEI,
    EXEC_HWBR,
    FETCH_CL,
    NUM_REASONS,
    NONE = NUM_REASONS
};

enum class dBus_access_e { NONE, READ = 1, WRITE = 2, FETCH = 3 };

struct dbus_access {
    dBus_access_e access_type{dBus_access_e::NONE};
    uint64_t bus_addr{0};
    std::vector<uint8_t> bus_data;
    bool operator==(dbus_access const& o) const {
        bool match = access_type == o.access_type && bus_addr == o.bus_addr;
        if(!match)
            return false;
        return std::equal(std::begin(bus_data), std::end(bus_data), std::begin(o.bus_data),
                          [](const uint8_t x, const uint8_t y) { return x == y; });
    }
};

template <typename WORDTYPE> struct exec_trace {
    uint64_t idx{0};
    fetch_type_e type{fetch_type_e::EXEC_INSTR};
    bool stop_on_retire{false};
    WORDTYPE fetch_pc{0};
    uint32_t fetch_value{0};
    bool is_compressed{false};
    bool br_taken{false};
    bool hwbr_taken{false};
    uint8_t privilege{0};
    int8_t trap{-1};
    int8_t irq{-1};
    std::vector<unsigned> irq_to_trigger; // bit 31: set/reset, bit 30:0 irq number
    std::vector<dbus_access> bus_accesses;
    struct reg_change {
        unsigned idx;
        WORDTYPE value;
        bool operator==(reg_change const& o) const { return idx == o.idx && value == o.value; }
    };
    std::vector<reg_change> reg_changes{0};
    void clear() {
        *this = exec_trace{};
        bus_accesses.resize(0);
        reg_changes.resize(0);
    }
    bool operator==(exec_trace const& o) const {
        bool match = type == o.type && fetch_pc == o.fetch_pc && fetch_value == o.fetch_value && is_compressed == o.is_compressed &&
                     br_taken == o.br_taken && privilege == o.privilege && reg_changes.size() == o.reg_changes.size();
        if(!match)
            return false;
        match = std::equal(std::begin(bus_accesses), std::end(bus_accesses), std::begin(o.bus_accesses),
                           [](const dbus_access& x, const dbus_access& y) { return x == y; });
        if(!match)
            return false;
        return std::equal(std::begin(reg_changes), std::end(reg_changes), std::begin(o.reg_changes),
                          [](const reg_change& x, const reg_change& y) { return x == y; });
    }
    bool operator!=(exec_trace const& o) const { return !(*this == o); }
};

template <typename WORDTYPE> std::ostream& operator<<(std::ostream& os, exec_trace<WORDTYPE>& rec) { return os; }
