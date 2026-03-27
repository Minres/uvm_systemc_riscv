/*
 * seq/types.h
 *
 *  Created on: Apr 30, 2023
 *      Author: eyck
 */

#ifndef UVM_TB_UVM_SEQ_SEQ_TYPES_H_
#define UVM_TB_UVM_SEQ_SEQ_TYPES_H_

#include <cstdint>
#include <iss/arch_if.h>
#include <systemc>
#include <tlm_core/tlm_1/tlm_req_rsp/tlm_1_interfaces/tlm_core_ifs.h>

struct mem_req {
    iss::access_type type{iss::access_type::READ};
    uint64_t addr{0};
    unsigned len{0};
    std::vector<uint8_t> data;
    mem_req& operator=(mem_req const& o) {
        type = o.type;
        addr = o.addr;
        len = o.len;
        data = o.data;
        return *this;
    }
    friend std::ostream& operator<<(std::ostream& os, const mem_req& req) {
        os << "Mem Request: " << req.addr;
        return os;
    }
    bool operator==(const mem_req& other) const { return data == other.data; }
};

struct mem_rsp {
    bool stopit{false};
    std::vector<uint8_t> data;
    mem_rsp& operator=(mem_rsp const& o) {
        stopit = o.stopit;
        data = o.data;
        return *this;
    }
    friend std::ostream& operator<<(std::ostream& os, const mem_rsp& rsp) {
        os << "Mem Response: " << rsp.stopit;
        return os;
    }
    bool operator==(const mem_rsp& other) const { return data == other.data; }
};

inline void sc_trace(sc_core::sc_trace_file* tf, const mem_req& val, const std::string& name) {
    sc_trace(tf, val.addr, name + ".addr");
    sc_trace(tf, val.len, name + ".len");
}

inline void sc_trace(sc_core::sc_trace_file* tf, const mem_rsp& val, const std::string& name) {
    sc_trace(tf, val.stopit, name + ".stopit");
    for(size_t i = 0; i < val.data.size(); ++i) {
        sc_trace(tf, val.data[i], name + "[" + std::to_string(i) + "]");
    }
}

struct irq_push_if : sc_core::sc_interface {
    virtual void put_irq_to_trigger(unsigned) = 0;
    virtual void put_trigger_delay_cnt(unsigned) = 0;
};

using seq_if = tlm::tlm_transport_if<mem_req, mem_rsp>;

#endif /* UVM_TB_UVM_SEQ_SEQ_TYPES_H_ */
