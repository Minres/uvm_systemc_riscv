
#pragma once

#include <iss/vm_plugin.h>
#include <iss/vm_types.h>

using virt_addr_t = iss::typed_addr_t<iss::address_type::VIRTUAL>;
using phys_addr_t = iss::typed_addr_t<iss::address_type::PHYSICAL>;

class iss_if {
public:
    virtual iss::status read_mem(phys_addr_t addr, unsigned length, uint8_t* const data) = 0;
    virtual iss::status write_mem(phys_addr_t addr, unsigned length, uint8_t const* const data) = 0;

    virtual char const* instance_name() = 0;

    virtual ~iss_if() {}

    bool compressed_instr{false};
};
