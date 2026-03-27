#include <src/uvm_systemc_riscv/item/instruction_item.h>
#include <systemc>
#include <uvm>

#include <algorithm>

namespace item {

instruction_item::instruction_item(const std::string& name)
: uvm::uvm_sequence_item(name) {}

void instruction_item::do_print(const uvm::uvm_printer& printer) const { printer.print_field_int("idx", item.idx); }

void instruction_item::do_pack(uvm::uvm_packer& p) const { p << item.idx; }

void instruction_item::do_unpack(uvm::uvm_packer& p) { p >> item.idx; }

void instruction_item::do_copy(const uvm::uvm_object& rhs) {
    const instruction_item* drhs = dynamic_cast<const instruction_item*>(&rhs);

    if(!drhs)
        UVM_FATAL("DO_COPY", "Object not of type core_trace_trans");

    item = drhs->item;
}

bool instruction_item::do_compare(const uvm::uvm_object& rhs, const uvm::uvm_comparer* comparer) const {
    const instruction_item* drhs = dynamic_cast<const instruction_item*>(&rhs);

    if(!drhs)
        UVM_FATAL("DO_COPY", "Object not of type core_trace_trans");

    if(item == drhs->item)
        return true;
    return false;
}

std::string instruction_item::convert2string() const {
    std::ostringstream str;
    if(item.type == fetch_type_e::FETCH_CL) {
        str << " fetch addr: 0x" << std::hex << item.bus_accesses[0].bus_addr << std::dec;
        str << " len: " << item.bus_accesses[0].bus_data.size();
    } else {
        str << " idx: " << item.idx;
        str << " fetch_pc: 0x" << std::hex << item.fetch_pc;
        str << " insn: 0x" << item.fetch_value << std::dec;
        str << " compressed: " << item.is_compressed;
        str << " br taken: " << item.br_taken;
        str << " hwbr taken: " << item.hwbr_taken;
        str << " trap: " << (int)item.trap;
        str << " privilege: " << (unsigned)item.privilege;
        if(item.bus_accesses.size())
            str << " first dbus_adddr: 0x" << std::hex << item.bus_accesses[0].bus_addr << std::dec;
        str << " stop_on_retire: " << item.stop_on_retire;
    }
    return str.str();
}

} // namespace item
