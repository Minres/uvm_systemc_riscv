#pragma once

#include <systemc>
#include <uvm>

#include <core_mapper.h>
#include <types.h>

namespace item {

class instruction_item : public uvm::uvm_sequence_item {
public:
    UVM_OBJECT_UTILS(instruction_item);

    exec_trace<traits::reg_t> item;
    bool ibus_mismatch{false};
    uint64_t ibus_addr{0};

    instruction_item(const std::string& name = "instruction_item");

    void do_print(const uvm::uvm_printer& printer) const override;
    void do_pack(uvm::uvm_packer& p) const override;
    void do_unpack(uvm::uvm_packer& p) override;
    void do_copy(const uvm::uvm_object& rhs) override;
    bool do_compare(const uvm::uvm_object& rhs, const uvm::uvm_comparer* comparer = nullptr) const override;
    std::string convert2string() const override;
};

struct dbus_analysis_pack {
    size_t idx{0};
    std::vector<dbus_access> accesses;
};

inline std::ostream& operator<<(std::ostream& os, dbus_analysis_pack& rec) { return os; }

} // namespace item
