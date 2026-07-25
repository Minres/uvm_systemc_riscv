/*
 * dyn_coverage_monitor.h
 *
 *  Created on: Jun 18, 2022
 *      Author: eyck
 */

#ifndef _COMPONENTS_DYN_COVERAGE_MONITOR_H_
#define _COMPONENTS_DYN_COVERAGE_MONITOR_H_

#include <cci_configuration>
#include <core_mapper.h>
#include <item/instruction_item.h>
#include <memory>
#include <systemc>
#include <uvm>

namespace components {

class dyn_coverage_monitor : public uvm::uvm_subscriber<exec_trace<traits::reg_t>> {
    struct impl;

public:
    // Provide implementations of virtual methods such as get_type_name and create
    UVM_COMPONENT_UTILS(dyn_coverage_monitor);

    dyn_coverage_monitor(uvm::uvm_component_name const& nm);

    virtual ~dyn_coverage_monitor();

    void build_phase(uvm::uvm_phase& phase) override;

private:
    std::string isa_yaml_file_name;
    std::string report_file_name;

    void end_of_simulation() override;

    void write(exec_trace<traits::reg_t> const& item) override;

    std::unique_ptr<impl> pimpl;
};
} // namespace components
#endif /* _COMPONENTS_DYN_COVERAGE_MONITOR_H_ */
