project(uvm_systemc_riscv CXX)

set(DISABLE_QKD_WARNING ON)

find_package(fmt)
find_package(accellera-uvm-systemc)
find_package(crave2uvm QUIET)

add_library(${PROJECT_NAME}
    item/instruction_item.cpp
    components/coverage_monitor.cpp
    components/coverage_monitor/instr.cpp
    seq/constr_instr_gen.cpp
)
if(TARGET crave2uvm::crave2uvm)
    target_sources(${PROJECT_NAME} PRIVATE
        seq/constrained_rand_gen.cpp
    )
    target_compile_definitions(${PROJECT_NAME} PUBLIC WITH_CRAVE)
else()
	message(STATUS "Building without Crave")
endif()

if(EN_EXT_DEBUG)
    target_compile_definitions(${PROJECT_NAME} PRIVATE EN_EXT_DEBUG)
endif()
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# target_link_libraries(${PROJECT_NAME} PUBLIC rv32cov rv32iss) 
if(TARGET fmt::fmt-header-only)
    target_link_libraries(${PROJECT_NAME} PUBLIC fmt::fmt-header-only)
else()
    target_link_libraries(${PROJECT_NAME} PUBLIC fmt::fmt)
endif()
target_link_libraries(${PROJECT_NAME} PUBLIC
    crave2uvm::crave2uvm
    rv32iss
    accellera-uvm-systemc::accellera-uvm-systemc
    scc::scc
    dbt-rise-riscv
    core_config
    fc4sc
)
