#pragma once

#include <cstdint>
#include <memory>

namespace seq {
/**
 * @brief Abstract base class for accessing CPU registers.
 *
 * This class provides a consistent interface for accessing CPU registers,
 * regardless of whether the registers are 32-bit or 64-bit.
 */
class regs_accessor_base {
public:
    virtual ~regs_accessor_base() = default;
    virtual uint64_t get_reg(size_t index) const = 0;
};

/**
 * @brief Templated derived class for accessing CPU registers.
 *
 * Allows to transparently handle both 32-bit and 64-bit regs.
 *
 * @tparam T Type of the registers (either uint32_t or uint64_t).
 */
template <typename T> class regs_accessor : public regs_accessor_base {
public:
    explicit regs_accessor(void* regs_base_ptr)
    : regs(reinterpret_cast<T*>(regs_base_ptr)) {}

    uint64_t get_reg(size_t index) const override { return static_cast<uint64_t>(regs[index]); }

private:
    T* regs;
};

using regs_accessor_32 = regs_accessor<uint32_t>;
using regs_accessor_64 = regs_accessor<uint64_t>;
} // namespace seq