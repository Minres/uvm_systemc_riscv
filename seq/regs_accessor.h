#pragma once

#include <cstdint>
#include <memory>

/**
 * @brief Abstract base class for accessing CPU registers.
 *
 * This class provides a consistent interface for accessing CPU registers,
 * regardless of whether the registers are 32-bit or 64-bit.
 */
class RegsAccessorBase {
public:
    virtual ~RegsAccessorBase() = default;
    virtual uint64_t get_reg(size_t index) const = 0;
};

/**
 * @brief Templated derived class for accessing CPU registers.
 *
 * Allows to transparently handle both 32-bit and 64-bit regs.
 *
 * @tparam T Type of the registers (either uint32_t or uint64_t).
 */
template <typename T> class RegsAccessor : public RegsAccessorBase {
public:
    explicit RegsAccessor(void* regs_base_ptr)
    : regs(reinterpret_cast<T*>(regs_base_ptr)) {}

    uint64_t get_reg(size_t index) const override { return static_cast<uint64_t>(regs[index]); }

private:
    T* regs;
};
