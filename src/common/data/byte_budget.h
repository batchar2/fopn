/*
 * Copyright Nixort <https://github.com/Nixort/fptn> 2026.
 *
 * License: MIT
 * You can find the license file in the project root.
 *
 * FPTN
 * The code was written for FPTN.
 * 15 August 2026.
 *
 * Transport and protocol implementation.
 *
 * This file contains a focused implementation component for the FPTN
 * transport optimization and its deterministic test coverage.
 */
#pragma once

#include <atomic>
#include <cstddef>

namespace fptn::common::data {

class ByteBudget final {
 public:
  explicit ByteBudget(const std::size_t max_bytes) noexcept
      : max_bytes_(max_bytes) {}

  ByteBudget(const ByteBudget&) = delete;
  ByteBudget& operator=(const ByteBudget&) = delete;

  bool TryAcquire(const std::size_t bytes) noexcept {
    if (bytes == 0 || bytes > max_bytes_) {
      return bytes == 0;
    }

    std::size_t used = used_bytes_.load(std::memory_order_relaxed);
    do {
      if (used > max_bytes_ - bytes) {
        return false;
      }
    } while (!used_bytes_.compare_exchange_weak(used, used + bytes,
        std::memory_order_acq_rel, std::memory_order_relaxed));
    return true;
  }

  void Release(const std::size_t bytes) noexcept {
    if (bytes == 0) {
      return;
    }
    used_bytes_.fetch_sub(bytes, std::memory_order_release);
  }

  [[nodiscard]] std::size_t UsedBytes() const noexcept {
    return used_bytes_.load(std::memory_order_acquire);
  }

  [[nodiscard]] std::size_t MaxBytes() const noexcept { return max_bytes_; }

 private:
  const std::size_t max_bytes_;
  std::atomic<std::size_t> used_bytes_{0};
};

}  // namespace fptn::common::data
