/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "traffic_shaper/leaky_bucket.h"

#include <cstdint>

namespace fptn::traffic_shaper {

LeakyBucket::LeakyBucket(std::size_t max_bites_per_second)
    : current_amount_(0),
      max_bytes_per_second_(max_bites_per_second / 8),
      last_leak_time_(std::chrono::steady_clock::now()),
      full_data_amount_(0)
{}

std::size_t LeakyBucket::FullDataAmount() const noexcept {
  // Read under the mutex: the counter is updated from every packet path.
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex
  return full_data_amount_;
}

bool LeakyBucket::CheckSpeedLimit(std::size_t packet_size) noexcept {
  return CheckSpeedLimitAt(packet_size, std::chrono::steady_clock::now());
}

bool LeakyBucket::CheckSpeedLimitAt(std::size_t packet_size,
    std::chrono::steady_clock::time_point now) noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  // Zero means the user has no bandwidth limit.
  if (max_bytes_per_second_ == 0) {
    full_data_amount_ += packet_size;
    return true;
  }

  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      now - last_leak_time_)
                           .count();

  // The bucket leaks in proportion to the elapsed time. The counter used to
  // reset only when a packet arrived a full second after the previous reset:
  // a dense stream never has such a gap, so the counter hit the ceiling and
  // everything after it was dropped until the traffic went quiet. That hurt
  // downloads far more than uploads, where pauses are common.
  if (elapsed > 0) {
    const auto leaked = static_cast<std::size_t>(
        (static_cast<std::uint64_t>(max_bytes_per_second_) *
            static_cast<std::uint64_t>(elapsed)) /
        1000U);
    current_amount_ = (current_amount_ > leaked) ? current_amount_ - leaked : 0;
    last_leak_time_ = now;
  }

  if (current_amount_ + packet_size <= max_bytes_per_second_) {
    current_amount_ += packet_size;
    full_data_amount_ += packet_size;
    return true;
  }
  return false;
}
}  // namespace fptn::traffic_shaper
