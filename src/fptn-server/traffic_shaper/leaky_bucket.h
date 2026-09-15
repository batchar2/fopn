/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <memory>
#include <mutex>

#include "common/network/ip_packet.h"

namespace fptn::traffic_shaper {
class LeakyBucket final {
 public:
  // A limit of zero means "no limit". A zero bucket would otherwise reject
  // every packet forever, and the server builds a shaper unconditionally -
  // any hiccup while reading the user's bandwidth would silence the tunnel
  // instead of merely slowing it down.
  explicit LeakyBucket(std::size_t max_bites_per_second);
  bool CheckSpeedLimit(std::size_t packet_size) noexcept;
  // Same, with the moment supplied by the caller: lets tests drive the clock
  // instead of sleeping through it.
  bool CheckSpeedLimitAt(std::size_t packet_size,
      std::chrono::steady_clock::time_point now) noexcept;
  std::size_t FullDataAmount() const noexcept;

 private:
  mutable std::mutex mutex_;
  std::size_t current_amount_;
  std::size_t max_bytes_per_second_;
  std::chrono::steady_clock::time_point last_leak_time_;

  std::size_t full_data_amount_;
};

using LeakyBucketSPtr = std::shared_ptr<LeakyBucket>;
}  // namespace fptn::traffic_shaper
