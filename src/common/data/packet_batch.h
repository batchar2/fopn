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

#include <cstddef>

#include "common/network/ip_packet.h"

namespace fptn::common::data {

inline std::size_t PacketBatchPayloadBytes(
    const fptn::common::network::BatchIPPacketPtr& packets) noexcept {
  std::size_t result = 0;
  for (const auto& packet : packets) {
    if (packet) {
      result += packet->Size();
    }
  }
  return result;
}

}  // namespace fptn::common::data
