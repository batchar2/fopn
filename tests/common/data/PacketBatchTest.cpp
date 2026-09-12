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
#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/data/packet_batch.h"

namespace {

fptn::common::network::IPPacketPtr MakePacket(const std::size_t size) {
  fptn::common::network::IPPacketData data(size, 0);
  data[0] = 0x45;
  data[8] = 64;
  data[9] = 17;
  return fptn::common::network::IPPacket::Parse(std::move(data));
}

TEST(PacketBatchTest, CountsOnlyConcretePackets) {
  fptn::common::network::BatchIPPacketPtr packets;
  packets.emplace_back(MakePacket(64));
  packets.emplace_back(nullptr);
  packets.emplace_back(MakePacket(1200));

  EXPECT_EQ(fptn::common::data::PacketBatchPayloadBytes(packets), 1264U);
}

TEST(PacketBatchTest, EmptyBatchHasNoPayloadBytes) {
  fptn::common::network::BatchIPPacketPtr packets;

  EXPECT_EQ(fptn::common::data::PacketBatchPayloadBytes(packets), 0U);
}

}  // namespace
