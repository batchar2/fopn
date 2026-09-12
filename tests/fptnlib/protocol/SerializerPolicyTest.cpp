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

#include "fptn-protocol-lib/https/connection_config.h"
#include "fptn-protocol-lib/protocol/serializer_policy.h"

namespace {

using fptn::protocol::ResolveSerializerPolicy;
using fptn::protocol::SerializerPolicy;
using fptn::protocol::SerializerPolicyFromHeader;
using fptn::protocol::ToString;

TEST(SerializerPolicyTest, SerializesStableWireNames) {
  EXPECT_EQ(ToString(SerializerPolicy::kAuto), "auto");
  EXPECT_EQ(ToString(SerializerPolicy::kProtobuf), "protobuf");
  EXPECT_EQ(ToString(SerializerPolicy::kYaff), "yaff");
}

TEST(SerializerPolicyTest, RejectsUnknownHeaderValuesToProtobuf) {
  EXPECT_EQ(SerializerPolicyFromHeader("protobuf"),
      SerializerPolicy::kProtobuf);
  EXPECT_EQ(SerializerPolicyFromHeader(""), SerializerPolicy::kProtobuf);
  EXPECT_EQ(SerializerPolicyFromHeader("unsupported"),
      SerializerPolicy::kProtobuf);
}

TEST(SerializerPolicyTest, ConnectionConfigDefaultsToAuto) {
  const fptn::protocol::https::ConnectionConfig config;
  EXPECT_EQ(config.common.serializer_policy, SerializerPolicy::kAuto);
  EXPECT_EQ(config.common.max_outbound_queue_bytes, 4U * 1024U * 1024U);
}

TEST(SerializerPolicyTest, ResolvesAutoToBandwidthEfficientDefault) {
  EXPECT_EQ(ResolveSerializerPolicy(SerializerPolicy::kAuto),
      SerializerPolicy::kProtobuf);
  EXPECT_EQ(ResolveSerializerPolicy(SerializerPolicy::kProtobuf),
      SerializerPolicy::kProtobuf);
  EXPECT_EQ(ResolveSerializerPolicy(SerializerPolicy::kYaff),
      SerializerPolicy::kYaff);
}

}  // namespace
