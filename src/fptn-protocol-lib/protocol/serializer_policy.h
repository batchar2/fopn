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

#include <string_view>

namespace fptn::protocol {

enum class SerializerPolicy {
  kAuto,
  kProtobuf,
  kYaff,
};

inline constexpr std::string_view ToString(
    const SerializerPolicy policy) noexcept {
  switch (policy) {
    case SerializerPolicy::kAuto:
      return "auto";
    case SerializerPolicy::kProtobuf:
      return "protobuf";
    case SerializerPolicy::kYaff:
      return "yaff";
  }
  return "protobuf";
}

inline constexpr SerializerPolicy SerializerPolicyFromHeader(
    const std::string_view value) noexcept {
  return value == "yaff" ? SerializerPolicy::kYaff
                          : SerializerPolicy::kProtobuf;
}

inline constexpr SerializerPolicy ResolveSerializerPolicy(
    const SerializerPolicy policy) noexcept {
  return policy == SerializerPolicy::kAuto ? SerializerPolicy::kProtobuf
                                            : policy;
}

}  // namespace fptn::protocol
