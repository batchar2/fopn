/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <vector>

#include "common/network/ip_packet.h"

namespace fptn::plugin {
enum class Direction : int {
  kOutgoing,
  kIncoming
};

struct Result {
  fptn::common::network::IPPacketPtr packet;
  fptn::common::network::IPPacketPtr reply;
  bool triggered;
};

class BasePlugin {
 public:
  virtual ~BasePlugin() = default;
  virtual Result HandlePacket(
      fptn::common::network::IPPacketPtr packet, Direction direction) = 0;
};

using BasePluginPtr = std::unique_ptr<BasePlugin>;
using PluginList = std::vector<BasePluginPtr>;

}  // namespace fptn::plugin
