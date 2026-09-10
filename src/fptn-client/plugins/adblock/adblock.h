/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>
#include <unordered_set>

#include "common/network/ip_packet.h"

#include "plugins/base_plugin.h"

namespace fptn::plugin {

class AdBlock final : public BasePlugin {
 public:
  AdBlock();
  explicit AdBlock(std::unordered_set<std::string> blocked_domains);

  ~AdBlock() override = default;

  Result HandlePacket(
      fptn::common::network::IPPacketPtr packet, Direction direction) override;

  fptn::common::network::IPPacketPtr ProcessOutgoingDns(
      const fptn::common::network::IPPacket& packet) const;

  std::size_t Size() const noexcept { return blocked_domains_.size(); }

 private:
  bool IsBlocked(const std::string& domain) const;

  std::unordered_set<std::string> blocked_domains_;
};

using AdBlockPtr = std::unique_ptr<AdBlock>;

}  // namespace fptn::plugin
