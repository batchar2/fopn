/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "common/network/ip_packet.h"

#include "plugins/base_plugin.h"
#include "routing/route_manager.h"

namespace fptn::plugin {
class Tunneling final : public BasePlugin {
 public:
  explicit Tunneling(const std::vector<std::string>& rules,
      routing::RouteManagerSPtr route_manager,
      fptn::routing::RoutingPolicy policy);

  ~Tunneling() override = default;

  Result HandlePacket(
      fptn::common::network::IPPacketPtr packet, Direction direction) override;

 private:
  const routing::RouteManagerSPtr route_manager_;
  const fptn::routing::RoutingPolicy policy_;

  std::unordered_set<std::string> domains_;
};

using TunnelingPtr = std::unique_ptr<Tunneling>;

}  // namespace fptn::plugin
