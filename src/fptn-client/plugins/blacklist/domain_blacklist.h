/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <mutex>
#include <regex>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <re2/re2.h>  // NOLINT(build/include_order)

#include "plugins/base_plugin.h"
#include "routing/route_manager.h"

namespace fptn::plugin {
class DomainBlacklist final : public BasePlugin {
 public:
  explicit DomainBlacklist(const std::vector<std::string>& rules,
      routing::RouteManagerSPtr route_manager);

  ~DomainBlacklist() override = default;

  Result HandlePacket(
      fptn::common::network::IPPacketPtr packet, Direction direction) override;

 private:
  mutable std::mutex mutex_;

  const routing::RouteManagerSPtr route_manager_;
  std::vector<std::unique_ptr<RE2>> rules_;

  std::unordered_set<std::uint32_t> ipv4_addresses_;
  std::unordered_set<std::string> ipv6_addresses_;
};

using DomainBlacklistPtr = std::unique_ptr<DomainBlacklist>;

}  // namespace fptn::plugin
