/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "plugins/split/tunneling.h"

#include <string>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/network/ip_utils.h"

#include "utils/utils.h"

namespace fptn::plugin {

Tunneling::Tunneling(const std::vector<std::string>& rules,
    routing::RouteManagerSPtr route_manager,
    fptn::routing::RoutingPolicy policy)
    : route_manager_(std::move(route_manager)), policy_(policy) {
  for (const auto& rule : rules) {
    std::string domain = fptn::utils::NormalizeDomainRule(rule);
    if (domain.empty()) {
      SPDLOG_WARN("Wrong pattern {}", rule);
      continue;
    }
    domains_.insert(std::move(domain));
  }
  SPDLOG_INFO("Tunneling rules loaded: {} domains", domains_.size());
}

Result Tunneling::HandlePacket(
    fptn::common::network::IPPacketPtr packet, Direction direction) {
  bool triggered = false;
  if (direction == Direction::kIncoming && packet->IsDns()) {
    const auto domain_opt = packet->GetDnsDomain();
    if (domain_opt.has_value()) {
      const std::string& domain = domain_opt.value();
      const bool domain_matched =
          fptn::utils::IsDomainMatched(domains_, domain);

      const bool needs_routes =
          (policy_ == routing::RoutingPolicy::kIncludeInVpn &&
              !domain_matched) ||
          (policy_ == routing::RoutingPolicy::kExcludeFromVpn &&
              domain_matched);
      if (needs_routes) {
        const auto ipv4_addresses = packet->GetDnsIPv4Addresses();
        if (!ipv4_addresses.empty()) {
          route_manager_->AddDnsRoutesIPv4(
              ipv4_addresses, routing::RoutingPolicy::kExcludeFromVpn);
          triggered = true;
        }
#ifndef __APPLE__
        const auto ipv6_addresses = packet->GetDnsIPv6Addresses();
        if (!ipv6_addresses.empty()) {
          route_manager_->AddDnsRoutesIPv6(
              ipv6_addresses, routing::RoutingPolicy::kExcludeFromVpn);
          triggered = true;
        }
#endif
        if (triggered) {
          SPDLOG_INFO("Domain '{}' -> EXCLUDE from VPN", domain);
        }
      }
    }
  } else if (direction == Direction::kOutgoing && packet->IsTCP() &&
             packet->IsIPv4()) {
    const auto [payload, size] = packet->GetTcpPayload();
    if (fptn::common::network::IsTlsClientHello(payload, size)) {
      const auto sni_opt = fptn::common::network::GetTlsSNI(payload, size);
      if (sni_opt.has_value()) {
        const std::string& sni = sni_opt.value();
        const bool domain_matched = fptn::utils::IsDomainMatched(domains_, sni);

        const bool needs_routes =
            (policy_ == routing::RoutingPolicy::kIncludeInVpn &&
                !domain_matched) ||
            (policy_ == routing::RoutingPolicy::kExcludeFromVpn &&
                domain_matched);
        if (needs_routes) {
          SPDLOG_INFO("SNI '{}' -> EXCLUDE from VPN", sni);
          route_manager_->AddExcludeRouteWithReset(
              packet->GetDstIPv4Address(), packet->MakeTcpReset());
          return {.packet = nullptr, .reply = nullptr, .triggered = true};
        }
      }
    }
  }
  return {
      .packet = std::move(packet),
      .reply = nullptr,
      .triggered = triggered,
  };
}

}  // namespace fptn::plugin
