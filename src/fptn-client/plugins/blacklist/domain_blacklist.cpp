/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "plugins/blacklist/domain_blacklist.h"

#include <memory>
#include <ranges>
#include <string>
#include <utility>
#include <vector>

#include "common/network/ip_utils.h"
#include "common/utils/utils.h"

#include "utils/utils.h"

namespace fptn::plugin {

DomainBlacklist::DomainBlacklist(const std::vector<std::string>& rules,
    routing::RouteManagerSPtr route_manager)
    : route_manager_(std::move(route_manager)) {
  RE2::Options re_options;
  re_options.set_case_sensitive(false);
  re_options.set_log_errors(false);

  for (const auto& rule : rules) {
    const std::string regex_pattern = fptn::utils::DomainToRegex(rule);
    if (!regex_pattern.empty()) {
      auto re = std::make_unique<RE2>(regex_pattern, re_options);
      if (re->ok()) {
        SPDLOG_INFO("Added blacklist rule: '{}' -> '{}'", rule, regex_pattern);
        rules_.push_back(std::move(re));
      } else {
        SPDLOG_WARN("Invalid regex pattern: {}, item={}", re->error(), rule);
      }
    } else {
      SPDLOG_WARN("Wrong pattern {}", rule);
    }
  }
}

Result DomainBlacklist::HandlePacket(
    fptn::common::network::IPPacketPtr packet, Direction direction) {
  bool triggered = false;
  if (direction == Direction::kOutgoing) {
    if (packet->IsTCP() && packet->IsIPv4()) {
      const auto [payload, size] = packet->GetTcpPayload();
      if (fptn::common::network::IsTlsClientHello(payload, size)) {
        const auto sni_opt = fptn::common::network::GetTlsSNI(payload, size);
        if (sni_opt.has_value() &&
            std::ranges::any_of(rules_, [&sni_opt](const auto& re) {
              return RE2::PartialMatch(sni_opt.value(), *re);
            })) {
          SPDLOG_INFO("Blocked TLS SNI {}", sni_opt.value());
          return {.packet = nullptr, .reply = nullptr, .triggered = true};
        }
      }
    }
  } else if (packet->IsDns()) {
    const auto domain_opt = packet->GetDnsDomain();
    if (domain_opt.has_value()) {
      const std::string& domain = domain_opt.value();

      if (std::ranges::any_of(rules_, [&domain](const auto& re) {
            return RE2::PartialMatch(domain, *re);
          })) {
        SPDLOG_INFO("Domain {} is blacklisted", domain);

        const auto ipv4_addresses = packet->GetDnsIPv4Addresses();
        const auto ipv6_addresses = packet->GetDnsIPv6Addresses();

        // save
        const std::unique_lock<std::mutex> lock(mutex_);  // mutex
        {
          for (const auto& ipv4_address : ipv4_addresses) {
            if (!ipv4_addresses_.contains(ipv4_address.ToInt())) {
              SPDLOG_INFO(
                  "Added IPv4 to blacklist: {}", ipv4_address.ToString());
              ipv4_addresses_.insert(ipv4_address.ToInt());
            }
          }
          for (const auto& ipv6_address : ipv6_addresses) {
            if (!ipv6_addresses_.contains(ipv6_address.ToString())) {
              SPDLOG_INFO(
                  "Added IPv6 to blacklist: {}", ipv6_address.ToString());
              ipv6_addresses_.insert(ipv6_address.ToString());
            }
          }
        }
        triggered = true;
      }
    }
  } else if (packet->IsIPv4()) {
    const std::uint32_t src_ipv4 = packet->GetSrcIPv4Address().ToInt();
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    if (ipv4_addresses_.contains(src_ipv4)) {
      SPDLOG_INFO("Blocked IPv4 packet from {}",
          packet->GetSrcIPv4Address().ToString());
      return {
          .packet = nullptr,
          .reply = nullptr,
          .triggered = true,
      };
    }
  } else if (packet->IsIPv6()) {
    const std::string src_ipv6 = packet->GetSrcIPv6Address().ToString();

    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    if (ipv6_addresses_.contains(src_ipv6)) {
      SPDLOG_INFO("Blocked IPv6 packet from {}", src_ipv6);
      return {
          .packet = nullptr,
          .reply = nullptr,
          .triggered = true,
      };
    }
  }
  return {
      .packet = std::move(packet),
      .reply = nullptr,
      .triggered = triggered,
  };
}

}  // namespace fptn::plugin
