/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <argparse/argparse.hpp>  // NOLINT(build/include_order)

#include "common/network/ip_address.h"

namespace fptn::config {

using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;

class ServerConfig {
 public:
  explicit ServerConfig(int argc, char* argv[]);
  bool Parse() noexcept;

 public:
  /* options */
  [[nodiscard]] std::string ServerCrt() const;
  [[nodiscard]] std::string ServerKey() const;
  [[nodiscard]] std::string OutNetworkInterface() const;
  [[nodiscard]] int ServerPort() const;

  [[nodiscard]] std::string TunInterfaceName() const;
  /* IPv4 */
  [[nodiscard]] IPv4Address TunInterfaceIPv4() const;
  [[nodiscard]] IPv4Address TunInterfaceNetworkIPv4Address() const;
  [[nodiscard]] std::uint32_t TunInterfaceNetworkIPv4Mask() const;
  /* IPv6 */
  [[nodiscard]] IPv6Address TunInterfaceIPv6() const;
  [[nodiscard]] IPv6Address TunInterfaceNetworkIPv6Address() const;
  [[nodiscard]] std::uint32_t TunInterfaceNetworkIPv6Mask() const;

  [[nodiscard]] std::string UserFile() const;
  [[nodiscard]] bool EnableAdsFilter() const;
  [[nodiscard]] std::vector<std::string> AdsBlocklistUrls() const;
  [[nodiscard]] std::string DataDir() const;
  [[nodiscard]] bool EnableTorrentFilter() const;
  [[nodiscard]] bool EnableSpamFilter() const;
  [[nodiscard]] bool EnableDomainBlacklistFilter() const;
  [[nodiscard]] std::vector<std::string> DomainBlacklistUrls() const;
  [[nodiscard]] std::string DomainBlacklistFile() const;
  [[nodiscard]] std::string PrometheusAccessKey() const;

  [[nodiscard]] bool UseRemoteServerAuth() const;
  [[nodiscard]] std::string RemoteServerAuthHost() const;
  [[nodiscard]] int RemoteServerAuthPort() const;

  [[nodiscard]] bool EnableDetectProbing() const;

  [[nodiscard]] std::vector<std::string> AllowedSniList() const;

  [[nodiscard]] std::size_t MaxActiveSessionsPerUser() const;

  [[nodiscard]] std::string ServerExternalIPs() const;

  [[nodiscard]] int MtuSize() const;

 private:
  int argc_;
  char** argv_;
  argparse::ArgumentParser args_;
};

using ServerConfigSPtr = std::shared_ptr<ServerConfig>;

}  // namespace fptn::config
