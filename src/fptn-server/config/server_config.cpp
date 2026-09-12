/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "config/server_config.h"

#include <algorithm>
#include <charconv>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include <fmt/format.h>     // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/utils/utils.h"

namespace {
int ParseInt(
    const std::string& value, int default_value, int min_value, int max_value) {
  if (value.empty()) {
    return default_value;
  }
  int result = 0;
  const auto [end, error] =
      std::from_chars(value.data(), value.data() + value.size(), result);
  if (error != std::errc() || end != value.data() + value.size()) {
    throw std::runtime_error("Invalid number: '" + value + "'");
  }
  if (result < min_value || result > max_value) {
    throw std::runtime_error(
        fmt::format("Value {} is out of range [{}..{}]", result, min_value,
            max_value));
  }
  return result;
}

bool ParseBoolean(std::string value) noexcept {
  try {
    // С++17
    // NOLINTNEXTLINE(modernize-use-ranges)
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return value == "true";
  } catch (...) {
    return false;
  }
}
}  // namespace

namespace fptn::config {

using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;

ServerConfig::ServerConfig(int argc, char* argv[])
    : argc_(argc), argv_(argv), args_("fptn-server", FPTN_VERSION) {
  // Required arguments
  args_.add_argument("--server-crt").required().help("Path to server.crt file");
  args_.add_argument("--server-key").required().help("Path to server.key file");
  args_.add_argument("--out-network-interface")
      .required()
      .help("Network out interface");
  // Optional arguments
  args_.add_argument("--server-port")
      .default_value(443)
      .help("Port number")
      .action([](const std::string& v) -> int {
        return ParseInt(v, 443, 1, 65535);
      });
  args_.add_argument("--mtu-size")
      .default_value(FPTN_DEFAULT_MTU_SIZE)
      .help("MTU size")
      .action([](const std::string& v) -> int {
        return ParseInt(v, FPTN_DEFAULT_MTU_SIZE, 576, 65535);
      });
  args_.add_argument("--tun-interface-name")
      .default_value("tun0")
      .help("Network interface name")
      .action([](const std::string& v) -> std::string {
        return v.empty() ? "tun0" : v;
      });
  /* IPv4 */
  args_.add_argument("--tun-interface-ip")
      .default_value(FPTN_SERVER_DEFAULT_ADDRESS_IP4)
      .help("IP address of the virtual interface")
      .action([](const std::string& v) -> std::string {
        return v.empty() ? FPTN_SERVER_DEFAULT_ADDRESS_IP4 : v;
      });
  args_.add_argument("--tun-interface-network-address")
      .default_value(FPTN_SERVER_DEFAULT_NET_ADDRESS_IP4)
      .help("IP network of the virtual interface")
      .action([](const std::string& v) -> std::string {
        return v.empty() ? FPTN_SERVER_DEFAULT_NET_ADDRESS_IP4 : v;
      });
  args_.add_argument("--tun-interface-network-mask")
      .default_value(16)
      .help("Network mask")
      .action([](const std::string& v) -> int {
        return ParseInt(v, 16, 1, 32);
      });
  /* IPv6 */
  args_.add_argument("--tun-interface-ipv6")
      .default_value(FPTN_SERVER_DEFAULT_ADDRESS_IP6)
      .help("IPv6 address of the virtual interface")
      .action([](const std::string& v) -> std::string {
        return v.empty() ? FPTN_SERVER_DEFAULT_ADDRESS_IP6 : v;
      });
  args_.add_argument("--tun-interface-network-ipv6-address")
      .default_value(FPTN_SERVER_DEFAULT_NET_ADDRESS_IP6)
      .help("IPv6 network address of the virtual interface")
      .action([](const std::string& v) -> std::string {
        return v.empty() ? FPTN_SERVER_DEFAULT_NET_ADDRESS_IP6 : v;
      });
  args_.add_argument("--tun-interface-network-ipv6-mask")
      .default_value(64)
      .help("IPv6 network mask")
      .action([](const std::string& v) -> int {
        return ParseInt(v, 64, 1, 128);
      });
  args_.add_argument("--userfile")
      .help("Path to users file (default: /etc/fptn/users.list)")
      .default_value("/etc/fptn/users.list")
      .action([](const std::string& v) -> std::string {
        return v.empty() ? "/etc/fptn/users.list" : v;
      });
  // Packet filters
  args_.add_argument("--enable-domain-blacklist-filter")
      .help(
          "Block the blacklisted domains: a TLS handshake whose SNI is a "
          "listed domain (or a subdomain of one) is dropped, and so are the "
          "QUIC and ICMP packets addressed to an IP such a domain resolves "
          "to. Enabled by default, set to 'false' to let this traffic "
          "through.")
      .default_value("true")
      .action([](const std::string& v) -> std::string {
        return v.empty() ? "true" : v;
      });
  args_.add_argument("--domain-blacklist-urls")
      .help(
          "Comma-separated URLs of the domain lists to block, one domain per "
          "line ('#' starts a comment). Every list is cached in --data-dir and "
          "downloaded again once it is older than an hour. The lists extend "
          "the built-in one. Empty downloads nothing.")
      .default_value(FPTN_SERVER_DEFAULT_DOMAIN_BLACKLIST_URLS);
  args_.add_argument("--domain-blacklist-file")
      .help(
          "Path to a file with domains to block, one per line ('#' starts a "
          "comment). Traffic to the addresses a listed domain or any of its "
          "subdomains resolves to is dropped. The list extends the built-in "
          "one. Empty (default) uses only the built-in list.")
      .default_value("");
  args_.add_argument("--enable-ads-filter")
      .help(
          "Block ads and trackers using the domain lists downloaded from "
          "--ads-blocklist-urls. A TLS handshake whose SNI is a listed domain "
          "(or a subdomain of one) is dropped. Enabled by default, set to "
          "'false' to let this traffic through.")
      .default_value("true")
      .action([](const std::string& v) -> std::string {
        return v.empty() ? "true" : v;
      });
  args_.add_argument("--ads-blocklist-urls")
      .help(
          "Comma-separated URLs of the ad/tracker domain lists (the hosts "
          "format and a bare domain per line are both accepted). Every list is "
          "cached in --data-dir and downloaded again once it is older than an "
          "hour. Empty downloads nothing.")
      .default_value(FPTN_SERVER_DEFAULT_ADS_BLOCKLIST_URLS);
  args_.add_argument("--data-dir")
      .help(
          "Directory for the files the server downloads at runtime, such as "
          "the ad/tracker domain lists (default: /etc/fptn/data)")
      .default_value("/etc/fptn/data")
      .action([](const std::string& v) -> std::string {
        return v.empty() ? "/etc/fptn/data" : v;
      });
  args_.add_argument("--enable-torrent-filter")
      .help(
          "Block BitTorrent traffic. Enabled by default, set to 'false' to let "
          "BitTorrent packets through.")
      .default_value("true")
      .action([](const std::string& v) -> std::string {
        return v.empty() ? "true" : v;
      });
  args_.add_argument("--enable-spam-filter")
      .help(
          "Block the client traffic that gets this server blacklisted: "
          "outgoing mail (the SMTP ports, any TCP stream that starts with an "
          "SMTP command, DNS MX lookups) together with the telnet, NetBIOS, "
          "SMB, SSDP and memcached ports. Enabled by default, set to 'false' "
          "to let this traffic through.")
      .default_value("true")
      .action([](const std::string& v) -> std::string {
        return v.empty() ? "true" : v;
      });
  // Allow prometheus metric
  args_.add_argument("--prometheus-access-key")
      .help(
          "Secret key required for accessing Prometheus metrics. Set this to a "
          "secret value if metrics is needed.")
      .default_value("");
  // Remote server auth
  args_.add_argument("--use-remote-server-auth")
      .help(
          "Enable remote server authentication. Set to 'true' to use a remote "
          "server for authentication.")
      .default_value("false");
  args_.add_argument("--remote-server-auth-host")
      .help(
          "Specify the remote server's IP address or hostname for "
          "authentication.")
      .default_value("1.1.1.1")
      .action([](const std::string& v) -> std::string {
        return v.empty() ? "1.1.1.1" : v;
      });
  args_.add_argument("--remote-server-auth-port")
      .help(
          "Specify the port number for the remote server authentication. Set "
          "to 0 to use the default port.")
      .default_value(443)
      .action([](const std::string& v) -> int {
        return ParseInt(v, 443, 0, 65535);
      });
  args_.add_argument("--max-active-sessions-per-user")
      .help("Maximum number of active sessions allowed per VPN user")
      .default_value(3)
      .action([](const std::string& v) -> int {
        return ParseInt(v, 3, 1, 1000);
      });
  // Probing
  args_.add_argument("--enable-detect-probing")
      .help(
          "Enable detection of non-FPTN clients or probing attempts during SSL "
          "handshake. ")
      .default_value("false");
  args_.add_argument("--allowed-sni-list")
      .help(
          "Comma-separated list of decoy domains for non-VPN (scanner) "
          "traffic.\n"
          "When a non-VPN client connects, its traffic is proxied to a real "
          "website:\n"
          " - if its SNI is in this list -> proxy to that SNI\n"
          " - otherwise -> proxy to the first reachable domain from the list\n"
          "If the list is empty, a built-in default domain is used.")
      .default_value("");
  // Prevent self-proxy
  args_.add_argument("--server-external-ips")
      .help(
          "Public IPv4 address of this VPN server. "
          "Prevents proxy loops when clients connect via IP. "
          "Example: --server-external-ip 1.2.3.4,5.6.7.8")
      .default_value("");
}

bool ServerConfig::Parse() noexcept {  // NOLINT(bugprone-exception-escape)
  try {
    args_.parse_args(argc_, argv_);
    return true;
  } catch (const std::runtime_error& err) {
    const std::string help = args_.help().str();
    SPDLOG_ERROR("Argument parsing error: {}\n{}", err.what(), help);
  } catch (...) {
    SPDLOG_ERROR("Undefined parser error");
  }
  return false;
}

std::string ServerConfig::ServerCrt() const {
  return args_.get<std::string>("--server-crt");
}

std::string ServerConfig::ServerKey() const {
  return args_.get<std::string>("--server-key");
}

std::string ServerConfig::OutNetworkInterface() const {
  return args_.get<std::string>("--out-network-interface");
}

int ServerConfig::ServerPort() const { return args_.get<int>("--server-port"); }

std::string ServerConfig::TunInterfaceName() const {
  return args_.get<std::string>("--tun-interface-name");
}

IPv4Address ServerConfig::TunInterfaceIPv4() const {
  return IPv4Address(args_.get<std::string>("--tun-interface-ip"));
}

IPv4Address ServerConfig::TunInterfaceNetworkIPv4Address() const {
  return IPv4Address(args_.get<std::string>("--tun-interface-network-address"));
}

std::uint32_t ServerConfig::TunInterfaceNetworkIPv4Mask() const {
  const int value = args_.get<int>("--tun-interface-network-mask");
  return static_cast<std::uint32_t>(value);
}

IPv6Address ServerConfig::TunInterfaceIPv6() const {
  return IPv6Address(args_.get<std::string>("--tun-interface-ipv6"));
}

IPv6Address ServerConfig::TunInterfaceNetworkIPv6Address() const {
  return IPv6Address(
      args_.get<std::string>("--tun-interface-network-ipv6-address"));
}

std::uint32_t ServerConfig::TunInterfaceNetworkIPv6Mask() const {
  const int value = args_.get<int>("--tun-interface-network-ipv6-mask");
  return static_cast<std::uint32_t>(value);
}

std::string ServerConfig::UserFile() const {
  return args_.get<std::string>("--userfile");
}

bool ServerConfig::EnableAdsFilter() const {
  return ParseBoolean(args_.get<std::string>("--enable-ads-filter"));
}

std::vector<std::string> ServerConfig::AdsBlocklistUrls() const {
  return fptn::common::utils::SplitCommaSeparated(
      args_.get<std::string>("--ads-blocklist-urls"));
}

std::string ServerConfig::DataDir() const {
  return args_.get<std::string>("--data-dir");
}

bool ServerConfig::EnableTorrentFilter() const {
  return ParseBoolean(args_.get<std::string>("--enable-torrent-filter"));
}

bool ServerConfig::EnableSpamFilter() const {
  return ParseBoolean(args_.get<std::string>("--enable-spam-filter"));
}

bool ServerConfig::EnableDomainBlacklistFilter() const {
  return ParseBoolean(
      args_.get<std::string>("--enable-domain-blacklist-filter"));
}

std::vector<std::string> ServerConfig::DomainBlacklistUrls() const {
  return fptn::common::utils::SplitCommaSeparated(
      args_.get<std::string>("--domain-blacklist-urls"));
}

std::string ServerConfig::DomainBlacklistFile() const {
  return args_.get<std::string>("--domain-blacklist-file");
}

std::string ServerConfig::PrometheusAccessKey() const {
  return args_.get<std::string>("--prometheus-access-key");
}

bool ServerConfig::UseRemoteServerAuth() const {
  return ParseBoolean(args_.get<std::string>("--use-remote-server-auth"));
}

std::string ServerConfig::RemoteServerAuthHost() const {
  return args_.get<std::string>("--remote-server-auth-host");
}

int ServerConfig::RemoteServerAuthPort() const {
  return args_.get<int>("--remote-server-auth-port");
}

bool ServerConfig::EnableDetectProbing() const {
  return ParseBoolean(args_.get<std::string>("--enable-detect-probing"));
}

[[nodiscard]]
std::vector<std::string> ServerConfig::AllowedSniList() const {
  auto list = common::utils::SplitCommaSeparated(
      args_.get<std::string>("--allowed-sni-list"));
  if (list.empty()) {
    list.emplace_back(FPTN_DEFAULT_SNI);
  }
  return list;
}

std::size_t ServerConfig::MaxActiveSessionsPerUser() const {
  return static_cast<std::size_t>(
      args_.get<int>("--max-active-sessions-per-user"));
}

[[nodiscard]]
std::string ServerConfig::ServerExternalIPs() const {
  return args_.get<std::string>("--server-external-ips");
}

[[nodiscard]]
int ServerConfig::MtuSize() const {
  return args_.get<int>("--mtu-size");
}

}  // namespace fptn::config
