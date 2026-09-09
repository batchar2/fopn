/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "routing/route_manager.h"

#include <algorithm>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <queue>  // NOLINT(build/include_order)

#include "common/network/net_interface.h"
#include "common/system/command.h"

namespace {
#ifdef _WIN32
std::mutex interface_number_mutex;
std::unordered_map<std::string, std::string> interface_numbers;

// The TUN adapter is recreated on every connect and gets a new index
void ResetWindowsInterfaceNumbers() {
  const std::scoped_lock lock(interface_number_mutex);
  interface_numbers.clear();
}

std::string EscapeForPowerShell(const std::string& value) {
  std::string escaped;
  for (const char symbol : value) {
    if (symbol == '\'') {
      escaped += '\'';
    }
    escaped += symbol;
  }
  return escaped;
}

std::string TrimLine(const std::string& line) {
  const std::size_t begin = line.find_first_not_of(" \t\r\n");
  if (begin == std::string::npos) {
    return {};
  }
  const std::size_t end = line.find_last_not_of(" \t\r\n");
  return line.substr(begin, end - begin + 1);
}

std::string GetWindowsInterfaceNumber(const std::string& interface_name) {
  if (interface_name.empty()) {
    return {};
  }

  {
    const std::scoped_lock lock(interface_number_mutex);
    const auto it = interface_numbers.find(interface_name);
    if (it != interface_numbers.end()) {
      return it->second;
    }
  }

  const std::string command =
      R"(powershell -NoProfile -NonInteractive -Command ")"
      R"($ErrorActionPreference='SilentlyContinue'; )"
      R"(try { [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false) } )"
      R"(catch {}; (Get-NetIPInterface -InterfaceAlias ')" +
      EscapeForPowerShell(interface_name) +
      R"(' | Select-Object -First 1).ifIndex")";

  std::vector<std::string> output;
  fptn::common::system::command::run(command, output);
  for (const auto& line : output) {
    const std::string index = TrimLine(line);
    if (index.empty() ||
        index.find_first_not_of("0123456789") != std::string::npos) {
      continue;
    }
    const std::scoped_lock lock(interface_number_mutex);
    interface_numbers[interface_name] = index;
    return index;
  }
  SPDLOG_WARN("Interface index was not found for '{}'", interface_name);
  return {};
}

std::pair<std::string, std::string> GetWindowsDefaultRoute(
    bool ipv6, const std::string& exclude_interface) {
  const std::string family = ipv6 ? "IPv6" : "IPv4";
  const std::string prefix = ipv6 ? "::/0" : "0.0.0.0/0";
  const std::string command =
      R"(powershell -NoProfile -NonInteractive -Command ")"
      R"($ErrorActionPreference='SilentlyContinue'; )"
      R"(try { [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false) } )"
      R"(catch {}; $r = Get-NetRoute -AddressFamily )" +
      family + " -DestinationPrefix '" + prefix + "'"
      " | Where-Object {$_.InterfaceAlias -ne '" +
      EscapeForPowerShell(exclude_interface) +
      "' -and $_.NextHop -ne '0.0.0.0' -and $_.NextHop -ne '::'}"
      " | Sort-Object {$_.RouteMetric + (Get-NetIPInterface -InterfaceIndex "
      "$_.ifIndex -AddressFamily " +
      family +
      ").InterfaceMetric}"
      " | Select-Object -First 1;" +
      R"( if ($r) { '{0}|{1}|{2}' -f $r.NextHop,$r.ifIndex,$r.InterfaceAlias }")";

  std::vector<std::string> output;
  fptn::common::system::command::run(command, output);
  for (const auto& line : output) {
    const std::size_t gateway_end = line.find('|');
    if (gateway_end == std::string::npos) {
      continue;
    }
    const std::size_t index_end = line.find('|', gateway_end + 1);
    if (index_end == std::string::npos) {
      continue;
    }
    const std::string gateway = line.substr(0, gateway_end);
    const std::string index =
        line.substr(gateway_end + 1, index_end - gateway_end - 1);
    const std::string alias = TrimLine(line.substr(index_end + 1));
    if (gateway.empty() || alias.empty() || index.empty() ||
        index.find_first_not_of("0123456789") != std::string::npos) {
      continue;
    }
    {
      const std::scoped_lock lock(interface_number_mutex);
      interface_numbers[alias] = index;
    }
    SPDLOG_INFO("Default {} route: gateway={} ifIndex={} interface='{}'",
        family, gateway, index, alias);
    return {gateway, alias};
  }
  SPDLOG_WARN("Default {} route was not found", family);
  return {};
}

std::pair<std::string, std::string> ParseIPv4CIDR(const std::string& network) {
  std::string ip = network;
  std::string mask = "255.255.255.255";

  std::size_t slash_pos = network.find('/');
  if (slash_pos != std::string::npos) {
    ip = network.substr(0, slash_pos);
    std::string cidr_str = network.substr(slash_pos + 1);

    try {
      int cidr = std::stoi(cidr_str);
      if (cidr >= 0 && cidr <= 32) {
        std::uint32_t mask_value = 0;
        if (cidr > 0) {
          mask_value = ~0u << (32 - cidr);
        }
        mask = fmt::format("{}.{}.{}.{}", (mask_value >> 24) & 0xFF,
            (mask_value >> 16) & 0xFF, (mask_value >> 8) & 0xFF,
            mask_value & 0xFF);
      }
    } catch (...) {
      SPDLOG_WARN("Warning: Failed to parse CIDR: {}", network);
    }
  }
  return {ip, mask};
}

std::pair<std::string, int> ParseIPv6CIDR(const std::string& network) {
  std::string ip = network;
  int prefix = 128;

  size_t slash_pos = network.find('/');
  if (slash_pos != std::string::npos) {
    ip = network.substr(0, slash_pos);
    std::string cidr_str = network.substr(slash_pos + 1);

    try {
      int cidr = std::stoi(cidr_str);
      if (cidr >= 0 && cidr <= 128) {
        prefix = cidr;
      }
    } catch (...) {
      SPDLOG_WARN("Warning: Failed to parse IPv6 CIDR: {}", network);
    }
  }
  return {ip, prefix};
}
#elif __linux__

#ifndef FPTN_OPENWRT
std::vector<std::string> GetLinuxDnsServers(const std::string& interface) {
  std::vector<std::string> dns_servers;

  const std::string command = fmt::format(
      "resolvectl status {} | grep 'DNS Servers:' | awk -F': ' '{{print $2}}'",
      interface);

  std::vector<std::string> output;
  fptn::common::system::command::run(command, output);

  if (!output.empty() && !output[0].empty()) {
    std::istringstream iss(output[0]);
    std::string server;
    while (iss >> server) {
      if (!server.empty()) {
        dns_servers.push_back(server);
      }
    }
  }
  return dns_servers;
}
#endif
#endif

bool AddIPv4RouteToSystem(const std::string& destination,
    const std::string& gateway_ip,
    const std::string& out_interface) {
  (void)gateway_ip;
  (void)out_interface;
  try {
#ifdef __linux__
    const std::string command =
        fmt::format(R"(ip route add {} via "{}" dev "{}" )", destination,
            gateway_ip, out_interface);
#elif __APPLE__
    const std::string command =
        fmt::format("route add -net {} {}", destination, gateway_ip);
#elif _WIN32
    auto [ip, mask] = ParseIPv4CIDR(destination);
    const std::string interface_number =
        out_interface.empty() ? std::string()
                              : GetWindowsInterfaceNumber(out_interface);
    const std::string interface_param =
        interface_number.empty() ? "" : "if " + interface_number;
    const std::string command =
        fmt::format("route add {} mask {} {} METRIC 2 {}", ip, mask, gateway_ip,
            interface_param);
#else
    return false;
#endif
    if (!fptn::common::system::command::run(command)) {
      SPDLOG_ERROR("Failed to add IPv4 route: {}", command);
    }
    return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Failed to add IPv4 route {}: {}", destination, e.what());
    return false;
  } catch (...) {
    SPDLOG_ERROR("Unknown error adding IPv4 route: {}", destination);
    return false;
  }
}

bool AddIPv6RouteToSystem(const std::string& destination,
    const std::string& gateway_ip,
    const std::string& out_interface) {
  (void)gateway_ip;
  (void)out_interface;
  try {
#ifdef __linux__
    const std::string command =
        fmt::format(R"(ip -6 route add {} via "{}" dev "{}" )", destination,
            gateway_ip, out_interface);
#elif __APPLE__
    const std::string command =
        fmt::format("route add -inet6 {} {}", destination, gateway_ip);
#elif _WIN32
    auto [ip, prefix] = ParseIPv6CIDR(destination);
    if (out_interface.empty()) {
      SPDLOG_ERROR("Interface name required for IPv6 route on Windows");
      return false;
    }
    const std::string interface_number =
        GetWindowsInterfaceNumber(out_interface);
    const std::string interface_param =
        interface_number.empty() ? out_interface : interface_number;
    const std::string command = fmt::format(
        "netsh interface ipv6 add route {}/{} \"{}\" {} store=active", ip,
        prefix, interface_param, gateway_ip);
#else
    return false;
#endif
    if (!fptn::common::system::command::run(command)) {
      SPDLOG_ERROR("Failed to add IPv6 route: {}", command);
    }
    return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Failed to add IPv6 route {}: {}", destination, e.what());
    return false;
  } catch (...) {
    SPDLOG_ERROR("Unknown error adding IPv6 route: {}", destination);
    return false;
  }
}

std::string BuildRemoveIPv4RouteCommand(const std::string& destination,
    const std::string& gateway_ip,
    const std::string& out_interface) {
  (void)gateway_ip;
  (void)out_interface;
  try {
#ifdef __linux__
    return fmt::format("ip route del {} via {} dev {}", destination, gateway_ip,
        out_interface);
#elif __APPLE__
    return fmt::format("route delete -net {} {}", destination, gateway_ip);
#elif _WIN32
    auto [ip, mask] = ParseIPv4CIDR(destination);
    std::string interface_param = "";
    if (!out_interface.empty()) {
      std::string interface_number = GetWindowsInterfaceNumber(out_interface);
      if (!interface_number.empty()) {
        interface_param = "if " + interface_number;
      }
    }
    return fmt::format(
        "route delete {} mask {} {} {}", ip, mask, gateway_ip, interface_param);
#else
    return {};
#endif
  } catch (const std::exception& e) {
    SPDLOG_ERROR(
        "Failed to build IPv4 route removal {}: {}", destination, e.what());
    return {};
  } catch (...) {
    SPDLOG_ERROR("Unknown error building IPv4 route removal: {}", destination);
    return {};
  }
}

std::string BuildRemoveIPv6RouteCommand(const std::string& destination,
    const std::string& gateway_ip,
    const std::string& out_interface) {
  (void)gateway_ip;
  (void)out_interface;
  try {
#ifdef __linux__
    return fmt::format("ip -6 route del {} via {} dev {}", destination,
        gateway_ip, out_interface);
#elif __APPLE__
    return fmt::format("route delete -inet6 {} {}", destination, gateway_ip);
#elif _WIN32
    auto [ip, prefix] = ParseIPv6CIDR(destination);
    if (out_interface.empty()) {
      SPDLOG_ERROR("Interface name required for IPv6 route removal on Windows");
      return {};
    }
    const std::string interface_number =
        GetWindowsInterfaceNumber(out_interface);
    const std::string interface_param =
        interface_number.empty() ? out_interface : interface_number;
    return fmt::format(
        "netsh interface ipv6 delete route {}/{} \"{}\" store=active", ip,
        prefix, interface_param);
#else
    return {};
#endif
  } catch (const std::exception& e) {
    SPDLOG_ERROR(
        "Failed to build IPv6 route removal {}: {}", destination, e.what());
    return {};
  } catch (...) {
    SPDLOG_ERROR("Unknown error building IPv6 route removal: {}", destination);
    return {};
  }
}

}  // namespace

namespace fptn::routing {
#ifdef __linux__
void HealStaleResolvConf() {
#ifndef FPTN_OPENWRT
  const std::string command =
      R"(sh -c "test -e /etc/resolv.conf.fptn-backup || exit 0; )"
      R"(chattr -i /etc/resolv.conf 2>/dev/null; )"
      R"(cp -f /etc/resolv.conf.fptn-backup /etc/resolv.conf; )"
      R"(rm -f /etc/resolv.conf.fptn-backup; )"
      R"(resolvectl flush-caches 2>/dev/null; true")";
  try {
    fptn::common::system::command::run(command);
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Failed to heal /etc/resolv.conf: {}", e.what());
  }
#endif
}
#endif

RouteManager::RouteManager(Config config)
    : running_(false), config_(std::move(config)) {
  route_workers_.reserve(kRouteWorkers);
  for (std::size_t i = 0; i < kRouteWorkers; ++i) {
    route_workers_.emplace_back(&RouteManager::RunRouteWorker, this);
  }
}

RouteManager::~RouteManager() {  // NOLINT(bugprone-exception-escape)
  StopRouteWorker();
  if (running_) {
    Clean();
  }
}

bool RouteManager::Apply(std::string tun_name) {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (running_) {
    return false;
  }

  tun_interface_name_ = std::move(tun_name);
  running_ = true;
#ifdef _WIN32
  ResetWindowsInterfaceNumbers();
#endif
  if (!config_.out_interface_name.empty()) {
    detected_out_interface_name_ = config_.out_interface_name;
  } else if (auto name = GetDefaultNetworkInterfaceName(tun_interface_name_);
             !name.empty()) {
    detected_out_interface_name_ = name;
  }
  if (!config_.gateway_ipv4.IsEmpty()) {
    detected_gateway_ipv4_ = config_.gateway_ipv4;
  } else if (auto gw4 = GetDefaultGatewayIPAddress(tun_interface_name_);
             !gw4.IsEmpty()) {
    detected_gateway_ipv4_ = gw4;
  }
  if (!config_.gateway_ipv6.IsEmpty()) {
    detected_gateway_ipv6_ = config_.gateway_ipv6;
  } else if (auto gw6 = GetDefaultGatewayIPv6Address(tun_interface_name_);
             !gw6.IsEmpty()) {
    detected_gateway_ipv6_ = gw6;
  }

  const bool has_custom_dns = config_.custom_dns_ipv4.IsValid();
  const std::string custom_dns = config_.custom_dns_ipv4.ToString();
  if (has_custom_dns) {
    SPDLOG_INFO("Custom DNS (IPv4):              {}", custom_dns);
  }

  SPDLOG_INFO("=== Setting up routing ===");
  SPDLOG_INFO(
      "IPTABLES VPN SERVER IP:         {}", config_.vpn_server_ip.ToString());
  SPDLOG_INFO(
      "IPTABLES OUT NETWORK INTERFACE: {}", detected_out_interface_name_);
  SPDLOG_INFO(
      "IPTABLES GATEWAY IP:            {}", detected_gateway_ipv4_.ToString());
  SPDLOG_INFO(
      "IPTABLES DNS SERVER:            {}", config_.dns_server_ipv4.ToString());
#ifdef __linux__
#ifndef FPTN_OPENWRT
  original_dns_servers_ = GetLinuxDnsServers(detected_out_interface_name_);
  for (const auto& dns : original_dns_servers_) {
    SPDLOG_INFO("Saved dns: {}", dns);
  }
  const std::string resolvectl_dns4 =
      has_custom_dns ? (custom_dns + " " + config_.dns_server_ipv4.ToString())
                     : config_.dns_server_ipv4.ToString();
#endif
  std::vector<std::string> commands = {
#ifndef FPTN_OPENWRT
      fmt::format("systemctl start sysctl"),
#endif
      fmt::format("sysctl -w net.ipv4.ip_forward=1"),
      fmt::format("sysctl -w net.ipv6.conf.default.disable_ipv6=0"),
      fmt::format("sysctl -w net.ipv6.conf.all.disable_ipv6=0"),
      fmt::format("sysctl -w net.ipv6.conf.lo.disable_ipv6=0"),
      fmt::format("sysctl -w net.ipv6.conf.all.forward=1"),
      fmt::format("sysctl -p"),
#ifndef FPTN_OPENWRT
      // iptables
      fmt::format("iptables -t nat -A POSTROUTING -o {} -m comment --comment "
                  "fptn -j MASQUERADE",
          detected_out_interface_name_),
      fmt::format("iptables -A FORWARD -i {} -o {} -m state --state "
                  "RELATED,ESTABLISHED -m comment --comment fptn -j ACCEPT",
          detected_out_interface_name_, tun_interface_name_),
      fmt::format(
          "iptables -A FORWARD -i {} -o {} -m comment --comment fptn -j ACCEPT",
          tun_interface_name_, detected_out_interface_name_),
      fmt::format(
          "iptables -A OUTPUT -o {} -d {} -m comment --comment fptn -j ACCEPT",
          detected_out_interface_name_, config_.vpn_server_ip.ToString()),
      fmt::format(
          "iptables -A INPUT -i {} -s {} -m comment --comment fptn -j ACCEPT",
          detected_out_interface_name_, config_.vpn_server_ip.ToString()),
#endif
      // IPv4 default & DNS route
      fmt::format(
          "ip route replace default dev {} scope link", tun_interface_name_),
      fmt::format("ip route add {} dev {}", config_.dns_server_ipv4.ToString(),
          tun_interface_name_),  // via TUN
      // IPv6 default
      fmt::format("ip -6 route add {} dev {}",
          config_.dns_server_ipv6.ToString(), tun_interface_name_),
      fmt::format("ip -6 route add default via {} dev {}",
          config_.dns_server_ipv6.ToString(), tun_interface_name_),
      // exclude vpn server
      fmt::format("ip route add {} via {} dev {}",
          config_.vpn_server_ip.ToString(), detected_gateway_ipv4_.ToString(),
          detected_out_interface_name_),
#ifndef FPTN_OPENWRT
      // Allow DNS responses from TUN (sport 53, not dport 53)
      fmt::format("iptables -A OUTPUT -o {} -p udp --sport 53 -m comment "
                  "--comment fptn -j ACCEPT",
          tun_interface_name_),
      fmt::format("iptables -A OUTPUT -o {} -p tcp --sport 53 -m comment "
                  "--comment fptn -j ACCEPT",
          tun_interface_name_),
      fmt::format("ip6tables -A OUTPUT -o {} -p udp --sport 53 -m comment "
                  "--comment fptn -j ACCEPT",
          tun_interface_name_),
      fmt::format("ip6tables -A OUTPUT -o {} -p tcp --sport 53 -m comment "
                  "--comment fptn -j ACCEPT",
          tun_interface_name_),
      // Block DNS requests on physical interface
      fmt::format("iptables -A OUTPUT -o {} -p udp --dport 53 -m comment "
                  "--comment fptn -j DROP",
          detected_out_interface_name_),
      fmt::format("iptables -A OUTPUT -o {} -p tcp --dport 53 -m comment "
                  "--comment fptn -j DROP",
          detected_out_interface_name_),
      // Block DNS IPv6
      fmt::format("ip6tables -A OUTPUT -o {} -p udp --dport 53 -m comment "
                  "--comment fptn -j DROP",
          detected_out_interface_name_),
      fmt::format("ip6tables -A OUTPUT -o {} -p tcp --dport 53 -m comment "
                  "--comment fptn -j DROP",
          detected_out_interface_name_),
      // Block DoT IPv4
      fmt::format("iptables -A OUTPUT -o {} -p udp --dport 853 -m comment "
                  "--comment fptn -j DROP",
          detected_out_interface_name_),
      fmt::format("iptables -A OUTPUT -o {} -p tcp --dport 853 -m comment "
                  "--comment fptn -j DROP",
          detected_out_interface_name_),
      // Block DoT IPv6
      fmt::format("ip6tables -A OUTPUT -o {} -p udp --dport 853 -m comment "
                  "--comment fptn -j DROP",
          detected_out_interface_name_),
      fmt::format("ip6tables -A OUTPUT -o {} -p tcp --dport 853 -m comment "
                  "--comment fptn -j DROP",
          detected_out_interface_name_),
      // Also allow DNS to specific DNS server IP
      fmt::format("iptables -A OUTPUT -d {} -p udp --dport 53 -m comment "
                  "--comment fptn -j ACCEPT",
          config_.dns_server_ipv4.ToString()),
      fmt::format("iptables -A OUTPUT -d {} -p tcp --dport 53 -m comment "
                  "--comment fptn -j ACCEPT",
          config_.dns_server_ipv4.ToString()),
      // DNS via resolvectl
      fmt::format("resolvectl resolv-conf false"),
      fmt::format("resolvectl dns {} {}", detected_out_interface_name_,
          resolvectl_dns4),
      fmt::format(
          "resolvectl default-route {} false", detected_out_interface_name_),
      fmt::format("resolvectl dns {} {}", tun_interface_name_, resolvectl_dns4),
      fmt::format("resolvectl default-route {} true", tun_interface_name_),
      fmt::format("resolvectl domain {} ~.", tun_interface_name_),
      fmt::format(
          R"(sh -c "test -e /etc/resolv.conf.fptn-backup || cp -f /etc/resolv.conf /etc/resolv.conf.fptn-backup")"),
      fmt::format(R"(sh -c "chattr -i /etc/resolv.conf")"),
      fmt::format(
          R"(sh -c "grep -q '^nameserver {}$' /etc/resolv.conf || sed -i '1i nameserver {}' /etc/resolv.conf")",
          config_.dns_server_ipv6.ToString(),
          config_.dns_server_ipv6.ToString()),
      fmt::format(
          R"(sh -c "grep -q '^nameserver {}$' /etc/resolv.conf || sed -i '1i nameserver {}' /etc/resolv.conf")",
          config_.dns_server_ipv4.ToString(),
          config_.dns_server_ipv4.ToString()),
      fmt::format(R"(sh -c "chattr +i /etc/resolv.conf")"),
      fmt::format("resolvectl flush-caches")
#endif
  };

  if (has_custom_dns) {
    commands.push_back(
        fmt::format("ip route add {} dev {}", custom_dns, tun_interface_name_));
#ifndef FPTN_OPENWRT
    commands.push_back(
        fmt::format("iptables -A OUTPUT -d {} -p udp --dport 53 -m comment "
                    "--comment fptn -j ACCEPT",
            custom_dns));
    commands.push_back(
        fmt::format("iptables -A OUTPUT -d {} -p tcp --dport 53 -m comment "
                    "--comment fptn -j ACCEPT",
            custom_dns));
    commands.push_back(fmt::format(
        R"(sh -c "chattr -i /etc/resolv.conf; grep -q '^nameserver {}$' /etc/resolv.conf || sed -i '1i nameserver {}' /etc/resolv.conf; chattr +i /etc/resolv.conf")",
        custom_dns, custom_dns));
#endif
  }

#elif __APPLE__
  const std::string mac_dns_servers =
      has_custom_dns ? (custom_dns + " " + config_.dns_server_ipv6.ToString() +
                           " " + config_.dns_server_ipv4.ToString())
                     : (config_.dns_server_ipv6.ToString() + " " +
                           config_.dns_server_ipv4.ToString());
  std::vector<std::string> commands = {
      fmt::format(
          R"(sh -c "networksetup -listallnetworkservices | grep -v '^An asterisk' | grep -v '^\* ' | xargs -I {{}} networksetup -setdnsservers '{{}}' empty")",
          config_.dns_server_ipv4.ToString()),  // clean DNS
      fmt::format("sysctl -w net.inet.ip.forwarding=1"),
      fmt::format("sysctl -w net.inet6.ip6.forwarding=1"),
      fmt::format(
          R"(sh -c "printf 'nat on {findOutInterfaceName} from {tunInterfaceName}:network to any -> ({findOutInterfaceName})
nat on {findOutInterfaceName} inet6 from {tunInterfaceName}:network to any -> ({findOutInterfaceName})
pass out on {findOutInterfaceName} proto tcp from any to {vpnServerIP}
pass in on {findOutInterfaceName} proto tcp from {vpnServerIP} to any
pass in on {tunInterfaceName} proto tcp from any to any
pass out on {tunInterfaceName} proto tcp from any to any
pass in on {tunInterfaceName} proto udp from any to any
pass out on {tunInterfaceName} proto udp from any to any
pass in on {tunInterfaceName} proto udp from any to any port 53
pass out on {tunInterfaceName} proto udp from any to any port 53
pass in on {tunInterfaceName} proto tcp from any to any port 53
pass out on {tunInterfaceName} proto tcp from any to any port 53
' > /tmp/pf.conf")",
          fmt::arg("findOutInterfaceName", detected_out_interface_name_),
          fmt::arg("tunInterfaceName", tun_interface_name_),
          fmt::arg("vpnServerIP", config_.vpn_server_ip.ToString())),
      fmt::format("pfctl -ef /tmp/pf.conf"),
      // IPv4 default & DNS route
      fmt::format(
          "route add -net 0.0.0.0/1 -interface {}", tun_interface_name_),
      fmt::format(
          "route add -net 128.0.0.0/1 -interface {}", tun_interface_name_),
      fmt::format("route add -host {} -interface {}",
          config_.dns_server_ipv4.ToString(), tun_interface_name_),  // via TUN
      // IPv6 routes
      fmt::format(
          "route add -inet6 -net ::0/1 -interface {}", tun_interface_name_),
      fmt::format(
          "route add -inet6 -net 8000::/1 -interface {}", tun_interface_name_),
      fmt::format("route add -inet6 default -interface {} 2>/dev/null || true",
          tun_interface_name_),
      fmt::format("route add -inet6 -host {} -interface {}",
          config_.dns_server_ipv6.ToString(), tun_interface_name_),
      // DNS IPv6 route
      fmt::format("route add -inet6 -host {} -interface {}",
          config_.dns_server_ipv6.ToString(), tun_interface_name_),
      // exclude vpn server & networks
      fmt::format("route add -host {} {}", config_.vpn_server_ip.ToString(),
          detected_gateway_ipv4_.ToString()),
      // DNS
      fmt::format("dscacheutil -flushcache"),
      fmt::format(
          R"(sh -c "networksetup -listallnetworkservices | grep -v '^An asterisk' | grep -v '^\* ' | xargs -I {{}} networksetup -setdnsservers '{{}}' {}")",
          mac_dns_servers)};

  if (has_custom_dns) {
    commands.push_back(fmt::format(
        "route add -host {} -interface {}", custom_dns, tun_interface_name_));
  }

#elif _WIN32
  const std::string win_interface_number =
      GetWindowsInterfaceNumber(tun_interface_name_);
  const std::string interface_info =
      win_interface_number.empty() ? "" : " if " + win_interface_number;
  const std::string backup_dns_cmd = R"PSHELL(powershell -Command "
    if (-not (Test-Path \"$env:TEMP\\fptn_orig_dns.txt\")) {
      $interface = ')PSHELL" +
                                     EscapeForPowerShell(
                                         detected_out_interface_name_) +
                                     R"PSHELL(';
      if (-not $interface) { $interface = ''; }
      if ($interface) {
        # IPv4
        $netshIPv4 = netsh interface ipv4 show dnsservers \"$interface\" 2>`$null;
        if ($netshIPv4 -match 'DHCP') {
          $output = @{IPv4='DHCP'};
        } else {
          $dns4 = Get-DnsClientServerAddress -InterfaceAlias $interface -AddressFamily IPv4 2>`$null | Select-Object -ExpandProperty ServerAddresses;
          if ($dns4) {
            $output = @{IPv4=($dns4 -join ',')};
          }
        }
        # IPv6
        $netshIPv6 = netsh interface ipv6 show dnsservers \"$interface\" 2>`$null;
        if ($netshIPv6 -match 'DHCP') {
          $output.IPv6 = 'DHCP';
        } else {
          $dns6 = Get-DnsClientServerAddress -InterfaceAlias $interface -AddressFamily IPv6 2>`$null | Select-Object -ExpandProperty ServerAddresses;
          if ($dns6) {
            $output.IPv6 = $dns6 -join ',';
          }
        }
        if ($output) {
          $output | ConvertTo-Json | Out-File \"$env:TEMP\\fptn_orig_dns.txt\" -Encoding UTF8;
        }
      }
    }")PSHELL";

  const std::string configure_dns_cmd = R"PSHELL(powershell -Command "
    $dns4 = ')PSHELL" + config_.dns_server_ipv4.ToString() +
                                        R"PSHELL(';
    $dns6 = ')PSHELL" + config_.dns_server_ipv6.ToString() +
                                        R"PSHELL(';
    $interface = ')PSHELL" +
                                        EscapeForPowerShell(
                                            detected_out_interface_name_) +
                                        R"PSHELL(';
    if (-not $interface) { $interface = ''; }
    if ($interface) {
      # IPv4
      Set-DnsClientServerAddress -InterfaceAlias $interface -ServerAddresses $dns4 -ErrorAction SilentlyContinue;
      netsh interface ipv4 set dnsservers name=\"$interface\" source=static address=$dns4 validate=no register=no 2>`$null;
      # IPv6
      Set-DnsClientServerAddress -InterfaceAlias $interface -ServerAddresses $dns6 -ErrorAction SilentlyContinue;
      netsh interface ipv6 set dnsservers name=\"$interface\" source=static address=$dns6 validate=no register=no 2>`$null;
  }")PSHELL";

  const std::string win_tun_dns4 =
      has_custom_dns ? custom_dns : config_.dns_server_ipv4.ToString();
  std::vector<std::string> commands = {
      fmt::format("route add {} mask 255.255.255.255 {} METRIC 2",
          config_.vpn_server_ip.ToString(), detected_gateway_ipv4_.ToString()),
      // Default gateway & dns
      fmt::format("route add 0.0.0.0 mask 0.0.0.0 {} METRIC 1 {}",
          config_.tun_interface_address_ipv4.ToString(), interface_info),
      fmt::format("route add {} mask 255.255.255.255 {} METRIC 2 {}",
          config_.dns_server_ipv4.ToString(),
          config_.tun_interface_address_ipv4.ToString(),
          interface_info),  // via TUN
      // DNS
      config_.enable_advanced_dns_management ? backup_dns_cmd : "",
      config_.enable_advanced_dns_management ? configure_dns_cmd : "",
      fmt::format(
          "netsh interface ip set dns name=\"{}\" static {} validate=no",
          tun_interface_name_, win_tun_dns4),
      // IPv6
      fmt::format(
          "netsh interface ipv6 add route ::/0 \"{}\" \"{}\" store=active",
          tun_interface_name_, config_.tun_interface_address_ipv6.ToString()),
      fmt::format("netsh interface ipv6 add dnsservers=\"{}\" \"{}\" index=1 "
                  "validate=no store=active",
          tun_interface_name_, config_.dns_server_ipv6.ToString()),
      // Flush DNS cache
      "ipconfig /flushdns"};

  if (has_custom_dns) {
    commands.push_back(fmt::format(
        "netsh interface ip add dns name=\"{}\" {} index=2 validate=no",
        tun_interface_name_, config_.dns_server_ipv4.ToString()));
    commands.push_back(fmt::format(
        "route add {} mask 255.255.255.255 {} METRIC 2 {}", custom_dns,
        config_.tun_interface_address_ipv4.ToString(), interface_info));
  }

#else
#error "Unsupported system!"
#endif
  try {
    for (const auto& cmd : commands) {
      if (cmd.empty()) {
        continue;
      }
      fptn::common::system::command::run(cmd);
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("IPTables error: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Undefined error");
  }

  const bool status = AddExcludeNetworks(config_.exclude_networks) &&
                      AddIncludeNetworks(config_.include_networks);
  if (status) {
    SPDLOG_INFO("=== Routing setup completed successfully ===");
  }
  return status;
}

bool RouteManager::Clean() {  // NOLINT(bugprone-exception-escape)
  if (!running_) {
    SPDLOG_INFO("No need to clean rules!");
    return true;
  }

  {
    const std::unique_lock<std::mutex> lock(queue_mutex_);  // mutex

    std::queue<PendingRoutes>().swap(route_queue_);
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  running_ = false;

  const bool has_custom_dns = config_.custom_dns_ipv4.IsValid();
  const std::string custom_dns = config_.custom_dns_ipv4.ToString();

  std::vector<std::string> del_commands;

  // clean dns ipv4
  for (const auto& ip : dns_routes_ipv4_) {
    std::string interface_name;
    if (ip.policy == RoutingPolicy::kExcludeFromVpn) {
      if (!detected_out_interface_name_.empty()) {
        interface_name = detected_out_interface_name_;
      } else if (!config_.out_interface_name.empty()) {
        interface_name = config_.out_interface_name;
      } else {
        interface_name = GetDefaultNetworkInterfaceName(tun_interface_name_);
      }
    } else {
      interface_name = tun_interface_name_;
    }
    del_commands.push_back(BuildRemoveIPv4RouteCommand(
        ip.destination, detected_gateway_ipv4_.ToString(), interface_name));
  }
  dns_routes_ipv4_.clear();

  // clean dns ipv6
  for (const auto& ip : dns_routes_ipv6_) {
    std::string interface_name;
    if (ip.policy == RoutingPolicy::kExcludeFromVpn) {
      if (!detected_out_interface_name_.empty()) {
        interface_name = detected_out_interface_name_;
      } else if (!config_.out_interface_name.empty()) {
        interface_name = config_.out_interface_name;
      } else {
        interface_name = GetDefaultNetworkInterfaceName(tun_interface_name_);
      }
    } else {
      interface_name = tun_interface_name_;
    }
    del_commands.push_back(BuildRemoveIPv6RouteCommand(
        ip.destination, detected_gateway_ipv6_.ToString(), interface_name));
  }
  dns_routes_ipv6_.clear();

  const std::string exclude_interface_name =
      !detected_out_interface_name_.empty() ? detected_out_interface_name_
                                            : config_.out_interface_name;

  // clean route ipv4
  for (const auto& route : additional_routes_ipv4_) {
    if (route.policy == RoutingPolicy::kExcludeFromVpn) {
      del_commands.push_back(BuildRemoveIPv4RouteCommand(route.destination,
          detected_gateway_ipv4_.ToString(), exclude_interface_name));
    } else {
      // Include route - remove through VPN interface
      del_commands.push_back(BuildRemoveIPv4RouteCommand(route.destination,
          config_.tun_interface_address_ipv4.ToString(), tun_interface_name_));
    }
  }
  additional_routes_ipv4_.clear();

  // Remove additional IPv6 routes
  for (const auto& route : additional_routes_ipv6_) {
    if (route.policy == RoutingPolicy::kExcludeFromVpn) {
      del_commands.push_back(BuildRemoveIPv6RouteCommand(route.destination,
          detected_gateway_ipv6_.ToString(), exclude_interface_name));
    } else {
      // Include route - remove through VPN interface
      del_commands.push_back(BuildRemoveIPv6RouteCommand(route.destination,
          config_.tun_interface_address_ipv6.ToString(), tun_interface_name_));
    }
  }
  additional_routes_ipv6_.clear();

  fptn::common::system::command::run_batch(del_commands);

#ifdef __linux__
  std::vector<std::string> commands = {
#ifndef FPTN_OPENWRT
      fmt::format("iptables -t nat -D POSTROUTING -o {} -m comment --comment "
                  "fptn -j MASQUERADE",
          detected_out_interface_name_),
      fmt::format("iptables -D FORWARD -i {} -o {} -m state --state "
                  "RELATED,ESTABLISHED -m comment --comment fptn -j ACCEPT",
          detected_out_interface_name_, tun_interface_name_),
      fmt::format(
          "iptables -D FORWARD -i {} -o {} -m comment --comment fptn -j ACCEPT",
          tun_interface_name_, detected_out_interface_name_),
      fmt::format(
          "iptables -D OUTPUT -o {} -d {} -m comment --comment fptn -j ACCEPT",
          detected_out_interface_name_, config_.vpn_server_ip.ToString()),
      fmt::format(
          "iptables -D INPUT -i {} -s {} -m comment --comment fptn -j ACCEPT",
          detected_out_interface_name_, config_.vpn_server_ip.ToString()),
#endif
      // restore default gateway
      fmt::format("ip route replace default via {} dev {}",
          detected_gateway_ipv4_.ToString(), detected_out_interface_name_),
      // del ipv6 route
      fmt::format("ip route del {} via {} dev {}",
          config_.vpn_server_ip.ToString(), detected_gateway_ipv4_.ToString(),
          detected_out_interface_name_),
      // Delete DNS server route
      fmt::format("ip route del {} dev {}", config_.dns_server_ipv4.ToString(),
          tun_interface_name_),
#ifndef FPTN_OPENWRT
      fmt::format(
          R"(sh -c "chattr -i /etc/resolv.conf; sed -i '/^nameserver {}$/d' /etc/resolv.conf; sed -i '/^nameserver {}$/d' /etc/resolv.conf; rm -f /etc/resolv.conf.fptn-backup")",
          config_.dns_server_ipv4.ToString(),
          config_.dns_server_ipv6.ToString()),
      // Delete DNS to specific DNS server IP rules
      fmt::format("iptables -D OUTPUT -d {} -p udp --dport 53 -m comment "
                  "--comment fptn -j ACCEPT",
          config_.dns_server_ipv4.ToString()),
      fmt::format("iptables -D OUTPUT -d {} -p tcp --dport 53 -m comment "
                  "--comment fptn -j ACCEPT",
          config_.dns_server_ipv4.ToString()),
      // Delete DNS block rules IPv4
      fmt::format("iptables -D OUTPUT -o {} -p udp --dport 53 -m comment "
                  "--comment fptn -j DROP",
          detected_out_interface_name_),
      fmt::format("iptables -D OUTPUT -o {} -p tcp --dport 53 -m comment "
                  "--comment fptn -j DROP",
          detected_out_interface_name_),
      fmt::format("iptables -D OUTPUT -o {} -p udp --dport 853 -m comment "
                  "--comment fptn -j DROP",
          detected_out_interface_name_),
      fmt::format("iptables -D OUTPUT -o {} -p tcp --dport 853 -m comment "
                  "--comment fptn -j DROP",
          detected_out_interface_name_),
      // Delete DNS block rules IPv6
      fmt::format("ip6tables -D OUTPUT -o {} -p udp --dport 53 -m comment "
                  "--comment fptn -j DROP",
          detected_out_interface_name_),
      fmt::format("ip6tables -D OUTPUT -o {} -p tcp --dport 53 -m comment "
                  "--comment fptn -j DROP",
          detected_out_interface_name_),
      fmt::format("ip6tables -D OUTPUT -o {} -p udp --dport 853 -m comment "
                  "--comment fptn -j DROP",
          detected_out_interface_name_),
      fmt::format("ip6tables -D OUTPUT -o {} -p tcp --dport 853 -m comment "
                  "--comment fptn -j DROP",
          detected_out_interface_name_),
      // Delete TUN allow rules IPv4
      fmt::format("iptables -D OUTPUT -o {} -p udp --sport 53 -m comment "
                  "--comment fptn -j ACCEPT",
          tun_interface_name_),
      fmt::format("iptables -D OUTPUT -o {} -p tcp --sport 53 -m comment "
                  "--comment fptn -j ACCEPT",
          tun_interface_name_),
      // Delete TUN allow rules IPv6
      fmt::format("ip6tables -D OUTPUT -o {} -p udp --sport 53 -m comment "
                  "--comment fptn -j ACCEPT",
          tun_interface_name_),
      fmt::format("ip6tables -D OUTPUT -o {} -p tcp --sport 53 -m comment "
                  "--comment fptn -j ACCEPT",
          tun_interface_name_)
#endif
  };

  if (has_custom_dns) {
    commands.push_back(
        fmt::format("ip route del {} dev {}", custom_dns, tun_interface_name_));
#ifndef FPTN_OPENWRT
    commands.push_back(
        fmt::format("iptables -D OUTPUT -d {} -p udp --dport 53 -m comment "
                    "--comment fptn -j ACCEPT",
            custom_dns));
    commands.push_back(
        fmt::format("iptables -D OUTPUT -d {} -p tcp --dport 53 -m comment "
                    "--comment fptn -j ACCEPT",
            custom_dns));
    commands.push_back(fmt::format(
        R"(sh -c "chattr -i /etc/resolv.conf; sed -i '/^nameserver {}$/d' /etc/resolv.conf")",
        custom_dns));
#endif
  }

  if (!detected_gateway_ipv6_.IsEmpty()) {
    commands.push_back(fmt::format("ip -6 route del {} dev {}",
        config_.dns_server_ipv6.ToString(), tun_interface_name_));
    commands.push_back(fmt::format("ip -6 route del default via {} dev {}",
        config_.dns_server_ipv6.ToString(), tun_interface_name_));
    commands.push_back(fmt::format("ip -6 route replace default via {} dev {}",
        detected_gateway_ipv6_.ToString(), detected_out_interface_name_));
  }

#ifndef FPTN_OPENWRT
  // Restore DNS
  if (!original_dns_servers_.empty()) {
    std::string all_dns;
    for (const auto& dns : original_dns_servers_) {
      if (!all_dns.empty()) {
        all_dns += " ";
      }
      all_dns += dns;
    }
    commands.push_back(fmt::format(
        "resolvectl dns {} {}", detected_out_interface_name_, all_dns));
    commands.push_back(
        fmt::format("resolvectl domain {} .", detected_out_interface_name_));
    commands.push_back(fmt::format(
        "resolvectl default-route {} true", detected_out_interface_name_));
    SPDLOG_INFO("Restoring {} DNS servers for {}", original_dns_servers_.size(),
        detected_out_interface_name_);
  } else {
    commands.push_back(
        fmt::format("resolvectl revert {}", detected_out_interface_name_));
    SPDLOG_INFO("Reverting DNS to DHCP for {}", detected_out_interface_name_);
  }
  commands.emplace_back("resolvectl flush-caches");
#endif

#elif __APPLE__
  std::vector<std::string> commands = {
      fmt::format(
          R"(sh -c "networksetup -listallnetworkservices | grep -v '^An asterisk' | grep -v '^\* ' | xargs -I {{}} networksetup -setdnsservers '{{}}' empty")"),  // clean DNS
      fmt::format("pfctl -F all -f /etc/pf.conf"),
      // del routes
      fmt::format("route delete -host {} -interface {}",
          config_.dns_server_ipv4.ToString(),
          tun_interface_name_),  // via TUN
      fmt::format(
          "route delete -net 0.0.0.0/1 -interface {}", tun_interface_name_),
      fmt::format(
          "route delete -net 128.0.0.0/1 -interface {}", tun_interface_name_),
      // del IPv6 routes
      fmt::format(
          "route delete -inet6 -net ::0/1 -interface {}", tun_interface_name_),
      fmt::format("route delete -inet6 -net 8000::/1 -interface {}",
          tun_interface_name_),
      fmt::format("route delete -host {} {}", config_.vpn_server_ip.ToString(),
          detected_gateway_ipv4_.ToString()),
      // DNS
      fmt::format(
          R"(sh -c "networksetup -listallnetworkservices | grep -v '^An asterisk' | grep -v '^\* ' | xargs -I {{}} networksetup -setdnsservers '{{}}' empty")")  // clean DNS
  };

  if (has_custom_dns) {
    commands.push_back(fmt::format("route delete -host {} -interface {}",
        custom_dns, tun_interface_name_));
  }
#elif _WIN32
  std::string current_interface_name = detected_out_interface_name_;
  if (current_interface_name.empty()) {
    current_interface_name = config_.out_interface_name;
  }
  if (current_interface_name.empty()) {
    current_interface_name =
        GetDefaultNetworkInterfaceName(tun_interface_name_);
  }
  const std::string restore_dns_cmd = R"PSHELL(powershell -Command "
    $interface = ')PSHELL" +
                                      EscapeForPowerShell(
                                          current_interface_name) +
                                      R"PSHELL(';
    if ($interface) {
        if (Test-Path \"$env:TEMP\\fptn_orig_dns.txt\") {
            $config = Get-Content \"$env:TEMP\\fptn_orig_dns.txt\" -Raw | ConvertFrom-Json;
            # IPv4
            if ($config.IPv4 -eq 'DHCP') {
                netsh interface ip set dns \"$interface\" dhcp
            } elseif ($config.IPv4) {
                $dns4Servers = $config.IPv4 -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' };
                if ($dns4Servers.Count -gt 0) {
                    netsh interface ip set dns \"$interface\" static $($dns4Servers[0])
                    if ($dns4Servers.Count -gt 1) {
                        netsh interface ip add dns \"$interface\" $($dns4Servers[1]) index=2
                    }
                }
            }
            # IPv6
            if ($config.IPv6 -eq 'DHCP') {
                netsh interface ipv6 set dnsservers \"$interface\" dhcp
            } elseif ($config.IPv6) {
                $dns6Servers = $config.IPv6 -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' };
                if ($dns6Servers.Count -gt 0) {
                    netsh interface ipv6 set dnsservers \"$interface\" static $($dns6Servers[0]) primary
                    if ($dns6Servers.Count -gt 1) {
                        netsh interface ipv6 add dnsservers \"$interface\" $($dns6Servers[1]) index=2
                    }
                }
            }
            Remove-Item \"$env:TEMP\\fptn_orig_dns.txt\" -Force
        } else {
            netsh interface ip set dns \"$interface\" dhcp
            netsh interface ipv6 set dnsservers \"$interface\" dhcp
        }
    }")PSHELL";

  std::vector<std::string> commands = {
      config_.enable_advanced_dns_management ? restore_dns_cmd : "",
      // Remove routes
      fmt::format("route delete {} mask 255.255.255.255",
          config_.vpn_server_ip.ToString()),
      fmt::format("route delete 0.0.0.0 mask 0.0.0.0 {}",
          config_.tun_interface_address_ipv4.ToString()),
      fmt::format("route delete {} mask 255.255.255.255",
          config_.dns_server_ipv4.ToString()),
      fmt::format("netsh interface ipv6 delete route ::/0 \"{}\" store=active",
          tun_interface_name_),

      // Final cleanup
      "ipconfig /flushdns"};

  if (has_custom_dns) {
    commands.push_back(
        fmt::format("route delete {} mask 255.255.255.255", custom_dns));
  }

#else
#error "Unsupported system!"
#endif
  try {
    for (const auto& cmd : commands) {
      if (cmd.empty()) {
        continue;
      }
      fptn::common::system::command::run(cmd);
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("IPTables error: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Undefined error");
  }
  running_ = false;
  return true;
}

bool RouteManager::AddDnsRoutesIPv4(
    const std::vector<fptn::common::network::IPv4Address>& ips,
    const RoutingPolicy policy) {
  return Enqueue({.ipv4 = ips, .ipv6 = {}, .policy = policy});
}

bool RouteManager::AddExcludeRouteWithReset(
    const fptn::common::network::IPv4Address& ip,
    fptn::common::network::IPPacketPtr reset) {
  return Enqueue({.ipv4 = {ip},
      .ipv6 = {},
      .policy = RoutingPolicy::kExcludeFromVpn,
      .reset_packet = std::move(reset)});
}

void RouteManager::SetTunSink(
    std::function<void(fptn::common::network::IPPacketPtr)> sink) {
  const std::unique_lock<std::mutex> lock(queue_mutex_);  // mutex
  tun_sink_ = std::move(sink);
}

bool RouteManager::AddDnsRoutesIPv6(
    const std::vector<fptn::common::network::IPv6Address>& ips,
    const RoutingPolicy policy) {
  return Enqueue({.ipv4 = {}, .ipv6 = ips, .policy = policy});
}

bool RouteManager::Enqueue(PendingRoutes routes) {
  constexpr std::size_t kMaxQueueSize = 1024;

  {
    const std::unique_lock<std::mutex> lock(queue_mutex_);  // mutex

    if (route_queue_.size() >= kMaxQueueSize) {
      SPDLOG_WARN("DNS route queue is full, dropping addresses");
      return false;
    }
    route_queue_.push(std::move(routes));
  }
  queue_cv_.notify_one();
  return true;
}

void RouteManager::RunRouteWorker() {
  while (worker_running_) {
    PendingRoutes routes;
    std::function<void(fptn::common::network::IPPacketPtr)> sink;
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);  // mutex

      queue_cv_.wait(
          lock, [this]() { return !route_queue_.empty() || !worker_running_; });
      if (!worker_running_) {
        break;
      }
      routes = std::move(route_queue_.front());
      route_queue_.pop();
      if (routes.reset_packet) {
        sink = tun_sink_;
      }
    }

    if (!running_) {
      continue;
    }
    if (!routes.ipv4.empty()) {
      ApplyDnsRoutesIPv4(routes.ipv4, routes.policy);
    }
    if (!routes.ipv6.empty()) {
      ApplyDnsRoutesIPv6(routes.ipv6, routes.policy);
    }
    if (routes.reset_packet && sink) {
      sink(std::move(routes.reset_packet));
    }
  }
}

void RouteManager::StopRouteWorker() {
  worker_running_ = false;
  queue_cv_.notify_all();
  for (auto& worker : route_workers_) {
    if (worker.joinable()) {
      worker.join();
    }
  }
  route_workers_.clear();
}

bool RouteManager::ApplyDnsRoutesIPv4(
    const std::vector<fptn::common::network::IPv4Address>& ips,
    const RoutingPolicy policy) {
  std::string interface_name;
  std::string gateway_ip;
  std::string tun_name;

  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    if (!running_) {
      return false;
    }
    tun_name = tun_interface_name_;
    if (policy == RoutingPolicy::kExcludeFromVpn) {
      if (!detected_out_interface_name_.empty()) {
        interface_name = detected_out_interface_name_;
      } else {
        interface_name = config_.out_interface_name;
      }
      if (!detected_gateway_ipv4_.IsEmpty()) {
        gateway_ip = detected_gateway_ipv4_.ToString();
      }
    } else {
      interface_name = tun_interface_name_;
      gateway_ip = config_.tun_interface_address_ipv4.ToString();
    }
  }
  if (interface_name.empty()) {
    interface_name = fptn::routing::GetDefaultNetworkInterfaceName(tun_name);
  }

  if (interface_name.empty()) {
    SPDLOG_WARN(
        "Cannot add DNS IPv4 routes: interface name is empty for policy {}",
        policy == RoutingPolicy::kExcludeFromVpn ? "EXCLUDE" : "INCLUDE");
    return false;
  }

  if (gateway_ip.empty()) {
    SPDLOG_WARN("Cannot add DNS IPv4 routes: gateway IP is empty for policy {}",
        policy == RoutingPolicy::kExcludeFromVpn ? "EXCLUDE" : "INCLUDE");
    return false;
  }

  std::vector<RouteEntry> entries_to_add;
  {
    const std::unique_lock<std::mutex> lock(mutex_);

    for (const auto& ip : ips) {
      std::string ip_str = ip.ToString();
      RouteEntry entry{.destination = ip_str, .policy = policy};

      if (!dns_routes_ipv4_.contains(entry)) {
        dns_routes_ipv4_.insert(entry);
        entries_to_add.push_back(std::move(entry));
      }
    }
  }

  if (entries_to_add.empty()) {
    return true;
  }

  bool status = true;
  for (const auto& entry : entries_to_add) {
    try {
      const bool rv =
          AddIPv4RouteToSystem(entry.destination, gateway_ip, interface_name);

      if (rv) {
        const std::string policy_str = (policy == RoutingPolicy::kExcludeFromVpn
                                            ? "EXCLUDE (bypass VPN)"
                                            : "INCLUDE (through VPN)");
        SPDLOG_INFO("DNS route added: {} [{}]", entry.destination, policy_str);
      } else {
        SPDLOG_WARN("Failed to add DNS route: {}", entry.destination);

        const std::unique_lock<std::mutex> lock(mutex_);
        dns_routes_ipv4_.erase(entry);
        status = false;
      }
    } catch (const std::exception& e) {
      SPDLOG_WARN("Exception adding DNS IPv4 route {}: {}", entry.destination,
          e.what());

      const std::unique_lock<std::mutex> lock(mutex_);
      dns_routes_ipv4_.erase(entry);
      status = false;
    }
  }

  return status;
}

bool RouteManager::ApplyDnsRoutesIPv6(
    const std::vector<fptn::common::network::IPv6Address>& ips,
    const RoutingPolicy policy) {
  std::string interface_name;
  std::string gateway_ip;
  std::string tun_name;

  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    if (!running_) {
      return false;
    }
    tun_name = tun_interface_name_;
    if (policy == RoutingPolicy::kExcludeFromVpn) {
      if (!detected_out_interface_name_.empty()) {
        interface_name = detected_out_interface_name_;
      } else {
        interface_name = config_.out_interface_name;
      }
      if (!detected_gateway_ipv6_.IsEmpty()) {
        gateway_ip = detected_gateway_ipv6_.ToString();
      }
    } else {
      interface_name = tun_interface_name_;
      gateway_ip = config_.tun_interface_address_ipv6.ToString();
    }
  }
  if (interface_name.empty()) {
    interface_name = fptn::routing::GetDefaultNetworkInterfaceName(tun_name);
  }

  if (interface_name.empty()) {
    SPDLOG_WARN(
        "Cannot add DNS IPv6 routes: interface name is empty for policy {}",
        policy == RoutingPolicy::kExcludeFromVpn ? "EXCLUDE" : "INCLUDE");
    return false;
  }

  if (gateway_ip.empty()) {
    SPDLOG_WARN("Cannot add DNS IPv6 routes: gateway IP is empty for policy {}",
        policy == RoutingPolicy::kExcludeFromVpn ? "EXCLUDE" : "INCLUDE");
    return false;
  }

  std::vector<RouteEntry> entries_to_add;
  {
    const std::unique_lock<std::mutex> lock(mutex_);

    for (const auto& ip : ips) {
      std::string ip_str = ip.ToString();
      RouteEntry entry{.destination = ip_str, .policy = policy};

      if (!dns_routes_ipv6_.contains(entry)) {
        dns_routes_ipv6_.insert(entry);
        entries_to_add.push_back(std::move(entry));
      }
    }
  }

  if (entries_to_add.empty()) {
    return true;
  }

  bool status = true;
  for (const auto& entry : entries_to_add) {
    try {
      const bool rv =
          AddIPv6RouteToSystem(entry.destination, gateway_ip, interface_name);

      if (rv) {
        const std::string policy_str = (policy == RoutingPolicy::kExcludeFromVpn
                                            ? "EXCLUDE (bypass VPN)"
                                            : "INCLUDE (through VPN)");
        SPDLOG_INFO(
            "DNS IPv6 route added: {} [{}]", entry.destination, policy_str);
      } else {
        SPDLOG_WARN("Failed to add DNS IPv6 route: {}", entry.destination);
        status = false;
      }
    } catch (const std::exception& e) {
      SPDLOG_WARN("Exception adding DNS IPv6 route {}: {}", entry.destination,
          e.what());
      status = false;
    }
  }
  return status;
}

bool RouteManager::AddExcludeNetworks(
    const std::vector<std::string>& networks) {
  std::vector<std::pair<std::string, bool>> networks_to_add;
  {
    for (const auto& network : networks) {
      if (network.empty()) {
        continue;
      }

      const bool is_ipv6 = network.find(':') != std::string::npos;  // NOLINT
      RouteEntry entry{
          .destination = network, .policy = RoutingPolicy::kExcludeFromVpn};

      if (is_ipv6) {
        if (!additional_routes_ipv6_.contains(entry)) {
          networks_to_add.emplace_back(network, true);
          additional_routes_ipv6_.insert(entry);
        }
      } else {
        if (!additional_routes_ipv4_.contains(entry)) {
          networks_to_add.emplace_back(network, false);
          additional_routes_ipv4_.insert(entry);
        }
      }
    }
    if (networks_to_add.empty()) {
      return true;
    }
  }

  const std::string interface_name = !detected_out_interface_name_.empty()
                                         ? detected_out_interface_name_
                                         : config_.out_interface_name;

  bool all_success = true;
  for (const auto& [network, is_ipv6] : networks_to_add) {
    try {
      bool success = false;

      if (is_ipv6) {
        success = AddIPv6RouteToSystem(
            network, detected_gateway_ipv6_.ToString(), interface_name);
      } else {
        success = AddIPv4RouteToSystem(
            network, detected_gateway_ipv4_.ToString(), interface_name);
      }

      if (success) {
        SPDLOG_INFO(
            "Added {} exclude network: {}", is_ipv6 ? "IPv6" : "IPv4", network);
      } else {
        SPDLOG_WARN("Failed to add route: {}", network);
        all_success = false;
      }
    } catch (const std::exception& e) {
      SPDLOG_WARN("Failed to add exclude network '{}': {}", network, e.what());
      RouteEntry entry{
          .destination = network, .policy = RoutingPolicy::kExcludeFromVpn};
      if (is_ipv6) {
        additional_routes_ipv6_.erase(entry);
      } else {
        additional_routes_ipv4_.erase(entry);
      }
      all_success = false;
    }
  }
  return all_success;
}

bool RouteManager::AddIncludeNetworks(
    const std::vector<std::string>& networks) {
  std::vector<std::pair<std::string, bool>> networks_to_add;
  {
    for (const auto& network : networks) {
      if (network.empty()) {
        continue;
      }

      const bool is_ipv6 = network.find(':') != std::string::npos;  // NOLINT
      RouteEntry entry{
          .destination = network, .policy = RoutingPolicy::kIncludeInVpn};

      if (is_ipv6) {
        if (!additional_routes_ipv6_.contains(entry)) {
          networks_to_add.emplace_back(network, true);
          additional_routes_ipv6_.insert(entry);
        }
      } else {
        if (!additional_routes_ipv4_.contains(entry)) {
          networks_to_add.emplace_back(network, false);
          additional_routes_ipv4_.insert(entry);
        }
      }
    }
    if (networks_to_add.empty()) {
      return true;
    }
  }

  bool all_success = true;
  for (const auto& [network, is_ipv6] : networks_to_add) {
    try {
      bool success = false;

      if (is_ipv6) {
        success = AddIPv6RouteToSystem(network,
            config_.tun_interface_address_ipv6.ToString(), tun_interface_name_);
      } else {
        success = AddIPv4RouteToSystem(network,
            config_.tun_interface_address_ipv4.ToString(), tun_interface_name_);
      }

      if (success) {
        SPDLOG_INFO(
            "Added {} include network: {}", is_ipv6 ? "IPv6" : "IPv4", network);
      } else {
        SPDLOG_ERROR("Failed to add route: {}", network);
        all_success = false;
      }
    } catch (const std::exception& e) {
      SPDLOG_WARN("Failed to add include network '{}': {}", network, e.what());
      all_success = false;
    }
  }
  return all_success;
}

// NOLINT(bugprone-exception-escape)
fptn::common::network::IPv4Address ResolveDomain(const std::string& domain) {
  try {
    try {
      // error test
      boost::asio::ip::make_address(domain);
      return fptn::common::network::IPv4Address::Create(domain);
    } catch (const std::exception&) {  // NOLINT(bugprone-empty-catch)
      // Not a valid IP address, proceed with domain name resolution
    }
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::asio::ip::tcp::resolver::results_type endpoints =
        resolver.resolve(domain, "");
    for (const auto& endpoint : endpoints) {
      return fptn::common::network::IPv4Address(
          endpoint.endpoint().address().to_string());
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Error resolving domain: {}", e.what());
  }
  return fptn::common::network::IPv4Address(domain);
}

fptn::common::network::IPv4Address GetDefaultGatewayIPAddress(
    const std::string& exclude_interface) {
#ifdef _WIN32
  const auto [gateway, alias] =
      GetWindowsDefaultRoute(false, exclude_interface);
  return fptn::common::network::IPv4Address::Create(gateway);
#else
  (void)exclude_interface;
  try {
#ifdef __linux__
    const std::string command =
        "for ip in 8.8.8.8 8.8.4.4 77.88.8.8; do r=$(ip route get $ip "
        "2>/dev/null | awk '{print $3; exit}'); [ -n \"$r\" ] && echo \"$r\" "
        "&& "
        "break; done; "
        "[ -z \"$r\" ] && ip -4 route show default 2>/dev/null "
        "| awk '{print $3; exit}'";
#elif __APPLE__
    const std::string command =
        "for ip in 8.8.8.8 8.8.4.4 77.88.8.8; do r=$(route get $ip 2>/dev/null "
        "| grep gateway | awk '{print $2}'); [ -n \"$r\" ] && echo \"$r\" && "
        "break; done";
#else
#error "Unsupported system!"
#endif
    std::vector<std::string> cmd_stdout;
    fptn::common::system::command::run(command, cmd_stdout);
    for (const auto& line : cmd_stdout) {
      std::string result = line;
      result.erase(
          // NOLINTNEXTLINE(modernize-use-ranges)
          std::remove_if(result.begin(), result.end(),
              [](char c) {
                /* Allow: a-z, A-Z, 0-9, dot, dash */
                return !std::isalnum(c) && c != '.' && c != '-' && c != '_';
              }),
          result.end());
      if (!result.empty()) {
        return ResolveDomain(result);
      }
    }
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("Error: Failed to retrieve the default gateway IP address. {}",
        ex.what());
  }
  return {};
#endif
}

fptn::common::network::IPv6Address GetDefaultGatewayIPv6Address(
    const std::string& exclude_interface) {
#ifdef _WIN32
  const auto [gateway, alias] = GetWindowsDefaultRoute(true, exclude_interface);
  return fptn::common::network::IPv6Address::Create(gateway);
#else
  (void)exclude_interface;
  try {
#ifdef __linux__
    const std::string command =
        "ip -6 route | grep default | head -1 | awk '{print $3}'";
#elif __APPLE__
    const std::string command =
        "route get -inet6 default | grep gateway | awk '{print $2}'";
#else
    return {};
#endif
    std::vector<std::string> cmd_stdout;
    fptn::common::system::command::run(command, cmd_stdout);

    for (const auto& line : cmd_stdout) {
      std::string result = line;
      std::erase_if(result, [](const char c) {
        return !std::isalnum(c) && c != ':' && c != '.' && c != '-';
      });
      if (result.empty()) {
        continue;
      }
      const auto addr = fptn::common::network::IPv6Address::Create(result);
      if (addr.IsValid()) {
        return addr;
      }
    }
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("Error getting IPv6 gateway: {}", ex.what());
  }
  return {};
#endif
}

std::string GetDefaultNetworkInterfaceName(
    const std::string& exclude_interface) {
#ifdef _WIN32
  const auto [gateway, alias] =
      GetWindowsDefaultRoute(false, exclude_interface);
  return alias;
#else
  (void)exclude_interface;
  try {
#ifdef __linux__
    const std::string command =
        "for ip in 8.8.8.8 8.8.4.4 77.88.8.8; do r=$(ip route get $ip "
        "2>/dev/null | awk '{print $5; exit}'); [ -n \"$r\" ] && echo \"$r\" "
        "&& "
        "break; done";
#elif __APPLE__
    const std::string command =
        "for ip in 8.8.8.8 8.8.4.4 77.88.8.8; do r=$(route get $ip 2>/dev/null "
        "| grep interface | awk '{print $2}'); [ -n \"$r\" ] && echo \"$r\" && "
        "break; done";
#else
#error "Unsupported system!"
#endif
    std::vector<std::string> cmd_stdout;
    fptn::common::system::command::run(command, cmd_stdout);
    for (const auto& line : cmd_stdout) {
      std::string result = line;
      result.erase(result.find_last_not_of(" \n\r\t") + 1);
      result.erase(0, result.find_first_not_of(" \n\r\t"));
      if (!result.empty()) {
        return result;
      }
    }
    SPDLOG_WARN("Warning: Default network interface not found.");
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("Error: Failed to retrieve the default network interface. {}",
        ex.what());
  }
  return {};
#endif
}
}  // namespace fptn::routing
