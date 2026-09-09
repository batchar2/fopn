/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <iostream>

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>  // NOLINT(build/include_order)
#endif

#include <charconv>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <argparse/argparse.hpp>
#include <fmt/format.h>  // NOLINT(build/include_order)
#include <fmt/ranges.h>  // NOLINT(build/include_order)

#include "common/logger/logger.h"
#include "common/network/ip_address.h"
#include "common/network/net_interface.h"

#include "config/config_file.h"
#include "fptn-protocol-lib/https/obfuscator/methods/detector.h"
#include "fptn-protocol-lib/time/time_provider.h"
#ifndef FPTN_OPENWRT
#include "plugins/adblock/adblock.h"
#endif
#include "plugins/blacklist/domain_blacklist.h"
#include "routing/route_manager.h"
// cppcheck-suppress missingInclude
#include "split_tunnel_domains.generated.h"  // NOLINT
#include "utils/signal/main_loop.h"
#include "vpn/vpn_manager.h"

int main(int argc, char* argv[]) {
#if defined(__linux__) || defined(__APPLE__)
  if (geteuid() != 0) {
    std::cerr << "You must be root to run this program." << std::endl;
    return EXIT_FAILURE;
  }
#endif
  try {
    const std::set<std::string> bypass_methods = {"obfuscation",
        /* chrome */
        "sni-spoofing-chrome-149", "sni-spoofing-chrome-148",
        "sni-spoofing-chrome-147", "sni-spoofing-chrome-146",
        "sni-spoofing-chrome-145",
        /* Firefox */
        "sni-spoofing-firefox-151", "sni-spoofing-firefox-150",
        "sni-spoofing-firefox-149",
        /* Yandex */
        "sni-spoofing-yandex-26-4", "sni-spoofing-yandex-26-3",
        "sni-spoofing-yandex-25", "sni-spoofing-yandex-24",
        /* Safari */
        "sni-spoofing-safari-26-5", "sni-spoofing-safari-26-4"};
    const std::set<std::string> tunnel_modes = {"exclude", "include"};

    using fptn::protocol::https::obfuscator::GetObfuscatorByName;
    using fptn::protocol::https::obfuscator::GetObfuscatorNames;

    argparse::ArgumentParser args("fptn-client", FPTN_VERSION);
    // Required arguments
    args.add_argument("--access-token").required().help("Access token");
    // Optional arguments
    args.add_argument("--out-network-interface")
        .default_value("")
        .help("Network out interface");
    args.add_argument("--gateway-ip")
        .default_value("")
        .help("Your default gateway IPv4 address");
    args.add_argument("--gateway-ipv6")
        .default_value("")
        .help("Your default gateway IPv6 address");
    args.add_argument("--mtu-size")
        .default_value(FPTN_DEFAULT_MTU_SIZE)
        .help("MTU size")
        .action([](const std::string& v) -> int {
          if (v.empty()) {
            return FPTN_DEFAULT_MTU_SIZE;
          }
          int mtu_size = 0;
          const auto [end, error] =
              std::from_chars(v.data(), v.data() + v.size(), mtu_size);
          if (error != std::errc() || end != v.data() + v.size()) {
            throw std::runtime_error(
                fmt::format("Invalid MTU size '{}'. It must be a number", v));
          }
          if (mtu_size < 576 || mtu_size > 65535) {
            throw std::runtime_error(fmt::format(
                "MTU size {} is out of range [576..65535]", mtu_size));
          }
          return mtu_size;
        });
    args.add_argument("--preferred-server")
        .default_value("")
        .help("Preferred server name (case-insensitive)");
    args.add_argument("--tun-interface-name")
        .default_value("tun0")
        .help("Network interface name")
        .action([](const std::string& v) -> std::string {
          return v.empty() ? "tun0" : v;
        });
    args.add_argument("--tun-interface-ip")
        .default_value(FPTN_CLIENT_DEFAULT_ADDRESS_IP4)
        .help("Network interface IPv4 address")
        .action([](const std::string& v) -> std::string {
          return v.empty() ? FPTN_CLIENT_DEFAULT_ADDRESS_IP4 : v;
        });
    args.add_argument("--tun-interface-ipv6")
        .default_value(FPTN_CLIENT_DEFAULT_ADDRESS_IP6)
        .help("Network interface IPv6 address")
        .action([](const std::string& v) -> std::string {
          return v.empty() ? FPTN_CLIENT_DEFAULT_ADDRESS_IP6 : v;
        });
    args.add_argument("--sni")
        .default_value(FPTN_DEFAULT_SNI)
        .help(
            "Domain name for SNI in TLS handshake (used to obfuscate VPN "
            "traffic)")
        .action([](const std::string& v) -> std::string {
          return v.empty() ? FPTN_DEFAULT_SNI : v;
        });
    args.add_argument("--blacklist-domains")
        .default_value(FPTN_CLIENT_DEFAULT_BLACKLIST_DOMAINS)
        .help(
            "Completely block access to the main domain AND all its "
            "subdomains\n"
            "Format: example.com,sub.site.org\n"
            "Example: ria.ru blocks ria.ru and all *.ria.ru sites");
#ifndef FPTN_OPENWRT
    args.add_argument("--enable-ad-block")
        .help("Block ads and trackers at the DNS level")
        .default_value(true)
        .nargs(1)
        .action([](const std::string& value) {
          if (value.empty()) {
            return true;
          }
          if (fptn::common::utils::ToLowerCase(value) == "true") {
            return true;
          }
          if (fptn::common::utils::ToLowerCase(value) == "false") {
            return false;
          }
          throw std::runtime_error("Value must be true/false");
        });
#endif
    // Method to bypass censorship
    args.add_argument("--bypass-method")
        .default_value("sni-spoofing-yandex-26-4")
        .help(
            "Method to bypass censorship:\n"
            "  obfuscation             - TLS obfuscation\n"
            "  sni-spoofing-chrome-149  - SNI spoofing with Chrome 149 "
            "handshake\n"
            "  sni-spoofing-chrome-148  - SNI spoofing with Chrome 148 "
            "handshake\n"
            "  sni-spoofing-chrome-147  - SNI spoofing with Chrome 147 "
            "handshake\n"
            "  sni-spoofing-chrome-146  - SNI spoofing with Chrome 146 "
            "handshake\n"
            "  sni-spoofing-chrome-145  - SNI spoofing with Chrome 145 "
            "handshake\n"
            "  sni-spoofing-firefox-151 - SNI spoofing with Firefox 151 "
            "handshake\n"
            "  sni-spoofing-firefox-150 - SNI spoofing with Firefox 150 "
            "handshake\n"
            "  sni-spoofing-firefox-149 - SNI spoofing with Firefox 149 "
            "handshake\n"
            "  sni-spoofing-yandex-26-4 - SNI spoofing with Yandex 26.4 "
            "handshake\n"
            "  sni-spoofing-yandex-26-3 - SNI spoofing with Yandex 26.3 "
            "handshake\n"
            "  sni-spoofing-yandex-25   - SNI spoofing with Yandex 25 "
            "handshake\n"
            "  sni-spoofing-yandex-24   - SNI spoofing with Yandex 24 "
            "handshake\n"
            "  sni-spoofing-safari-26-5 - SNI spoofing with Safari 26.5 "
            "handshake\n"
            "  sni-spoofing-safari-26-4 - SNI spoofing with Safari 26.4 "
            "handshake\n")
        .action([&bypass_methods](const std::string& v) -> std::string {
          if (v.empty() || v == "sni-spoofing") {
            return "sni-spoofing-yandex-26-4";
          }
          if (!bypass_methods.contains(v)) {
            throw std::runtime_error(
                fmt::format("Invalid bypass method '{}'. Choose from: {}", v,
                    fmt::join(bypass_methods, ", ")));
          }
          return v;
        });
    args.add_argument("--connection-strategy")
        .default_value("rolling-tunnel")
        .help(
            "Connection strategy:\n"
            "  rolling-tunnel        - a single tunnel renewed every 10 mins\n"
            "  dual-rolling-tunnel   - two rolling tunnels in parallel\n"
            "  triple-rolling-tunnel - three rolling tunnels in parallel\n")
        .action([](const std::string& v) -> std::string {
          if (v.empty()) {
            return "rolling-tunnel";
          }
          if (v != "rolling-tunnel" && v != "dual-rolling-tunnel" &&
              v != "triple-rolling-tunnel") {
            throw std::runtime_error(fmt::format(
                "Invalid connection strategy '{}'. Choose from: "
                "rolling-tunnel, dual-rolling-tunnel, triple-rolling-tunnel",
                v));
          }
          return v;
        });
    // networks
    args.add_argument("--exclude-tunnel-networks")
        .default_value(FPTN_CLIENT_DEFAULT_EXCLUDE_NETWORKS)
        .help(
            "Networks that always bypass VPN tunnel\n"
            "Traffic to these networks goes directly, never through VPN\n"
            "Format: CIDR notation or IP addresses, comma-separated\n"
            "Example: 10.0.0.0/8,192.168.0.0/16");
    args.add_argument("--include-tunnel-networks")
        .default_value("")
        .help(
            "Networks that always use VPN tunnel\n"
            "Traffic to these networks always goes through VPN\n"
            "Format: CIDR notation or IP addresses, comma-separated\n"
            "Example: 172.16.0.0/12,192.168.99.0/24");
    // Split-tunneling arguments
    args.add_argument("--enable-split-tunnel")
        .help(
            "Enable split tunneling - allows different traffic routing for "
            "different sites.\n"
            "When enabled, you can configure which sites use VPN and which go"
            "directly.\n"
            "Use with --split-tunnel-mode and --split-tunnel-domains for "
            "configuration.")
        .default_value(false)
        .nargs(1)
        .action([](const std::string& value) {
          if (value.empty()) {
            return true;
          }
          if (fptn::common::utils::ToLowerCase(value) == "true") {
            return true;
          }
          if (fptn::common::utils::ToLowerCase(value) == "false") {
            return false;
          }
          throw std::runtime_error("Value must be true/false");
        });
    args.add_argument("--split-tunnel-mode")
        .default_value("exclude")
        .help(
            "Defines traffic routing strategy for split tunneling.\n"
            "Modes:\n"
            "  exclude - Bypass VPN for specified domains, route all other "
            "traffic through VPN.\n"
            "  include - Route only specified domains through VPN, bypass VPN "
            "for all other traffic.\n")
        .action([&tunnel_modes](const std::string& v) -> std::string {
          if (v.empty()) {
            return "exclude";
          }
          if (!tunnel_modes.contains(v)) {
            throw std::runtime_error(
                fmt::format("Invalid tunnel mode '{}'. Choose from: {}", v,
                    fmt::join(tunnel_modes, ", ")));
          }
          return v;
        });
    args.add_argument("--split-tunnel-domains")
        .default_value(std::string(""))
        .help(
            "List websites that should either use or bypass VPN\n"
            "\n"
            "How it works:\n"
            "  If --tunnel-mode=exclude: VPN skips these sites\n"
            "  If --tunnel-mode=include: VPN only for these sites\n"
            "Format: com,another.com,sub.domainname.com\n"
            "Empty (default) uses the built-in list");
    // parse cmd arguments
    try {
      args.parse_args(argc, argv);
    } catch (const std::runtime_error& err) {
      std::cerr << err.what() << std::endl;
      std::cerr << args;
      return EXIT_FAILURE;
    }

    if (fptn::logger::init("fptn-client-cli")) {
      SPDLOG_INFO("Application started successfully.");
    } else {
      std::cerr << "Logger initialization failed. Exiting application."
                << std::endl;
      return EXIT_FAILURE;
    }

    fptn::time::TimeProvider::Instance();

#ifdef __linux__
    fptn::routing::HealStaleResolvConf();
#endif

    /* parse cmd args */
    const auto out_network_interface_name =
        args.get<std::string>("--out-network-interface");

    const auto param_gateway_ip = args.get<std::string>("--gateway-ip");
    const auto gateway_ip =
        fptn::common::network::IPv4Address::Create(param_gateway_ip);

    const auto mtu_size = args.get<int>("--mtu-size");

    const auto param_gateway_ipv6 = args.get<std::string>("--gateway-ipv6");
    const auto gateway_ipv6 =
        fptn::common::network::IPv6Address::Create(param_gateway_ipv6);

    const auto preferred_server = args.get<std::string>("--preferred-server");

    const auto tun_interface_name =
        args.get<std::string>("--tun-interface-name");
    const auto tun_interface_address_ipv4 =
        fptn::common::network::IPv4Address::Create(
            args.get<std::string>("--tun-interface-ip"));
    const auto tun_interface_address_ipv6 =
        fptn::common::network::IPv6Address::Create(
            args.get<std::string>("--tun-interface-ipv6"));
    const auto sni = args.get<std::string>("--sni");

    /* check gateway address */
    const auto using_gateway_ip =
        gateway_ip.IsEmpty()
            ? fptn::routing::GetDefaultGatewayIPAddress(tun_interface_name)
            : fptn::common::network::IPv4Address::Create(gateway_ip);
    const auto using_gateway_ipv6 =
        gateway_ipv6.IsEmpty()
            ? fptn::routing::GetDefaultGatewayIPv6Address(tun_interface_name)
            : fptn::common::network::IPv6Address::Create(gateway_ipv6);
    if (using_gateway_ip.IsEmpty()) {
      SPDLOG_ERROR(
          "Unable to find the default gateway IP address. "
          "Please check your connection and make sure no other VPN is active. "
          "If the error persists, specify the gateway address in the FPTN "
          "settings using your router's IP "
          "address with the \"--gateway-ip\" option. If the issue "
          "remains unresolved, please contact the developer via Telegram "
          "@fptn_chat.");
      return EXIT_FAILURE;
    }

    using fptn::protocol::https::CensorshipStrategy;
    const auto bypass_method = args.get<std::string>("--bypass-method");
    CensorshipStrategy censorship_strategy =
        CensorshipStrategy::kSniRealityModeYandex26_4;
    if (bypass_method == "obfuscation") {
      censorship_strategy = CensorshipStrategy::kTlsObfuscator;
    }
    /* Chrome */
    else if (bypass_method == "sni-spoofing-chrome-149") {
      censorship_strategy = CensorshipStrategy::kSniRealityModeChrome149;
    } else if (bypass_method == "sni-spoofing-chrome-148") {
      censorship_strategy = CensorshipStrategy::kSniRealityModeChrome148;
    } else if (bypass_method == "sni-spoofing-chrome-147") {
      censorship_strategy = CensorshipStrategy::kSniRealityModeChrome147;
    } else if (bypass_method == "sni-spoofing-chrome-146") {
      censorship_strategy = CensorshipStrategy::kSniRealityModeChrome146;
    } else if (bypass_method == "sni-spoofing-chrome-145") {
      censorship_strategy = CensorshipStrategy::kSniRealityModeChrome145;
    }
    /* Firefox */
    else if (bypass_method == "sni-spoofing-firefox-151") {
      censorship_strategy = CensorshipStrategy::kSniRealityModeFirefox151;
    } else if (bypass_method == "sni-spoofing-firefox-150") {
      censorship_strategy = CensorshipStrategy::kSniRealityModeFirefox150;
    } else if (bypass_method == "sni-spoofing-firefox-149") {
      censorship_strategy = CensorshipStrategy::kSniRealityModeFirefox149;
    }
    /* Yandex */
    else if (bypass_method == "sni-spoofing-yandex-26-4") {
      censorship_strategy = CensorshipStrategy::kSniRealityModeYandex26_4;
    } else if (bypass_method == "sni-spoofing-yandex-26-3") {
      censorship_strategy = CensorshipStrategy::kSniRealityModeYandex26_3;
    } else if (bypass_method == "sni-spoofing-yandex-25") {
      censorship_strategy = CensorshipStrategy::kSniRealityModeYandex25;
    } else if (bypass_method == "sni-spoofing-yandex-24") {
      censorship_strategy = CensorshipStrategy::kSniRealityModeYandex24;
    }
    /* Safari */
    else if (bypass_method == "sni-spoofing-safari-26-5") {
      censorship_strategy = CensorshipStrategy::kSniRealityModeSafari26_5;
    } else if (bypass_method == "sni-spoofing-safari-26-4") {
      censorship_strategy = CensorshipStrategy::kSniRealityModeSafari26_4;
    }

    using fptn::protocol::connection::strategies::ConnectionStrategy;
    const auto connection_strategy_name =
        args.get<std::string>("--connection-strategy");
    ConnectionStrategy connection_strategy =
        ConnectionStrategy::kSingleRollingTunnel;
    if (connection_strategy_name == "browser-mimicry") {
      connection_strategy = ConnectionStrategy::kBrowserMimicry;
    } else if (connection_strategy_name == "dual-rolling-tunnel") {
      connection_strategy = ConnectionStrategy::kDualRollingTunnel;
    } else if (connection_strategy_name == "triple-rolling-tunnel") {
      connection_strategy = ConnectionStrategy::kTripleRollingTunnel;
    }

    /* parse network lists */
    const auto exclude_networks_str =
        args.get<std::string>("--exclude-tunnel-networks");
    const auto include_networks_str =
        args.get<std::string>("--include-tunnel-networks");

    const std::vector<std::string> exclude_networks =
        fptn::common::utils::SplitCommaSeparated(exclude_networks_str);
    const std::vector<std::string> include_networks =
        fptn::common::utils::SplitCommaSeparated(include_networks_str);

    /* parse split-tunneling parameters */
#ifndef FPTN_OPENWRT
    const bool enable_ad_block = args.get<bool>("--enable-ad-block");
#endif
    const bool enable_split_tunnel = args.get<bool>("--enable-split-tunnel");
    const auto tunnel_mode = args.get<std::string>("--split-tunnel-mode");
    const auto split_domains_str =
        args.get<std::string>("--split-tunnel-domains");
    const auto blacklist_domains_str =
        args.get<std::string>("--blacklist-domains");

    std::vector<std::string> split_domains =
        fptn::common::utils::SplitCommaSeparated(split_domains_str);
    if (split_domains.empty()) {
      split_domains.assign(std::begin(fptn::defaults::kSplitTunnelDomains),
          std::end(fptn::defaults::kSplitTunnelDomains));
    }
    const std::vector<std::string> blacklist_domains =
        fptn::common::utils::SplitCommaSeparated(blacklist_domains_str);

    /* check config */
    const auto access_token = args.get<std::string>("--access-token");
    fptn::config::ConfigFile config(access_token, sni, censorship_strategy);
    fptn::utils::speed_estimator::ServerInfo selected_server;
    std::string pre_obtained_token;
    try {
      config.Parse();
      bool use_login_race = preferred_server.empty();
      if (!preferred_server.empty()) {
        auto server_opt = config.GetServer(preferred_server);
        if (server_opt.has_value()) {
          selected_server = std::move(*server_opt);
        } else {
          SPDLOG_WARN("Server '{}' does not exist! Check your token!",
              preferred_server);
          use_login_race = true;
        }
      }
      if (use_login_race) {
        auto login_result = config.FindServerByLogin(10);
        if (!login_result) {
          SPDLOG_ERROR("All servers unavailable!");
          return EXIT_FAILURE;
        }
        selected_server = login_result->server;
        pre_obtained_token = std::move(login_result->access_token);
      }
    } catch (const std::runtime_error& err) {
      SPDLOG_ERROR("Config error: {}", err.what());
      return EXIT_FAILURE;
    }
    const auto server_ip = fptn::routing::ResolveDomain(selected_server.host);
    if (server_ip.IsEmpty()) {
      SPDLOG_ERROR("DNS resolve error: {}", selected_server.host);
      return EXIT_FAILURE;
    }

    SPDLOG_INFO(
        "\n--- Starting client ---\n"
        "VERSION:            {}\n"
        "SELECTED SERVER:    {}\n"
        "SNI:                {}\n"
        "VPN SERVER NAME:    {}\n"
        "VPN SERVER IP:      {}\n"
        "VPN SERVER PORT:    {}\n"
        "BYPASS-METHOD:      {}\n"
        "GATEWAY IP:         {}\n"
        "NETWORK INTERFACE:  {}\n"
        "EXCLUDE NETWORKS:   {}\n"
        "INCLUDE NETWORKS:   {}\n"
        "SPLIT TUNNEL:       {}\n"
        "TUNNEL MODE:        {}\n"
        "TUNNEL DOMAINS:     {}\n"
        "BLACKLIST DOMAINS:  {}\n",
        // version
        FPTN_VERSION,
        // server
        selected_server.name, sni, selected_server.name, selected_server.host,
        selected_server.port, bypass_method,
        // network
        using_gateway_ip.ToString(), out_network_interface_name,
        // additional settings
        exclude_networks_str, include_networks_str,
        enable_split_tunnel ? "enabled" : "disabled", tunnel_mode,
        split_domains_str, blacklist_domains_str);

    /* auth & dns */
    auto http_client = std::make_unique<fptn::vpn::http::Client>(
        fptn::protocol::https::ConnectionConfig{
            .common ={
                    .server_ip = server_ip,
                    .server_port =
                        static_cast<std::uint16_t>(selected_server.port),
                    .sni = sni,
                    .md5_fingerprint = selected_server.md5_fingerprint,
                    .client_version = FPTN_VERSION,
                    .censorship_strategy = censorship_strategy,
                    .tun_interface_address_ipv4 = tun_interface_address_ipv4,
                    .tun_interface_address_ipv6 = tun_interface_address_ipv6,
                }},
        connection_strategy);

    if (!pre_obtained_token.empty()) {
      http_client->SetAccessToken(pre_obtained_token);
    }
    const bool status =
        http_client->Login(config.GetUsername(), config.GetPassword());
    if (!status) {
      SPDLOG_ERROR("Login failed (code {}): {}", http_client->LatestErrorCode(),
          http_client->LatestError());
      return EXIT_FAILURE;
    }
    const auto [dns_server_ipv4, dns_server_ipv6] = http_client->GetDns();
    if (dns_server_ipv4.IsEmpty() || dns_server_ipv6.IsEmpty()) {
      SPDLOG_ERROR("DNS server error! Check your connection!");
      return EXIT_FAILURE;
    }

    /* tun interface */
    auto virtual_network_interface =
        std::make_shared<fptn::common::network::TunInterface>(
            fptn::common::network::TunInterface::Config{
                .name = tun_interface_name,
                .mtu_size = mtu_size,
                .using_rate_calculator = true,
                .ipv4_addr = tun_interface_address_ipv4,
                .ipv4_netmask = 32,
                .ipv6_addr = tun_interface_address_ipv6,
                .ipv6_netmask = 126});

    // route manager
    auto route_manager = std::make_shared<fptn::routing::RouteManager>(
        fptn::routing::RouteManager::Config{
            .out_interface_name = out_network_interface_name,
            .tun_interface_address_ipv4 = tun_interface_address_ipv4,
            .tun_interface_address_ipv6 = tun_interface_address_ipv6,
            .vpn_server_ip = server_ip,
            .dns_server_ipv4 = dns_server_ipv4,
            .dns_server_ipv6 = dns_server_ipv6,
            .gateway_ipv4 = gateway_ip,
            .gateway_ipv6 = gateway_ipv6,
            .exclude_networks = exclude_networks,
            .include_networks = include_networks
#if _WIN32
            ,
            .enable_advanced_dns_management = false
#endif
        });

    /* plugins */
    std::vector<fptn::plugin::BasePluginPtr> client_plugins;
#ifndef FPTN_OPENWRT
    if (enable_ad_block) {
      client_plugins.push_back(std::make_unique<fptn::plugin::AdBlock>());
    }
#endif
    if (!blacklist_domains.empty()) {
      auto blacklist_plugin = std::make_unique<fptn::plugin::DomainBlacklist>(
          blacklist_domains, route_manager);
      client_plugins.push_back(std::move(blacklist_plugin));
    }

    if (enable_split_tunnel) {
      const auto policy = tunnel_mode == "exclude"
                              ? fptn::routing::RoutingPolicy::kExcludeFromVpn
                              : fptn::routing::RoutingPolicy::kIncludeInVpn;
      auto split_tunnel_plugin = std::make_unique<fptn::plugin::Tunneling>(
          split_domains, route_manager, policy);
      client_plugins.push_back(std::move(split_tunnel_plugin));
    }

    /* vpn client */
    fptn::vpn::VpnManager vpn_client(
        fptn::vpn::VpnManager::Config{.http_client = std::move(http_client),
            .route_manager = route_manager,
            .virtual_net_interface = virtual_network_interface,
            .plugins = std::move(client_plugins)});

    vpn_client.Start();

    /* start event loop */
    fptn::utils::WaitForSignal(vpn_client);

    /* clean */
    route_manager->Clean();
    vpn_client.Stop();
    spdlog::shutdown();
    return EXIT_SUCCESS;
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("An error occurred: {}. Exiting...", ex.what());
  } catch (...) {
    SPDLOG_ERROR("An unknown error occurred. Exiting...");
  }
  return EXIT_FAILURE;
}
