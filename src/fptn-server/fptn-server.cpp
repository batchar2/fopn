/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <fmt/ranges.h>  // NOLINT(build/include_order)

#include "common/jwt_token/token_manager.h"
#include "common/logger/logger.h"
#include "common/network/ip_address.h"
#include "common/utils/utils.h"

#include "config/server_config.h"
#include "filter/filters/adblock/adblock.h"
#include "filter/filters/antiscan/antiscan.h"
#include "filter/filters/antispam/antispam.h"
#include "filter/filters/bittorrent/bittorrent.h"
#include "filter/filters/domain_blacklist/domain_blacklist.h"
#include "filter/manager.h"
#include "fptn-protocol-lib/time/time_provider.h"
#include "nat/table.h"
#include "network/virtual_interface.h"
#include "routing/route_manager.h"
#include "statistic/metrics.h"
#include "user/user_manager.h"
#include "vpn/manager.h"
#include "web/server.h"

namespace {

void WaitForSignal() {
  boost::asio::io_context io_context;
  boost::asio::signal_set signals(io_context, SIGINT, SIGTERM /*,SIGQUIT*/);
  signals.async_wait([&](auto, auto) { io_context.stop(); });
  io_context.run();
}
}  // namespace

int main(int argc, char* argv[]) {
#if defined(__linux__) || defined(__APPLE__)
  if (geteuid() != 0) {
    std::cerr << "You must be root to run this program." << std::endl;
    return EXIT_FAILURE;
  }
#endif
  try {
    /* Init config */
    auto config = std::make_shared<fptn::config::ServerConfig>(argc, argv);
    if (!config->Parse()) {
      return EXIT_FAILURE;
    }
    if (!std::filesystem::exists(config->ServerCrt()) ||
        !std::filesystem::exists(config->ServerKey())) {
      SPDLOG_ERROR("SSL certificate or key file does not exist!");
      return EXIT_FAILURE;
    }

    /* Init logger */
    if (fptn::logger::init("fptn-server", false)) {
      SPDLOG_INFO("Application started successfully.");
    } else {
      std::cerr << "Logger initialization failed. Exiting application."
                << std::endl;
      return EXIT_FAILURE;
    }

    fptn::time::TimeProvider::Instance();

    /* Init route manager */
    auto route_manager = std::make_unique<fptn::routing::RouteManager>(
        config->OutNetworkInterface(), config->TunInterfaceName());
    /* Init virtual network interface */

    auto virtual_network_interface =
        std::make_unique<fptn::network::VirtualInterface>(
            config->TunInterfaceName(), config->MtuSize(),
            std::move(route_manager),
            fptn::common::network::TunInterface::Config{
                .ipv4_addr = config->TunInterfaceIPv4(),
                .ipv4_netmask = config->TunInterfaceNetworkIPv4Mask(),
                .ipv6_addr = config->TunInterfaceIPv6(),
                .ipv6_netmask = config->TunInterfaceNetworkIPv6Mask()});

    /* Init web server */
    auto token_manager =
        std::make_shared<fptn::common::jwt_token::TokenManager>(
            config->ServerCrt(), config->ServerKey());
    /* Init user manager */
    auto user_manager = std::make_shared<fptn::user::UserManager>(
        config->UserFile(), config->UseRemoteServerAuth(),
        config->RemoteServerAuthHost(), config->RemoteServerAuthPort());
    /* Init NAT */
    auto nat_table = std::make_shared<fptn::nat::Table>(
        fptn::nat::Table::Config{.tun_ipv4 = config->TunInterfaceIPv4(),
            .tun_ipv4_network = config->TunInterfaceNetworkIPv4Address(),
            .tun_network_ipv4_mask = config->TunInterfaceNetworkIPv4Mask(),
            .tun_ipv6 = config->TunInterfaceIPv6(),
            .tun_ipv6_network = config->TunInterfaceNetworkIPv6Address(),
            .tun_network_ipv6_mask = config->TunInterfaceNetworkIPv6Mask()});
    /* Init prometheus */
    auto prometheus = std::make_shared<fptn::statistic::Metrics>();
    /* Init webserver */
    auto web_server = std::make_unique<fptn::web::Server>(config->ServerPort(),
        nat_table, user_manager, token_manager, prometheus,
        config->PrometheusAccessKey(), config->TunInterfaceIPv4(),
        config->TunInterfaceIPv6(),
        /* probing */
        config->EnableDetectProbing(), config->AllowedSniList(),
        /* sessions */
        config->MaxActiveSessionsPerUser(),
        /* External IPs */
        config->ServerExternalIPs());

    /* init from-client packet filter */
    auto from_client_filter_manager = std::make_shared<fptn::filter::Manager>();
    if (config->EnableTorrentFilter()) {  // block bittorrent traffic
      from_client_filter_manager->Add(
          std::make_shared<fptn::filter::BitTorrent>());
    }
    if (config->EnableSpamFilter()) {
      from_client_filter_manager->Add(
          std::make_shared<fptn::filter::AntiSpam>());
    }
    // Prevent sending requests to the VPN virtual network from the client
    from_client_filter_manager->Add(std::make_shared<fptn::filter::AntiScan>(
        /* IPv4 */
        config->TunInterfaceIPv4(), config->TunInterfaceNetworkIPv4Address(),
        config->TunInterfaceNetworkIPv4Mask(),
        /* IPv6 */
        config->TunInterfaceIPv6(), config->TunInterfaceNetworkIPv6Address(),
        config->TunInterfaceNetworkIPv6Mask()));

    /* init to-client packet filter (domain blacklist) */
    auto to_client_filter_manager = std::make_shared<fptn::filter::Manager>();
    if (config->EnableDomainBlacklistFilter()) {
      auto domain_blacklist = std::make_shared<fptn::filter::DomainBlacklist>(
          config->DataDir(), config->DomainBlacklistUrls(),
          config->DomainBlacklistFile());
      // one filter in both directions: filled on the to-client path,
      // read on the from-client path
      to_client_filter_manager->Add(domain_blacklist);
      from_client_filter_manager->Add(std::move(domain_blacklist));
    }

    /* ads filter */
    if (config->EnableAdsFilter()) {
      from_client_filter_manager->Add(std::make_shared<fptn::filter::AdBlock>(
          config->DataDir(), config->AdsBlocklistUrls()));
    }

    SPDLOG_INFO(
        "\n--- Starting server---\n"
        "VERSION:           {}\n"
        "NETWORK INTERFACE: {}\n"
        "VPN NETWORK IPv4:  {}\n"
        "VPN NETWORK IPv6:  {}\n"
        "VPN SERVER PORT:   {}\n"
        "DETECT_PROBING:    {}\n"
        "ALLOWED_SNI_LIST:     {}\n"
        "DOMAIN BLACKLIST:     {}\n"
        "ADS FILTER:           {}\n"
        "TORRENT FILTER:       {}\n"
        "SPAM FILTER:          {}\n"
        "MAX_ACTIVE_SESSIONS_PER_USER: {}\n",
        FPTN_VERSION,
        // Network settings
        config->OutNetworkInterface(),
        config->TunInterfaceNetworkIPv4Address().ToString(),
        config->TunInterfaceNetworkIPv6Address().ToString(),
        config->ServerPort(),
        // Probing settings
        config->EnableDetectProbing() ? "YES" : "NO",
        fmt::format("[{}]", fmt::join(config->AllowedSniList(), ", ")),
        // Packet filters
        config->EnableDomainBlacklistFilter() ? "YES" : "NO",
        config->EnableAdsFilter() ? "YES" : "NO",
        config->EnableTorrentFilter() ? "YES" : "NO",
        config->EnableSpamFilter() ? "YES" : "NO",
        // max session
        config->MaxActiveSessionsPerUser());

    // Init vpn manager
    fptn::vpn::Manager manager(
        fptn::vpn::Manager::Config{.web_server = std::move(web_server),
            .network_interface = std::move(virtual_network_interface),
            .nat = nat_table,
            .from_client_filter = from_client_filter_manager,
            .to_client_filter = to_client_filter_manager,
            .prometheus = prometheus});

    /* start/wait/stop */
    manager.Start();
    WaitForSignal();
    manager.Stop();

    return EXIT_SUCCESS;
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("An error occurred: {}. Exiting...", ex.what());
  } catch (...) {
    SPDLOG_ERROR("An unknown error occurred. Exiting...");
  }
  return EXIT_FAILURE;
}
