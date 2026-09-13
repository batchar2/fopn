/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include "common/data/channel.h"
#include "common/jwt_token/token_manager.h"
#include "common/network/ip_packet.h"

#include "handshake/handshake_cache_manager.h"
#include "listener/listener.h"
#include "nat/table.h"
#include "user/user_manager.h"

namespace fptn::web {
class Server final {
 public:
  Server(std::uint16_t port,
      const fptn::nat::TableSPtr& nat_table,
      const fptn::user::UserManagerSPtr& user_manager,
      const fptn::common::jwt_token::TokenManagerSPtr& token_manager,
      const fptn::statistic::MetricsSPtr& prometheus,
      const std::string& prometheus_access_key,
      fptn::common::network::IPv4Address dns_server_ipv4,
      fptn::common::network::IPv6Address dns_server_ipv6,
      bool enable_detect_probing,
      std::vector<std::string> allowed_sni_list,
      std::size_t max_active_sessions_per_user,
      std::string server_external_ips,
      int thread_number = 16);
  ~Server();
  bool Start();
  bool Stop();

  fptn::web::SessionSPtr GetSessionById(fptn::ClientID client_id);

  fptn::common::network::BatchIPPacketPtr WaitForPackets(
      const std::chrono::milliseconds& duration);

  fptn::common::network::IPPacketPtr WaitForPacket(
    const std::chrono::milliseconds& duration);


 protected:
  // http
  boost::asio::awaitable<int> HandleApiDns(
      const http::request& req, http::response& resp);
  boost::asio::awaitable<int> HandleApiLogin(
      const http::request& req, http::response& resp);
  boost::asio::awaitable<int> HandleApiMetrics(
      const http::request& req, http::response& resp);
  boost::asio::awaitable<int> HandleApiTestFile(
      const http::request& req, http::response& resp);

 protected:
  // websocket
  fptn::nat::ConnectionMultiplexerSPtr HandleWsOpenConnection(
      const fptn::nat::ConnectParams& params, const SessionSPtr& session);
  void HandleWsNewIPPacket(fptn::common::network::IPPacketPtr packet) noexcept;
  void HandleWsCloseConnection(fptn::ClientID client_id) noexcept;

 private:
  mutable std::shared_mutex mutex_;
  std::atomic<bool> running_;

  const std::uint16_t port_;
  const fptn::nat::TableSPtr& nat_table_;
  const fptn::user::UserManagerSPtr& user_manager_;
  const fptn::common::jwt_token::TokenManagerSPtr token_manager_;
  const fptn::statistic::MetricsSPtr& prometheus_;
  const std::string prometheus_access_key_;
  const fptn::common::network::IPv4Address dns_server_ipv4_;
  const fptn::common::network::IPv6Address dns_server_ipv6_;
  const bool enable_detect_probing_;
  const std::vector<std::string> allowed_sni_list_;

  const std::size_t max_active_sessions_per_user_;
  const std::string server_external_ips_;
  const std::size_t thread_number_;

  boost::asio::io_context ioc_;
  fptn::common::data::Channel from_client_;

  ListenerSPtr listener_;

  HandshakeCacheManagerSPtr handshake_cache_manager_;

  std::vector<std::thread> ioc_threads_;
  std::unordered_map<fptn::ClientID, SessionSPtr> sessions_;
};

using ServerPtr = std::unique_ptr<Server>;
}  // namespace fptn::web
