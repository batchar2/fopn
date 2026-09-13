/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "web/server.h"

#include <algorithm>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/api/handle.h"
#include "common/utils/utils.h"

using fptn::web::Server;

Server::Server(std::uint16_t port,
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
    int thread_number)
    : running_(false),
      port_(port),
      nat_table_(nat_table),
      user_manager_(user_manager),
      token_manager_(token_manager),
      prometheus_(prometheus),
      prometheus_access_key_(prometheus_access_key),
      dns_server_ipv4_(std::move(dns_server_ipv4)),
      dns_server_ipv6_(std::move(dns_server_ipv6)),
      enable_detect_probing_(enable_detect_probing),
      allowed_sni_list_(std::move(allowed_sni_list)),
      max_active_sessions_per_user_(max_active_sessions_per_user),
      server_external_ips_(std::move(server_external_ips)),
      thread_number_(std::max<std::size_t>(1, thread_number)),
      ioc_(thread_number),
      from_client_("packets_from_websockets", 1024 * 2) {
  using std::placeholders::_1;
  using std::placeholders::_2;

  handshake_cache_manager_ =
      std::make_shared<HandshakeCacheManager>(allowed_sni_list_);

  listener_ = std::make_shared<Listener>(port_,
      // proxy settings
      enable_detect_probing_, allowed_sni_list_,
      // ioc
      ioc_, token_manager, handshake_cache_manager_, server_external_ips_,
      // NOLINTNEXTLINE(modernize-avoid-bind)
      std::bind(&Server::HandleWsOpenConnection, this, _1, _2),
      // NOLINTNEXTLINE(modernize-avoid-bind)
      std::bind(&Server::HandleWsNewIPPacket, this, _1),
      // NOLINTNEXTLINE(modernize-avoid-bind)
      std::bind(&Server::HandleWsCloseConnection, this, _1));
  listener_->AddApiHandle(fptn::common::api::kApiDnsUrl, "GET",
      // NOLINTNEXTLINE(modernize-avoid-bind)
      std::bind(&Server::HandleApiDns, this, _1, _2));
  listener_->AddApiHandle(fptn::common::api::kApiLoginUrl, "POST",
      // NOLINTNEXTLINE(modernize-avoid-bind)
      std::bind(&Server::HandleApiLogin, this, _1, _2));
  listener_->AddApiHandle(fptn::common::api::kApiTestFileBinUrl, "GET",
      // NOLINTNEXTLINE(modernize-avoid-bind)
      std::bind(&Server::HandleApiTestFile, this, _1, _2));
  if (!prometheus_access_key.empty()) {
    // Construct the URL for accessing Prometheus statistics by appending the
    // access key
    const std::string metrics =
        std::string(common::api::kApiMetricsUrl) + '/' + prometheus_access_key;
    listener_->AddApiHandle(
        // NOLINTNEXTLINE(modernize-avoid-bind)
        metrics, "GET", std::bind(&Server::HandleApiMetrics, this, _1, _2));
  }
}

Server::~Server() { Stop(); }

bool Server::Start() {
  running_ = true;
  try {
    {
      boost::asio::io_context warmup_ioc;
      boost::asio::co_spawn(
          warmup_ioc,
          [this]() -> boost::asio::awaitable<void> {
            co_await handshake_cache_manager_->Warmup(std::chrono::seconds(3));
          },
          boost::asio::detached);
      warmup_ioc.run();
    }
    // run listener
    boost::asio::co_spawn(
        ioc_,
        [this]() -> boost::asio::awaitable<void> { co_await listener_->Run(); },
        boost::asio::detached);
    boost::asio::co_spawn(
        ioc_,
        [this]() -> boost::asio::awaitable<void> {
          co_await handshake_cache_manager_->MonitorLiveness(
              std::chrono::seconds(3));
        },
        boost::asio::detached);
    boost::asio::co_spawn(
        ioc_,
        [this]() -> boost::asio::awaitable<void> {
          co_await handshake_cache_manager_->RetryDead(std::chrono::seconds(3));
        },
        boost::asio::detached);
    // run threads
    ioc_threads_.reserve(thread_number_);
    for (std::size_t i = 0; i < thread_number_; ++i) {
      ioc_threads_.emplace_back([this]() { ioc_.run(); });
    }
  } catch (boost::system::system_error& err) {
    SPDLOG_ERROR("Server::start error: {}", err.what());
    running_ = false;
    return false;
  }
  return true;
}

bool Server::Stop() {
  if (running_) {
    running_ = false;
    SPDLOG_INFO("Server stop");

    listener_->Stop();

    {
      const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex

      for (auto& session : sessions_) {
        if (session.second) {
          session.second->Close();
        }
      }
    }
    if (!ioc_.stopped()) {
      ioc_.stop();
    }
    for (auto& th : ioc_threads_) {
      if (th.joinable()) {
        th.join();
      }
    }

    const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex

    sessions_.clear();
    return true;
  }
  return false;
}

fptn::web::SessionSPtr Server::GetSessionById(fptn::ClientID client_id) {
  const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

  auto it = sessions_.find(client_id);
  if (it != sessions_.end()) {
    return it->second;
  }
  return nullptr;
}

fptn::common::network::BatchIPPacketPtr Server::WaitForPackets(
    const std::chrono::milliseconds& duration) {
  return from_client_.WaitForPackets(duration);
}

fptn::common::network::IPPacketPtr Server::WaitForPacket(
    const std::chrono::milliseconds& duration) {
  return from_client_.WaitForPacket(duration);
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
boost::asio::awaitable<int> Server::HandleApiDns(
    const http::request& req, http::response& resp) {
  (void)req;

  resp.body() = fmt::format(R"({{"dns": "{}", "dns_ipv6": "{}" }})",
      dns_server_ipv4_.ToString(), dns_server_ipv6_.ToString());
  resp.set(boost::beast::http::field::content_type,
      "application/json; charset=utf-8");
  co_return 200;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
boost::asio::awaitable<int> Server::HandleApiLogin(
    const http::request& req, http::response& resp) {
  try {
    const auto request = nlohmann::json::parse(req.body());
    const auto username = request.at("username").get<std::string>();
    const auto password = request.at("password").get<std::string>();
    std::int64_t bandwidth_bit = 0;
    const auto status =
        co_await user_manager_->LoginAsync(username, password, bandwidth_bit);
    if (status == fptn::user::LoginStatus::kSuccess) {
      SPDLOG_INFO("Successful login for user {}", username);
      const auto tokens = token_manager_->Generate(username, bandwidth_bit);
      resp.body() = fmt::format(
          R"({{ "access_token": "{}", "refresh_token": "{}", "bandwidth_bit": {} }})",
          tokens.first, tokens.second, std::to_string(bandwidth_bit));
      co_return 200;
    }
    if (status == fptn::user::LoginStatus::kAuthServerUnavailable) {
      SPDLOG_ERROR(
          "Authorization server is unavailable, user: \"{}\"", username);
      resp.body() =
          R"({"status": "error", "message": "Authorization server is unavailable."})";
      co_return 503;
    }
    SPDLOG_WARN("Wrong password for user: \"{}\" ", username);
    resp.body() =
        R"({"status": "error", "message": "Invalid login or password."})";
  } catch (const nlohmann::json::exception& e) {
    SPDLOG_ERROR("HTTP JSON AUTH ERROR: {}", e.what());
    resp.body() = R"({"status": "error", "message": "Invalid JSON format."})";
    co_return 400;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("HTTP AUTH ERROR: {}", e.what());
    resp.body() =
        R"({"status": "error", "message": "An unexpected error occurred."})";
    co_return 500;
  } catch (...) {
    SPDLOG_ERROR("UNDEFINED SERVER ERROR");
    resp.body() = R"({"status": "error", "message": "Undefined server error"})";
    co_return 501;
  }
  co_return 401;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
boost::asio::awaitable<int> Server::HandleApiMetrics(
    const http::request& req, http::response& resp) {
  (void)req;

  resp.set(boost::beast::http::field::content_type, "text/html; charset=utf-8");
  resp.body() = prometheus_->Collect();
  co_return 200;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
boost::asio::awaitable<int> Server::HandleApiTestFile(
    const http::request& req, http::response& resp) {
  (void)req;

  static const std::string kData =
      fptn::common::utils::GenerateRandomString(100 * 1024);  // 100KB

  resp.set(boost::beast::http::field::content_type, "application/octet-stream");
  resp.body() = kData;
  co_return 200;
}

fptn::nat::ConnectionMultiplexerSPtr Server::HandleWsOpenConnection(
    const fptn::nat::ConnectParams& params, const SessionSPtr& session) {
  if (!running_) {
    SPDLOG_ERROR("Server is not running");
    return nullptr;
  }
  if (params.request.url != fptn::common::api::kApiWebSocketUrl &&
      params.request.url != fptn::common::api::kApiWebSocketUrlOld) {
    SPDLOG_ERROR("Wrong URL \"{}\"", params.request.url);
    return nullptr;
  }

  std::string username;
  std::size_t bandwidth_bites_seconds = 0;
  if (!token_manager_->Validate(
          params.request.jwt_auth_token, username, bandwidth_bites_seconds)) {
    SPDLOG_WARN("WRONG TOKEN: {}", username);
    return nullptr;
  }

  const auto active_sessions =
      nat_table_->GetNumberActiveSessionByUsername(username);

  if (active_sessions > max_active_sessions_per_user_) {
    SPDLOG_WARN("Session limit exceeded for user '{}': {} active (limit: {})",
        username, active_sessions, max_active_sessions_per_user_);
    return nullptr;
  }

  const auto shaper_to_client =
      std::make_shared<fptn::traffic_shaper::LeakyBucket>(
          bandwidth_bites_seconds);
  const auto shaper_from_client =
      std::make_shared<fptn::traffic_shaper::LeakyBucket>(
          bandwidth_bites_seconds);

  fptn::nat::ConnectParams mod_params = params;
  mod_params.user.username = username;
  mod_params.user.bandwidth_bites_seconds += bandwidth_bites_seconds;

  const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex
  if (!running_ || sessions_.contains(params.client_id)) {
    return nullptr;
  }

  auto nat_session = nat_table_->AddConnection(
      mod_params, shaper_to_client, shaper_from_client);
  if (nat_session == nullptr) {
    SPDLOG_WARN("Failed to allocate NAT session for user '{}' (client_id={})",
        username, params.client_id);
    return nullptr;
  }

  SPDLOG_INFO(
      "NEW CONNECTION! Username={} client_id={} session_id={} Bandwidth={} "
      "ClientIP={} VPN_IPv4={} VPN_IPv6={}",
      username, params.client_id, mod_params.request.session_id,
      mod_params.user.bandwidth_bites_seconds,
      params.request.client_ipv4.ToString(),
      nat_session->FakeClientIPv4().ToString(),
      nat_session->FakeClientIPv6().ToString());

  sessions_.insert({params.client_id, session});
  return nat_session;
}

void Server::HandleWsNewIPPacket(
    fptn::common::network::IPPacketPtr packet) noexcept {
  from_client_.Push(std::move(packet));
}

void Server::HandleWsCloseConnection(fptn::ClientID client_id) noexcept {
  SessionSPtr session;
  if (running_) {
    const std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = sessions_.find(client_id);
    if (it != sessions_.end()) {
      session = std::move(it->second);
      sessions_.erase(it);
    }
  }
  if (session != nullptr) {
    session->Close();
    SPDLOG_INFO("Session closed and removed (client_id={})", client_id);
  } else {
    SPDLOG_WARN(
        "Attempted to close non-existent session (client_id={})", client_id);
  }
  nat_table_->DelConnectionByClientId(client_id);
}
