/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "user/user_manager.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <fmt/format.h>     // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/api/handle.h"

using fptn::user::LoginStatus;
using fptn::user::UserManager;

UserManager::UserManager(const std::string& userfile,
    bool use_remote_server,
    std::string remote_server_ip,
    int remote_server_port)
    : use_remote_server_(use_remote_server),
      remote_server_ip_(std::move(remote_server_ip)),
      remote_server_port_(remote_server_port) {
  if (use_remote_server_) {
    // remote user list
    http_api_client_ =
        std::make_unique<fptn::protocol::https::ApiClient>(remote_server_ip_,
            remote_server_port, protocol::https::CensorshipStrategy::kSni);
  } else {
    // local user list
    common_manager_ =
        std::make_unique<fptn::common::user::CommonUserManager>(userfile);
  }
}

boost::asio::awaitable<LoginStatus> UserManager::LoginAsync(
    const std::string& username,
    const std::string& password,
    std::int64_t& bandwidth_bit) const {
  bandwidth_bit = 0;
  if (use_remote_server_) {
    SPDLOG_INFO(
        "LoginAsync request to {}:{}", remote_server_ip_, remote_server_port_);

    const std::string request = fmt::format(
        R"({{ "username": "{}", "password": "{}" }})", username, password);
    const auto resp = co_await http_api_client_->AsyncPost(
        common::api::kApiLoginUrl, request, "application/json");

    if (resp.code == 200) {
      try {
        const auto msg = resp.Json();
        if (msg.contains("access_token") && msg.contains("bandwidth_bit")) {
          bandwidth_bit = msg["bandwidth_bit"].get<std::int64_t>();
          co_return LoginStatus::kSuccess;
        }
        SPDLOG_INFO(
            "LoginAsync: access_token not found in response. "
            "Check your connection");
      } catch (const nlohmann::json::parse_error& e) {
        SPDLOG_INFO(
            "LoginAsync: JSON parse error: {}\n{}", e.what(), resp.body);
      }
      co_return LoginStatus::kAuthServerUnavailable;
    }
    if (resp.code == 401 || resp.code == 403) {
      co_return LoginStatus::kInvalidCredentials;
    }
    SPDLOG_INFO(
        "LoginAsync: request failed. Code: {} Msg: {}", resp.code, resp.errmsg);
    co_return LoginStatus::kAuthServerUnavailable;
  }
  if (common_manager_->Authenticate(username, password)) {
    bandwidth_bit = common_manager_->GetUserBandwidthBit(username);
    co_return LoginStatus::kSuccess;
  }
  co_return LoginStatus::kInvalidCredentials;
}

bool UserManager::Login(const std::string& username,
    const std::string& password,
    std::int64_t& bandwidth_bit) const {
  bandwidth_bit = 0;  // reset
  if (use_remote_server_) {
    SPDLOG_INFO(
        "Login request to {}:{}", remote_server_ip_, remote_server_port_);

    const std::string request = fmt::format(
        R"({{ "username": "{}", "password": "{}" }})", username, password);
    const auto resp = http_api_client_->Post(
        common::api::kApiLoginUrl, request, "application/json");

    if (resp.code == 200) {
      try {
        const auto msg = resp.Json();
        if (msg.contains("access_token") && msg.contains("bandwidth_bit")) {
          bandwidth_bit = msg["bandwidth_bit"].get<std::int64_t>();
          return true;
        }
        SPDLOG_INFO(
            "User manager error: Access token not found in the response. "
            "Check your connection");
      } catch (const nlohmann::json::parse_error& e) {
        SPDLOG_INFO("User manager: Error parsing JSON response: {}\n{}",
            e.what(), resp.body);
      }
    } else {
      SPDLOG_INFO(
          "User manager: request failed or response is null. Code: {} Msg: {}",
          resp.code, resp.errmsg);
    }
  } else if (common_manager_->Authenticate(username, password)) {
    bandwidth_bit = common_manager_->GetUserBandwidthBit(username);
    return true;
  }
  return false;
}
