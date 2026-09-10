/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "config/config_file.h"

#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "common/utils/base64.h"
#include "common/utils/utils.h"

#include "utils/brotli/brotli.h"

using fptn::utils::speed_estimator::ServerInfo;

namespace fptn::config {

ConfigFile::ConfigFile(std::string sni,
    fptn::protocol::https::CensorshipStrategy censorship_strategy)
    : sni_(std::move(sni)),
      censorship_strategy_(censorship_strategy),
      version_(0) {}  // NOLINT(whitespace/indent_namespace)

ConfigFile::ConfigFile(std::string token,
    std::string sni,
    fptn::protocol::https::CensorshipStrategy censorship_strategy)
    : token_(std::move(token)),
      sni_(std::move(sni)),
      censorship_strategy_(censorship_strategy),
      version_(0) {}  // NOLINT(whitespace/indent_namespace)

bool ConfigFile::AddServer(const ServerInfo& s) {
  servers_.push_back(s);
  return true;
}

std::optional<ServerInfo> ConfigFile::GetServer(
    const std::string& server_name) const {
  const std::string prepared_server_name =
      fptn::common::utils::Trim(fptn::common::utils::ToLowerCase(server_name));

  if (server_name.empty()) {
    return std::nullopt;
  }

  auto it = std::ranges::find_if(
      servers_, [&prepared_server_name](
                    const fptn::utils::speed_estimator::ServerInfo& server) {
        return fptn::common::utils::Trim(fptn::common::utils::ToLowerCase(
                   server.name)) == prepared_server_name;
      });
  if (it != servers_.end()) {
    return *it;
  }
  return std::nullopt;
}

bool ConfigFile::Parse() {
  try {
    if (token_.empty()) {
      throw std::runtime_error("Token is empty");
    }
    std::string token_data;
    if (token_.starts_with("fptnb:") || token_.starts_with("fptnb//")) {
      // Brotli
      const std::string compressed_data = fptn::common::utils::base64::decode(
          fptn::common::utils::RemoveSubstring(
              token_, {"fptnb:", "fptnb//", " ", "\n", "\r", "\t", "="}));
      token_data = fptn::utils::brotli::Decompress(compressed_data);
    } else {
      const std::string sanitized_token = fptn::common::utils::RemoveSubstring(
          token_, {"fptn://", "fptn:", " ", "\n", "\r", "\t", "="});
      token_data = fptn::common::utils::base64::decode(sanitized_token);
    }

    const auto config = nlohmann::json::parse(token_data);
    version_ = config.at("version").get<int>();
    service_name_ = config.at("service_name").get<std::string>();
    username_ = config.at("username").get<std::string>();
    password_ = config.at("password").get<std::string>();
    for (const auto& server : config.at("servers")) {
      ServerInfo s(server.at("name").get<std::string>(),
          server.at("host").get<std::string>(), server.at("port").get<int>(),
          server.at("md5_fingerprint").get<std::string>());
      servers_.push_back(s);
    }
    if (servers_.empty()) {
      throw std::runtime_error("Server list is empty!");
    }
    return true;
  } catch (const nlohmann::json::exception& e) {
    throw std::runtime_error(std::string("JSON parsing error: ") + e.what() +
                             ". Try to update your token");
  } catch (const std::exception& e) {
    throw std::runtime_error(std::string("Token parsing error: ") + e.what());
  }
}

std::optional<fptn::utils::speed_estimator::LoginResult>
ConfigFile::FindServerByLogin(int timeout_sec) const {
  // Ensure every server has credentials (CLI path sets them at ConfigFile
  // level)
  std::vector<ServerInfo> servers = servers_;
  for (auto& s : servers) {
    if (s.username.empty()) s.username = username_;
    if (s.password.empty()) s.password = password_;
  }
  return fptn::utils::speed_estimator::FindServerByLogin(
      sni_, servers, censorship_strategy_, timeout_sec);
}

std::uint64_t ConfigFile::GetDownloadTimeMs(const ServerInfo& server,
    const std::string& sni,
    int timeout,
    const std::string& md5_fingerprint) {
  return fptn::utils::speed_estimator::GetDownloadTimeMs(
      server, sni, timeout, md5_fingerprint, censorship_strategy_);
}

int ConfigFile::GetVersion() const noexcept { return version_; }

const std::string& ConfigFile::GetServiceName() const noexcept {
  return service_name_;
}

const std::string& ConfigFile::GetUsername() const noexcept {
  return username_;
}

const std::string& ConfigFile::GetPassword() const noexcept {
  return password_;
}

const std::vector<ServerInfo>& ConfigFile::GetServers() const noexcept {
  return servers_;
}
}  // namespace fptn::config
