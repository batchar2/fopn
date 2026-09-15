/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "fptn-client/utils/speed_estimator/server_info.h"
#include "fptn-client/utils/speed_estimator/speed_estimator.h"
#include "fptn-protocol-lib/https/censorship_strategy.h"

namespace fptn::config {
class ConfigFile final {
 public:
  explicit ConfigFile(std::string sni,
      fptn::protocol::https::CensorshipStrategy censorship_strategy);
  explicit ConfigFile(std::string token,
      std::string sni,
      fptn::protocol::https::CensorshipStrategy censorship_strategy);

  bool Parse();
  std::optional<fptn::utils::speed_estimator::LoginResult> FindServerByLogin(
      int timeout_sec) const;
  std::uint64_t GetDownloadTimeMs(
      const fptn::utils::speed_estimator::ServerInfo& server,
      const std::string& sni,
      int timeout,
      const std::string& md5_fingerprint);

  bool AddServer(const fptn::utils::speed_estimator::ServerInfo& s);

  std::optional<fptn::utils::speed_estimator::ServerInfo> GetServer(
      const std::string& server_name) const;

  int GetVersion() const noexcept;
  const std::string& GetServiceName() const noexcept;
  const std::string& GetUsername() const noexcept;
  const std::string& GetPassword() const noexcept;
  const std::vector<fptn::utils::speed_estimator::ServerInfo>& GetServers()
      const noexcept;

 private:
  const std::string token_;
  const std::string sni_;
  const fptn::protocol::https::CensorshipStrategy censorship_strategy_;

  int version_;
  std::string service_name_;
  std::string username_;
  std::string password_;
  std::vector<fptn::utils::speed_estimator::ServerInfo> servers_;
};
}  // namespace fptn::config
