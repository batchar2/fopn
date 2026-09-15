/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <chrono>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

#include <jwt-cpp/base.h>  // NOLINT(build/include_order)
#include <jwt-cpp/jwt.h>   // NOLINT(build/include_order)
#include <jwt-cpp/traits/nlohmann-json/defaults.h>  // NOLINT(build/include_order)
#include <nlohmann/json.hpp>  // NOLINT(build/include_order)
#include <spdlog/spdlog.h>    // NOLINT(build/include_order)

namespace fptn::common::jwt_token {
class TokenManager {
 public:
  TokenManager(
      const std::string& server_crt_path, const std::string& server_key_path)
      : server_crt_path_(server_crt_path),
        server_key_path_(server_key_path),
        server_crt_(ReadFromFile(server_crt_path_)),
        server_key_(ReadFromFile(server_key_path_)) {}

  [[nodiscard]] std::pair<std::string, std::string> Generate(
      const std::string& username, std::int64_t bandwidth_bit) const noexcept {
    const auto now = std::chrono::system_clock::now();
    // CHECK JWT
    const auto access_token =
        jwt::create<jwt::traits::nlohmann_json>()
            .set_issuer("auth0")
            .set_type("JWT")
            .set_id("fptn")
            .set_issued_at(now)
            .set_expires_at(now + std::chrono::hours{24 * 30})
            .set_payload_claim("username", username)
            .set_payload_claim("bandwidth_bit", bandwidth_bit)
            .sign(jwt::algorithm::rs256("", server_key_, "", ""));
    return std::make_pair(access_token, "");
  }

  bool Validate(const std::string& token,
      std::string& username,
      std::size_t& bandwidth_bit) const noexcept {
    try {
      const auto decoded = jwt::decode<jwt::traits::nlohmann_json>(token);
      username = decoded.get_payload_claim("username").as_string();
      bandwidth_bit = decoded.get_payload_claim("bandwidth_bit").as_integer();

      const auto verifier =
          jwt::verify<jwt::default_clock, jwt::traits::nlohmann_json>(
              jwt::default_clock())
              .allow_algorithm(jwt::algorithm::rs256("", server_key_, "", ""))
              .with_issuer("auth0");
      verifier.verify(decoded);
      return true;
    } catch (const jwt::error::invalid_json_exception& e) {
      SPDLOG_ERROR("Token parsing error: {}", e.what());
    } catch (const jwt::error::token_verification_exception& e) {
      SPDLOG_ERROR("Unauthorized: Invalid token: {}", e.what());
    } catch (const std::exception& e) {
      SPDLOG_ERROR("Handle other standard exceptions: {}", e.what());
    } catch (...) {
      SPDLOG_ERROR("Undefined error");
    }
    return false;
  }

  const std::string& ServerCrtPath() const noexcept { return server_crt_path_; }

  const std::string& ServerKeyPath() const noexcept { return server_key_path_; }

 private:
  std::string ReadFromFile(const std::string& path) noexcept {
    std::ifstream is(path, std::ios::binary);
    if (!is) {
      SPDLOG_ERROR("Failed to open file: {}", path);
      return {};
    }
    std::string contents(
        (std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());
    return contents;
  }

 private:
  const std::string server_crt_path_;
  const std::string server_key_path_;

  const std::string server_crt_;
  const std::string server_key_;
};

using TokenManagerSPtr = std::shared_ptr<TokenManager>;
}  // namespace fptn::common::jwt_token
