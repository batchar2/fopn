/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/asio.hpp>

namespace fptn::web {

using HandshakeResponse = std::shared_ptr<std::vector<std::uint8_t>>;

class HandshakeCacheManager final {
 public:
  // A cached ServerHello is replayed verbatim, so every client served from one
  // entry sees the same ServerHello.random. The TTL bounds how long that
  // repetition is observable; refetching costs one TLS handshake per SNI.
  explicit HandshakeCacheManager(std::vector<std::string> decoy_domains,
      std::chrono::seconds cache_ttl = std::chrono::seconds(3600));

  boost::asio::awaitable<HandshakeResponse> GetHandshake(const std::string& sni,
      const std::uint8_t* buffer_ptr,
      std::size_t size,
      const std::chrono::seconds& target_timeout,
      const std::chrono::seconds& fallback_timeout,
      std::string* answered_domain = nullptr);

  boost::asio::awaitable<void> Warmup(const std::chrono::seconds& timeout);

  boost::asio::awaitable<void> MonitorLiveness(
      const std::chrono::seconds& timeout);

  boost::asio::awaitable<void> RetryDead(const std::chrono::seconds& timeout);

  HandshakeResponse CheckCache(const std::string& cache_key);

  bool IsDead(const std::string& domain);

 protected:
  struct CacheEntry {
    HandshakeResponse data;
    std::chrono::steady_clock::time_point timestamp;
  };

  boost::asio::awaitable<HandshakeResponse> Fetch(const std::string& domain,
      const std::vector<std::uint8_t>& client_hello,
      const std::chrono::seconds& timeout);

  void MarkDead(const std::string& domain);

 private:
  mutable std::mutex mutex_;

  std::chrono::seconds cache_ttl_;

  const std::vector<std::string> decoy_domains_;

  std::unordered_map<std::string, CacheEntry> cache_;

  std::unordered_map<std::string, std::chrono::steady_clock::time_point> dead_;
};

using HandshakeCacheManagerSPtr = std::shared_ptr<HandshakeCacheManager>;

}  // namespace fptn::web
