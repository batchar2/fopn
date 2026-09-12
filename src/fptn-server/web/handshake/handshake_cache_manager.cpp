/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "web/handshake/handshake_cache_manager.h"

#include <algorithm>
#include <array>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast.hpp>
#include <camouflage/tls/builder.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/network/ip_utils.h"
#include "common/network/resolv.h"
#include "common/network/utils.h"

namespace {

std::vector<std::uint8_t> GenerateChromeClientHello(const std::string& sni) {
  const auto handshake =
      camouflage::tls::Builder::Create()
          .GoogleChrome(
              camouflage::tls::google_chrome::Version::kV_149_0_7827_103)
          .SetSNI(sni)
          .Generate();
  if (!handshake.has_value()) {
    return {};
  }
  return {handshake->handshake_packet,
      handshake->handshake_packet + handshake->handshake_packet_size};
}

bool IsTls13Flight(const fptn::web::HandshakeResponse& flight) {
  // TLS record(5) + HS type(1) + HS length(3)
  constexpr std::size_t kServerHelloBodyOffset = 9;
  const std::vector<std::uint8_t>& data = *flight;
  if (data.size() < kServerHelloBodyOffset || data[5] != 0x02) {
    return false;
  }
  const std::uint32_t body_len = (static_cast<std::uint32_t>(data[6]) << 16) |
                                 (static_cast<std::uint32_t>(data[7]) << 8) |
                                 data[8];
  return fptn::common::network::detail::IsTls13ServerHello(
      data, kServerHelloBodyOffset, body_len);
}

// Forwards the client's own ClientHello to the decoy and returns its answer.
//
// This is the Reality property itself: the decoy must see the genuine browser
// fingerprint the client produced, not one of ours. The price is that the
// client's private key is not ours, so the flight cannot be decrypted and its
// end cannot be derived by parsing. The only sound stopping condition left is
// structural plus silence: the buffer holds a whole number of TLS records and
// the decoy has stopped writing. A short answer is not fatal — the client's
// obfuscator resynchronises past whatever it did not consume.
boost::asio::awaitable<fptn::web::HandshakeResponse> FetchForwardedHandshake(
    const std::string& sni,
    const std::vector<std::uint8_t>& client_hello,
    const std::chrono::seconds& timeout) {
  auto executor = co_await boost::asio::this_coro::executor;
  boost::asio::ip::tcp::socket target_socket(executor);

  constexpr std::size_t kMaxTotalSize = 65536;
  constexpr auto kQuietPeriod = std::chrono::milliseconds(300);
  auto full_response = std::make_shared<std::vector<std::uint8_t>>();
  try {
    auto fetch = [&]() -> boost::asio::awaitable<void> {
      const auto resolve_result =
          co_await fptn::common::network::AsyncResolve(sni, "443");
      if (!resolve_result.success()) {
        SPDLOG_WARN(
            "DNS failed for {}: {}", sni, resolve_result.error.message());
        co_return;
      }
      co_await boost::asio::async_connect(
          target_socket, resolve_result.results, boost::asio::use_awaitable);
      co_await boost::asio::async_write(target_socket,
          boost::asio::buffer(client_hello), boost::asio::use_awaitable);

      std::vector<std::uint8_t> data;
      data.reserve(kMaxTotalSize);
      std::array<std::uint8_t, 8192> buf{};
      using boost::asio::experimental::awaitable_operators::operator||;
      while (data.size() < kMaxTotalSize) {
        boost::asio::steady_timer quiet(executor,
            data.empty()
                ? std::chrono::duration_cast<std::chrono::milliseconds>(timeout)
                : kQuietPeriod);
        boost::system::error_code read_ec;
        const auto race = co_await(  // NOLINT(whitespace/parens)
            target_socket.async_read_some(boost::asio::buffer(buf),
                boost::asio::redirect_error(
                    boost::asio::use_awaitable, read_ec)) ||
            quiet.async_wait(boost::asio::use_awaitable));
        if (race.index() == 1) {
          break;
        }
        const std::size_t bytes = std::get<0>(race);
        if (read_ec || bytes == 0) {
          break;
        }
        data.insert(data.end(), buf.begin(), buf.begin() + bytes);
      }

      if (fptn::common::network::IsServerHelloComplete(data)) {
        *full_response = std::move(data);
      } else {
        SPDLOG_WARN(
            "Decoy {} answered {} bytes: not a complete TLS server flight",
            sni, data.size());
      }
    };

    boost::asio::steady_timer deadline(executor, timeout);
    using boost::asio::experimental::awaitable_operators::operator||;
    const auto race = co_await(  // NOLINT(whitespace/parens)
        fetch() || deadline.async_wait(boost::asio::use_awaitable));
    if (race.index() == 1) {
      SPDLOG_WARN("Timeout forwarding handshake to {}", sni);
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Error forwarding handshake to {}: {}", sni, e.what());
  }

  boost::system::error_code close_ec;
  target_socket.close(close_ec);

  // cppcheck-suppress knownConditionTrueFalse
  if (full_response->empty()) {
    co_return nullptr;
  }
  SPDLOG_INFO(
      "Forwarded handshake to {}: {} bytes", sni, full_response->size());
  co_return full_response;
}

}  // namespace

namespace fptn::web {

HandshakeCacheManager::HandshakeCacheManager(
    std::vector<std::string> decoy_domains, std::chrono::seconds cache_ttl)
    : cache_ttl_(cache_ttl),
      decoy_domains_(std::move(decoy_domains)) {}  // NOLINT

HandshakeResponse HandshakeCacheManager::CheckCache(
    const std::string& cache_key) {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  const auto it = cache_.find(cache_key);
  if (it != cache_.end()) {
    const auto& entry = it->second;
    const auto now = std::chrono::steady_clock::now();
    if (now - entry.timestamp < cache_ttl_) {
      return it->second.data;
    }
    cache_.erase(it);
  }
  return nullptr;
}

bool HandshakeCacheManager::IsDead(const std::string& domain) {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  const auto it = dead_.find(domain);
  if (it == dead_.end()) {
    return false;
  }
  if (std::chrono::steady_clock::now() - it->second < cache_ttl_) {
    return true;
  }
  dead_.erase(it);
  return false;
}

void HandshakeCacheManager::MarkDead(const std::string& domain) {
  if (std::ranges::find(decoy_domains_, domain) == decoy_domains_.end()) {
    return;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  dead_[domain] = std::chrono::steady_clock::now();
}

boost::asio::awaitable<HandshakeResponse> HandshakeCacheManager::Fetch(
    const std::string& domain,
    const std::vector<std::uint8_t>& client_hello,
    const std::chrono::seconds& timeout) {
  const HandshakeResponse response =
      co_await FetchForwardedHandshake(domain, client_hello, timeout);
  if (!response || response->empty()) {
    MarkDead(domain);
    co_return nullptr;
  }
  if (!IsTls13Flight(response)) {
    SPDLOG_WARN("Decoy {} negotiated TLS 1.2, unusable", domain);
    MarkDead(domain);
    co_return nullptr;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex
  dead_.erase(domain);
  cache_[domain] = CacheEntry{
      .data = response, .timestamp = std::chrono::steady_clock::now()};
  co_return response;
}

boost::asio::awaitable<void> HandshakeCacheManager::Warmup(
    const std::chrono::seconds& timeout) {
  const auto executor = co_await boost::asio::this_coro::executor;
  for (const auto& domain : decoy_domains_) {
    boost::asio::co_spawn(
        executor,
        [this, &domain, timeout]() -> boost::asio::awaitable<void> {
          try {
            const auto response = co_await Fetch(
                domain, GenerateChromeClientHello(domain), timeout);
            SPDLOG_INFO(
                "Decoy handshake {}: {}", domain, response ? "ready" : "dead");
          } catch (const std::exception& e) {
            SPDLOG_ERROR("Decoy handshake {} failed: {}", domain, e.what());
          }
        },
        boost::asio::detached);
  }
}

boost::asio::awaitable<void> HandshakeCacheManager::MonitorLiveness(
    const std::chrono::seconds& timeout) {
  const auto executor = co_await boost::asio::this_coro::executor;
  boost::asio::steady_timer timer(executor);
  const auto interval = cache_ttl_ - std::chrono::minutes(5);
  for (;;) {
    timer.expires_after(interval);
    boost::system::error_code ec;
    co_await timer.async_wait(
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec == boost::asio::error::operation_aborted) {
      co_return;
    }
    if (ec) {
      SPDLOG_WARN("MonitorLiveness timer error, continuing: {}", ec.message());
      continue;
    }
    co_await Warmup(timeout);
  }
}

boost::asio::awaitable<void> HandshakeCacheManager::RetryDead(
    const std::chrono::seconds& timeout) {
  const auto executor = co_await boost::asio::this_coro::executor;
  boost::asio::steady_timer timer(executor);
  for (;;) {
    timer.expires_after(std::chrono::minutes(5));
    boost::system::error_code ec;
    co_await timer.async_wait(
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec == boost::asio::error::operation_aborted) {
      co_return;
    }
    if (ec) {
      SPDLOG_WARN("RetryDead timer error, continuing: {}", ec.message());
      continue;
    }
    std::size_t dead_count = 0;
    for (const auto& domain : decoy_domains_) {
      if (!IsDead(domain)) {
        continue;
      }
      ++dead_count;
      boost::asio::co_spawn(
          executor,
          [this, &domain, timeout]() -> boost::asio::awaitable<void> {
            try {
              co_await Fetch(
                  domain, GenerateChromeClientHello(domain), timeout);
            } catch (const std::exception& e) {
              SPDLOG_ERROR("Retry decoy {} failed: {}", domain, e.what());
            }
          },
          boost::asio::detached);
    }
    if (dead_count == decoy_domains_.size()) {
      SPDLOG_ERROR(
          "All decoy domains are dead - reality mode will fail. Check "
          "ALLOWED_SNI_LIST and outbound TLS/DNS from this host");
    }
  }
}

boost::asio::awaitable<HandshakeResponse> HandshakeCacheManager::GetHandshake(
    const std::string& sni,
    const std::uint8_t* buffer_ptr,
    std::size_t size,
    const std::chrono::seconds& target_timeout,
    const std::chrono::seconds& fallback_timeout,
    std::string* answered_domain) {
  const std::vector<std::uint8_t> client_hello(buffer_ptr, buffer_ptr + size);

  const auto cached_response = CheckCache(sni);
  if (cached_response && !cached_response->empty()) {
    if (answered_domain) {
      *answered_domain = sni;
    }
    co_return cached_response;
  }
  if (!IsDead(sni)) {
    const auto response = co_await Fetch(sni, client_hello, target_timeout);
    if (response) {
      if (answered_domain) {
        *answered_domain = sni;
      }
      co_return response;
    }
  }

  for (const auto& domain : decoy_domains_) {
    if (domain == sni || IsDead(domain)) {
      continue;
    }
    const auto cached_fallback = CheckCache(domain);
    if (cached_fallback && !cached_fallback->empty()) {
      if (answered_domain) {
        *answered_domain = domain;
      }
      co_return cached_fallback;
    }
    const auto response =
        co_await Fetch(domain, client_hello, fallback_timeout);
    if (response) {
      if (answered_domain) {
        *answered_domain = domain;
      }
      co_return response;
    }
  }
  SPDLOG_WARN("No decoy answered for SNI: {}", sni);
  co_return HandshakeResponse();
}

}  // namespace fptn::web
