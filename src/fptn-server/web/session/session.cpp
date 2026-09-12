/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "web/session/session.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include <boost/algorithm/string/replace.hpp>
#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <openssl/rand.h>   // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/api/handle.h"
#include "common/network/resolv.h"
#include "common/network/utils.h"
#include "common/utils/utils.h"

#include "fptn-protocol-lib/https/obfuscator/methods/detector.h"
#include "fptn-protocol-lib/https/obfuscator/methods/tls/tls_obfuscator.h"
#include "fptn-protocol-lib/https/obfuscator/methods/tls2/tls_obfuscator2.h"
#include "fptn-protocol-lib/https/utils/tls/tls.h"
#include "fptn-protocol-lib/protocol/protobuf/protobuf_serializer.h"
#include "fptn-protocol-lib/protocol/yaff/yaff_serializer.h"
#include "fptn-protocol-lib/time/time_provider.h"

namespace {
std::atomic<fptn::ClientID> client_id_counter = 0;

std::vector<std::string> GetServerIpAddresses(
    const std::string& server_external_ips) {
  static std::mutex ip_mutex;
  static std::vector<std::string> server_ips;

  const std::scoped_lock lock(ip_mutex);  // mutex

  if (server_ips.empty()) {
    server_ips = fptn::common::network::GetServerIpAddresses();

    if (!server_external_ips.empty()) {
      const auto external_ips =
          fptn::common::utils::SplitCommaSeparated(server_external_ips);
      std::ranges::copy_if(external_ips, std::back_inserter(server_ips),
          [](const std::string& ip) {
            return fptn::common::network::IsIpAddress(ip);
          });
    }
  }
  return server_ips;
}

std::string NormalizeSni(std::string sni) {
  std::ranges::transform(sni, sni.begin(),
      [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return sni;
}

std::string ApplyAllowedSniList(std::string sni,
    const std::vector<std::string>& allowed_sni_list,
    const std::string& default_domain,
    fptn::ClientID client_id) {
  if (allowed_sni_list.empty() || sni == default_domain) {
    return sni;
  }

  const bool sni_allowed =
      std::ranges::any_of(allowed_sni_list, [&sni](const std::string& entry) {
        const std::string allowed_sni = NormalizeSni(entry);
        if (sni == allowed_sni) {
          return true;
        }
        // check subdomains
        if (sni.size() > allowed_sni.size() + 1) {
          return sni.ends_with("." + allowed_sni);
        }
        return false;
      });
  if (sni_allowed) {
    return sni;
  }

  SPDLOG_WARN(
      "SNI '{}' (len={}) not in allowed list, using default domain: {} "
      "(client_id={})",
      sni, sni.size(), default_domain, client_id);
  return default_domain;
}

constexpr auto kSelfProxyCacheTtl = std::chrono::hours(1);

using SelfProxyEntry = std::pair<bool, std::chrono::steady_clock::time_point>;

std::mutex self_proxy_mutex;
std::unordered_map<std::string, SelfProxyEntry> self_proxy_cache;

std::optional<bool> GetCachedSelfProxyVerdict(const std::string& sni) {
  const std::scoped_lock lock(self_proxy_mutex);  // mutex

  const auto it = self_proxy_cache.find(sni);
  if (it == self_proxy_cache.end()) {
    return std::nullopt;
  }
  if (std::chrono::steady_clock::now() - it->second.second >=
      kSelfProxyCacheTtl) {
    self_proxy_cache.erase(it);
    return std::nullopt;
  }
  return it->second.first;
}

void CacheSelfProxyVerdict(const std::string& sni, bool is_self_proxy) {
  const std::scoped_lock lock(self_proxy_mutex);  // mutex

  self_proxy_cache[sni] = {is_self_proxy, std::chrono::steady_clock::now()};
}

void SetSocketTimeouts(boost::asio::ip::tcp::socket& socket, int timeout_sec) {
  timeval tv = {};
  tv.tv_sec = timeout_sec;
  tv.tv_usec = 0;
  const int socket_fd = socket.native_handle();
  ::setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO,
      reinterpret_cast<const char*>(&tv), sizeof(tv));
  ::setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO,
      reinterpret_cast<const char*>(&tv), sizeof(tv));
}

std::uint64_t ParseRequestUint(
    const boost::beast::http::request<boost::beast::http::string_body>& request,
    const std::string& param_name,
    const std::uint64_t default_value) {
  if (!request.contains(param_name)) {
    return default_value;
  }
  try {
    const std::string value_str = request[param_name];
    std::size_t pos = 0;
    const std::uint64_t value = std::stoull(value_str, &pos, 10);
    if (pos != value_str.size()) {
      return default_value;
    }
    return value;
  } catch (const std::exception&) {
    return default_value;
  }
}

std::string ParseRequestStr(
    const boost::beast::http::request<boost::beast::http::string_body>& request,
    const std::string& param_name,
    const std::string& default_value) {
  if (request.contains(param_name)) {
    return request[param_name];
  }
  return default_value;
}

std::vector<std::uint8_t> RandomBytes(std::size_t size) {
  std::vector<std::uint8_t> bytes(size);
  if (::RAND_bytes(bytes.data(), static_cast<int>(size)) != 1) {
    return {};
  }
  return bytes;
}

boost::asio::awaitable<std::size_t> PeekWithTimeout(
    boost::asio::ip::tcp::socket& socket,
    const boost::asio::mutable_buffer& buffer,
    const std::chrono::milliseconds& timeout,
    boost::system::error_code& ec) {
  using boost::asio::experimental::awaitable_operators::operator||;
  boost::asio::steady_timer timer(
      co_await boost::asio::this_coro::executor, timeout);
  const auto result = co_await(
      socket.async_receive(buffer, boost::asio::socket_base::message_peek,
          boost::asio::redirect_error(boost::asio::use_awaitable, ec)) ||
      timer.async_wait(boost::asio::use_awaitable));
  if (result.index() == 1) {
    ec = boost::asio::error::timed_out;
    co_return 0;
  }
  co_return std::get<0>(result);
}

boost::asio::awaitable<std::size_t> PeekClientHelloWithTimeout(
    boost::asio::ip::tcp::socket& socket,
    const boost::asio::mutable_buffer& buffer,
    const std::chrono::milliseconds& timeout,
    boost::system::error_code& ec) {
  constexpr auto kPollInterval = std::chrono::milliseconds(20);

  const auto deadline = std::chrono::steady_clock::now() + timeout;
  const auto* data = static_cast<const std::uint8_t*>(buffer.data());

  std::size_t bytes_read = 0;
  for (;;) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      break;
    }
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);

    const std::size_t peeked =
        co_await PeekWithTimeout(socket, buffer, remaining, ec);
    if (ec || !peeked) {
      if (bytes_read) {
        ec.clear();
        break;
      }
      co_return 0;
    }
    bytes_read = peeked;

    constexpr std::size_t kTlsClientHelloPrefixLen = 6;
    if (bytes_read >= kTlsClientHelloPrefixLen &&
        !fptn::common::network::IsTlsClientHello(data, bytes_read)) {
      break;
    }

    if (fptn::common::network::IsClientHelloComplete(
            std::vector<std::uint8_t>(data, data + bytes_read))) {
      break;
    }
    if (bytes_read == buffer.size()) {
      break;
    }

    boost::asio::steady_timer timer(
        co_await boost::asio::this_coro::executor, kPollInterval);
    co_await timer.async_wait(boost::asio::use_awaitable);
  }
  co_return bytes_read;
}

}  // namespace

namespace fptn::web {

using BatchIPPacketPtr = common::network::BatchIPPacketPtr;

Session::Session(bool enable_detect_probing,
    std::vector<std::string> allowed_sni_list,
    std::string server_external_ips,
    boost::asio::ip::tcp::socket&& socket,
    boost::asio::ssl::context& ctx,
    const ApiHandleMap& api_handles,
    HandshakeCacheManagerSPtr handshake_cache_manager,
    WebSocketOpenConnectionCallback ws_open_callback,
    WebSocketNewIPPacketCallback ws_new_ippacket_callback,
    WebSocketCloseConnectionCallback ws_close_callback)
    : enable_detect_probing_(enable_detect_probing),
      allowed_sni_list_(std::move(allowed_sni_list)),
      server_external_ips_(std::move(server_external_ips)),
      ws_(ssl_stream_type(
          obfuscator_socket_type(tcp_stream_type(std::move(socket))), ctx)),
      strand_(ws_.get_executor()),
      // Capacity is counted in batches, not packets.
      write_channel_(strand_, 32),
      api_handles_(api_handles),
      handshake_cache_manager_(std::move(handshake_cache_manager)),
      ws_open_callback_(std::move(ws_open_callback)),
      ws_new_ippacket_callback_(std::move(ws_new_ippacket_callback)),
      ws_close_callback_(std::move(ws_close_callback)),
      running_(false),
      init_completed_(false),
      ws_session_was_opened_(false),
      full_queue_(false),
      support_batch_sending_(false),
      use_yaff_serializer_(false) {
  try {
    client_id_ = ++client_id_counter;
    boost::beast::get_lowest_layer(ws_).socket().set_option(
        boost::asio::ip::tcp::no_delay(true));

    ws_.text(false);
    ws_.binary(true);
    ws_.auto_fragment(false);
    ws_.read_message_max(256 * 1024);
    ws_.set_option(boost::beast::websocket::stream_base::timeout::suggested(
        boost::beast::role_type::server));
    ws_.set_option(boost::beast::websocket::stream_base::timeout{
        .handshake_timeout = std::chrono::seconds(60),
        .idle_timeout = std::chrono::seconds(60),
        .keep_alive_pings = true});
    ws_.set_option(
        boost::beast::websocket::permessage_deflate{.server_enable = false,
            .client_enable = false,
            .server_max_window_bits = 15,  // MAX
            .client_max_window_bits = 15,  // MAX
            .compLevel = 3,
            .memLevel = 8});

    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(10));
    init_completed_ = true;
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Session::init failed (client_id={}): {} [{}]", client_id_,
        err.what(), err.code().message());
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Session::init unexpected exception (client_id={}): {}",
        client_id_, e.what());
  } catch (...) {
    SPDLOG_ERROR(
        "Session::init unknown fatal error (client_id={})", client_id_);
  }
}

Session::~Session() {
  if (running_.exchange(false)) {
    DoClose();
  }
}

boost::asio::any_io_executor Session::GetExecutor() const noexcept {
  return strand_;
}

boost::asio::awaitable<void> Session::Run() {
  boost::system::error_code ec;

  running_ = true;
  if (!init_completed_) {
    SPDLOG_ERROR("Session not initialized. Closing connection (client_id={})",
        client_id_);
    Close();
    co_return;
  }

  // Setup traffic obfuscator
  auto obfuscator_opt = co_await DetectObfuscator();
  if (!obfuscator_opt.has_value()) {
    Close();
    co_return;
  }
  ws_.next_layer().next_layer().set_obfuscator(obfuscator_opt.value());

  std::array<std::uint8_t, 16384> client_hello{};
  std::size_t client_hello_size = 0;
  std::string client_sni = ProxyFallbackDomain();
  if (obfuscator_opt.value() == nullptr) {
    auto& tcp_socket = boost::beast::get_lowest_layer(ws_).socket();

    boost::system::error_code peek_ec;
    client_hello_size = co_await PeekClientHelloWithTimeout(tcp_socket,
        boost::asio::buffer(client_hello), std::chrono::seconds(3), peek_ec);
    if (peek_ec || !client_hello_size) {
      SPDLOG_ERROR("Peeked zero bytes from socket (client_id={})", client_id_);
      Close();
      co_return;
    }
    if (!fptn::common::network::IsTlsClientHello(
            client_hello.data(), client_hello_size)) {
      SPDLOG_ERROR(
          "Not an SSL message, closing connection (client_id={})", client_id_);
      Close();
      co_return;
    }

    const auto sni_opt =
        common::network::GetTlsSNI(client_hello.data(), client_hello_size);
    if (!sni_opt.has_value()) {
      SPDLOG_WARN(
          "Failed to extract SSLClientHelloMessage from handshake "
          "(client_id={})",
          client_id_);
    } else {
      client_sni = NormalizeSni(sni_opt.value());
    }
    client_sni = ApplyAllowedSniList(std::move(client_sni), allowed_sni_list_,
        ProxyFallbackDomain(), client_id_);
  }

  // Detect probing (only for null obfuscator)
  if (enable_detect_probing_ && obfuscator_opt.value() == nullptr) {
    const auto probing_result = co_await DetectProbing(
        client_hello.data(), client_hello_size, client_sni);
    if (probing_result.should_close) {
      SPDLOG_WARN(
          "Connection rejected during probing (client_id={})", client_id_);
      Close();
      co_return;
    }
    if (probing_result.is_probing) {
      SPDLOG_WARN(
          "Probing detected. Redirecting to proxy (client_id={}, SNI={}, "
          "port={})",
          client_id_, probing_result.sni, 443);
      co_await ProxyWithFallback(probing_result.sni);
      Close();
      co_return;
    }
    SPDLOG_INFO("SESSION ID correct. Continue setup connection (client_id={})",
        client_id_);
  }

  // Check for Reality Mode handshake (only when no obfuscator is detected)
  if (obfuscator_opt.value() == nullptr) {
    const auto result =
        IsRealityHandshake(client_hello.data(), client_hello_size, client_sni);
    if (result.should_close) {
      SPDLOG_WARN(
          "Reality Mode handshake check failed. Redirecting to proxy "
          "(client_id={}, SNI={})",
          client_id_, client_sni);
      co_await ProxyWithFallback(client_sni);
      Close();
      co_return;
    }

    // Process Reality Mode connection if detected
    if (result.is_reality_mode || result.is_reality_mode2) {
      if (result.is_reality_mode) {
        SPDLOG_INFO("Processing Reality Mode connection sni={} (client_id={}) ",
            result.sni, client_id_);
      }
      if (result.is_reality_mode2) {
        SPDLOG_INFO(
            "Processing Reality Mode2 connection sni={} (client_id={}) ",
            result.sni, client_id_);
      }

      // Prevent recursive proxy attempts for Reality Mode
      const std::string fallback_domain = ProxyFallbackDomain();
      if (result.sni != fallback_domain) {
        const auto self_proxy = co_await IsSniSelfProxyAttempt(result.sni);
        if (self_proxy) {
          co_await HandleProxy(fallback_domain, 443);
          Close();
          co_return;
        }
      }

      // Refresh the beast timeout: the construction-time deadline was already
      // partly spent on probing and DNS, so give the fake handshake a full,
      // fresh budget instead of a stale one that can cancel its reads midway.
      boost::beast::get_lowest_layer(ws_).expires_after(
          std::chrono::seconds(10));

      bool reality_success = false;
      if (result.is_reality_mode) {
        // DEPRECATED
        reality_success = co_await PerformFakeHandshake(result.sni);
        // For Reality Mode we use TLS obfuscator after fake handshake
        // This provides additional encryption layer for the real connection
        ws_.next_layer().next_layer().set_obfuscator(
            std::make_shared<protocol::https::obfuscator::TlsObfuscator>());
      } else {
        reality_success = co_await PerformFakeHandshake2(result.sni);
        // For Reality Mode we use TLS obfuscator after fake handshake
        // This provides additional encryption layer for the real connection
        ws_.next_layer().next_layer().set_obfuscator(
            std::make_shared<protocol::https::obfuscator::TlsObfuscator2>());
      }

      if (!reality_success) {
        SPDLOG_WARN("Reality mode handshake failed (client_id={})", client_id_);
        Close();
        co_return;
      }
    }
  }
  // SSL handshake
  boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(10));
  co_await ws_.next_layer().async_handshake(
      boost::asio::ssl::stream_base::server,
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec) {
    SPDLOG_WARN("TLS-Handshake error (client_id={})", client_id_);
    Close();
    co_return;
  }

  // Reset obfuscator after TLS handshake
  ws_.next_layer().next_layer().set_obfuscator(nullptr);

  // Process request (HTTP or WebSocket)
  auto& tcp_socket = boost::beast::get_lowest_layer(ws_).socket();
  const bool status = co_await ProcessRequest();
  if (status && tcp_socket.is_open()) {
    tcp_socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
    tcp_socket.set_option(boost::asio::socket_base::keep_alive(true), ec);

    auto self = shared_from_this();
    boost::asio::co_spawn(
        strand_,
        [self]() mutable -> boost::asio::awaitable<void> {
          return self->RunReader();
        },
        boost::asio::detached);
    boost::asio::co_spawn(
        strand_,
        [self]() mutable -> boost::asio::awaitable<void> {
          return self->RunSender();
        },
        boost::asio::detached);

  } else {
    Close();
  }
  co_return;
}

std::string Session::ProxyFallbackDomain() const {
  const auto it = std::ranges::find_if(
      allowed_sni_list_, [this](const std::string& domain) {
        return !handshake_cache_manager_->IsDead(domain);
      });
  return it != allowed_sni_list_.end() ? *it : allowed_sni_list_.front();
}

boost::asio::awaitable<Session::ProbingResult> Session::DetectProbing(
    const std::uint8_t* client_hello, std::size_t size, std::string sni) {
  try {
    // Detect and prevent recursive proxying to the local server
    const std::string fallback_domain = ProxyFallbackDomain();
    if (sni != fallback_domain) {
      const bool is_recursive_attempt = co_await IsSniSelfProxyAttempt(sni);
      if (is_recursive_attempt) {
        SPDLOG_WARN(
            "Detected recursive proxy attempt! "
            "Client: {}, SNI: {}, Redirecting to default SNI: {}",
            client_id_, sni, fallback_domain);
        sni = fallback_domain;
      }
    }

    // Get Session ID
    constexpr std::size_t kSessionLen = 32;
    const auto session_id =
        common::network::GetTlsSessionId(client_hello, size);

    if (session_id.size() != kSessionLen) {
      SPDLOG_ERROR(
          "Invalid session ID length: expected {}, got {} (client_id={})",
          kSessionLen, session_id.size(), client_id_);
      co_return ProbingResult{
          .is_probing = true, .sni = sni, .should_close = false};
    }

    // Check Session ID
    const bool is_fptn_session_id =
        protocol::https::utils::IsFptnClientSessionID(
            session_id.data(), session_id.size());
    const bool is_decoy_session_id =
        protocol::https::utils::IsDecoyHandshakeSessionID(
            session_id.data(), session_id.size());
    const bool is_decoy_session_id2 =
        protocol::https::utils::IsDecoyHandshakeSessionID2(
            session_id.data(), session_id.size());
    if (!is_fptn_session_id && !is_decoy_session_id && !is_decoy_session_id2) {
      SPDLOG_ERROR(
          "Session ID does not match FPTN client format (client_id={})",
          client_id_);
      co_return ProbingResult{
          .is_probing = true, .sni = sni, .should_close = false};
    }
    // Valid FPTN client
    co_return ProbingResult{
        .is_probing = false, .sni = sni, .should_close = false};
  } catch (const boost::system::system_error& e) {
    SPDLOG_ERROR(
        "System error during probing: {} (client_id={})", e.what(), client_id_);
  } catch (const std::exception& e) {
    SPDLOG_ERROR(
        "Exception during probing: {} (client_id={})", e.what(), client_id_);
  } catch (...) {
    SPDLOG_ERROR("Unknown exception during probing (client_id={})", client_id_);
  }
  co_return ProbingResult{
      .is_probing = true, .sni = ProxyFallbackDomain(), .should_close = true};
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
boost::asio::awaitable<bool> Session::IsSniSelfProxyAttempt(
    const std::string& sni) const {
  // First check if SNI is already an IP address
  if (fptn::common::network::IsIpAddress(sni)) {
    // FIXME
    SPDLOG_WARN("SNI is IP address, treating as potential self-proxy: {}", sni);
    co_return true;
  }

  const auto cached_verdict = GetCachedSelfProxyVerdict(sni);
  if (cached_verdict.has_value()) {
    co_return cached_verdict.value();
  }

  // Not an IP address - proceed with DNS resolution using our new function
  try {
    const auto server_ips = GetServerIpAddresses(server_external_ips_);

    boost::asio::ip::tcp::resolver resolver(
        co_await boost::asio::this_coro::executor);
    boost::system::error_code resolve_ec;
    using boost::asio::experimental::awaitable_operators::operator||;
    boost::asio::steady_timer timer(
        co_await boost::asio::this_coro::executor, std::chrono::seconds(5));
    const auto race =
        co_await(resolver.async_resolve(sni, "",
                     boost::asio::redirect_error(
                         boost::asio::use_awaitable, resolve_ec)) ||
                 timer.async_wait(boost::asio::use_awaitable));
    if (race.index() == 1) {
      SPDLOG_WARN("DNS resolution timed out for {}", sni);
      CacheSelfProxyVerdict(sni, false);
      co_return false;
    }
    if (resolve_ec) {
      SPDLOG_WARN(
          "DNS resolution failed for {}: {}", sni, resolve_ec.message());
      CacheSelfProxyVerdict(sni, false);
      co_return false;
    }

    // Iterate through resolved endpoints
    for (const auto& endpoint : std::get<0>(race)) {
      const auto ip = endpoint.endpoint().address().to_string();
      if (ip.empty()) {
        continue;
      }
      // check server interfaces
      if (std::ranges::find(server_ips, ip) != server_ips.end()) {
        SPDLOG_WARN(
            "SNI {} resolves to server interface IP {}, blocking self-proxy",
            sni, ip);
        CacheSelfProxyVerdict(sni, true);
        co_return true;
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_WARN("Exception during DNS resolution for {}: {}", sni, e.what());
    co_return false;
  }

  CacheSelfProxyVerdict(sni, false);
  co_return false;
}

Session::RealityResult Session::IsRealityHandshake(
    const std::uint8_t* client_hello, std::size_t size, std::string sni) const {
  try {
    // Get Session ID
    constexpr std::size_t kSessionLen = 32;
    const auto session_id =
        common::network::GetTlsSessionId(client_hello, size);

    if (session_id.size() == kSessionLen) {
      // Check if it's a decoy handshake (reality mode)
      const bool is_reality = protocol::https::utils::IsDecoyHandshakeSessionID(
          session_id.data(), session_id.size());
      const bool is_reality2 =
          protocol::https::utils::IsDecoyHandshakeSessionID2(
              session_id.data(), session_id.size());
      if (is_reality || is_reality2) {
        return RealityResult{.is_reality_mode = is_reality,
            .is_reality_mode2 = is_reality2,
            .sni = std::move(sni),
            .should_close = false};
      }
      if (protocol::https::utils::IsFptnClientSessionID(
              session_id.data(), session_id.size())) {
        return RealityResult{.is_reality_mode = false,
            .is_reality_mode2 = false,
            .sni = std::move(sni),
            .should_close = false};
      }
      SPDLOG_WARN("Session ID does not match FPTN client format (client_id={})",
          client_id_);
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("IsRealityHandshake exception (client_id={}): {}", client_id_,
        e.what());
  }
  return RealityResult{.is_reality_mode = true,
      .is_reality_mode2 = false,
      .sni = "",
      .should_close = true};
}

// DEPRECATED
boost::asio::awaitable<bool> Session::PerformFakeHandshake(
    const std::string& sni) {
  try {
    auto& tcp_socket = boost::beast::get_lowest_layer(ws_).socket();

    std::vector<std::uint8_t> buffer(16384, '\0');
    // std::string buffer(16384, '\0');
    const std::size_t bytes_read = co_await tcp_socket.async_receive(
        boost::asio::buffer(buffer), boost::asio::use_awaitable);
    if (!bytes_read || !handshake_cache_manager_) {
      co_return false;
    }
    buffer.resize(bytes_read);

    const auto handshake_answer =
        co_await handshake_cache_manager_->GetHandshake(sni, buffer.data(),
            bytes_read, std::chrono::seconds(2), std::chrono::seconds(3));

    if (!handshake_answer) {
      co_return false;
    }

    std::vector<std::uint8_t> answer = *handshake_answer;
    const auto client_session_id =
        common::network::GetTlsSessionId(buffer.data(), bytes_read);
    if (!common::network::SetTlsSessionId(answer, client_session_id)) {
      SPDLOG_WARN("Could not restamp session id for {} (client_id={})", sni,
          client_id_);
    }
    constexpr std::size_t kTlsRandomLen = 32;
    common::network::SetTlsServerRandom(answer, RandomBytes(kTlsRandomLen));
    common::network::SetTlsServerKeyShare(answer, RandomBytes(kTlsRandomLen));

    const std::size_t bytes_wrote = co_await boost::asio::async_write(
        tcp_socket, boost::asio::buffer(answer), boost::asio::use_awaitable);

    SPDLOG_INFO(
        "Reality mode completed, ready for real handshake (client_id={}) "
        "request_size = {} response_size: {}",
        client_id_, bytes_read, bytes_wrote);
    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR(
        "HandleRealityMode exception (client_id={}): {}", client_id_, e.what());
  }
  co_return false;
}

boost::asio::awaitable<bool> Session::PerformFakeHandshake2(
    const std::string& sni) {
  try {
    auto& tcp_socket = boost::beast::get_lowest_layer(ws_).socket();
    /* Wait for client hello */
    const auto client_hello =
        co_await common::network::WaitForClientTlsHelloAsync(tcp_socket);
    if (!client_hello.has_value()) {
      SPDLOG_ERROR("Empty client hello");
      co_return false;
    }

    const auto client_hello_size = client_hello.value().size();

    /* Send server hello */
    std::string answered_domain;
    const auto handshake_answer =
        co_await handshake_cache_manager_->GetHandshake(sni,
            client_hello.value().data(), client_hello_size,
            std::chrono::seconds(2), std::chrono::seconds(3),
            &answered_domain);
    if (!handshake_answer) {
      co_return false;
    }

    // The cached ServerHello was fetched with our own ClientHello, so its
    // legacy_session_id echo belongs to that fetch, not to this client. Every
    // real TLS server echoes the client's value; leaving a stale one makes the
    // pair trivially distinguishable by comparing two plaintext fields.
    std::vector<std::uint8_t> answer = *handshake_answer;
    const auto client_session_id = common::network::GetTlsSessionId(
        client_hello.value().data(), client_hello_size);
    if (!common::network::SetTlsSessionId(answer, client_session_id)) {
      SPDLOG_WARN("Could not restamp session id for {} (client_id={})", sni,
          client_id_);
    }
    constexpr std::size_t kTlsRandomLen = 32;
    common::network::SetTlsServerRandom(answer, RandomBytes(kTlsRandomLen));
    common::network::SetTlsServerKeyShare(answer, RandomBytes(kTlsRandomLen));

    const std::size_t handshake_answer_size =
        co_await boost::asio::async_write(
            tcp_socket, boost::asio::buffer(answer),
            boost::asio::use_awaitable);

    /* Wait for ChangeCipherSpec */
    const bool change_cipher_spec_size =
        co_await common::network::WaitForClientChangeCipherSpec(tcp_socket);
    if (!change_cipher_spec_size) {
      SPDLOG_ERROR("Failed to receive Client ChangeCipherSpec");
      co_return false;
    }

    SPDLOG_INFO(
        "Reality mode2 completed, ready for real handshake (client_id={}) "
        "request_size = {} response_size: {} decoy={}",
        client_id_, client_hello_size, handshake_answer_size,
        answered_domain);
    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("HandleRealityMode2 exception (client_id={}): {}", client_id_,
        e.what());
  }
  co_return false;
}

boost::asio::awaitable<bool> Session::HandleProxy(
    const std::string& sni, int port) {
  auto& tcp_socket = boost::beast::get_lowest_layer(ws_).socket();
  boost::asio::ip::tcp::socket target_socket(
      co_await boost::asio::this_coro::executor);

  constexpr int kTimeout = 10;
  boost::beast::get_lowest_layer(ws_).expires_after(
      std::chrono::seconds(kTimeout));

  bool status = false;
  try {
    const std::string port_str = std::to_string(port);

    // Neither AsyncResolve nor async_connect carries a deadline of its own,
    // and the beast timer on ws_ does not cover target_socket. Without this
    // race a decoy host that silently drops packets pins the session open
    // indefinitely, and a handful of such sessions stops the server from
    // accepting new connections.
    bool setup_completed = false;
    auto setup = [&]() -> boost::asio::awaitable<void> {
      const auto resolve_result =
          co_await fptn::common::network::AsyncResolve(sni, port_str);
      if (!resolve_result.success()) {
        SPDLOG_ERROR("Proxy DNS resolution failed for {}:{}: {}", sni, port_str,
            resolve_result.error.message());
        co_return;
      }
      boost::system::error_code connect_ec;
      co_await boost::asio::async_connect(target_socket, resolve_result.results,
          boost::asio::redirect_error(boost::asio::use_awaitable, connect_ec));
      if (connect_ec) {
        SPDLOG_ERROR("Proxy connect failed for {}:{}: {}", sni, port_str,
            connect_ec.message());
        co_return;
      }
      setup_completed = true;
    };

    {
      boost::asio::steady_timer setup_deadline(
          co_await boost::asio::this_coro::executor,
          std::chrono::seconds(kTimeout));
      using boost::asio::experimental::awaitable_operators::operator||;
      const auto race = co_await(  // NOLINT(whitespace/parens)
          setup() || setup_deadline.async_wait(boost::asio::use_awaitable));
      if (race.index() == 1) {
        SPDLOG_WARN("Proxy setup to {}:{} timed out after {}s (client_id={})",
            sni, port_str, kTimeout, client_id_);
      }
    }
    if (!setup_completed) {
      co_return false;
    }

    const auto ep = target_socket.remote_endpoint();
    SPDLOG_INFO("Proxying {}:{} <-> {}:{} (client_id={})",
        ep.address().to_string(), ep.port(), sni, port_str, client_id_);

    auto self = shared_from_this();
    auto forward = [self](
                       auto& from, auto& to) -> boost::asio::awaitable<void> {
      try {
        boost::system::error_code ec;
        std::array<std::uint8_t, 16384> buf{};
        using boost::asio::experimental::awaitable_operators::operator||;
        while (self->running_) {
          boost::asio::steady_timer idle(
              co_await boost::asio::this_coro::executor,
              std::chrono::seconds(60));
          const auto r = co_await(from.async_read_some(boost::asio::buffer(buf),
                                      boost::asio::redirect_error(
                                          boost::asio::use_awaitable, ec)) ||
                                  idle.async_wait(boost::asio::use_awaitable));
          if (r.index() == 1) {
            break;
          }
          const auto n = std::get<0>(r);
          if (ec || n == 0) {
            break;
          }
          co_await boost::asio::async_write(to,
              boost::asio::buffer(buf.data(), n),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
          if (ec) {
            break;
          }
        }
        from.close();
      } catch (const boost::system::system_error& e) {
        SPDLOG_ERROR("Coroutine system error: {} [{}] (client_id={})", e.what(),
            e.code().message(), self->client_id_);
      }
      co_return;
    };

    // Set socket timeout
    SetSocketTimeouts(tcp_socket, kTimeout);
    SetSocketTimeouts(target_socket, kTimeout);

    auto [client_to_server_result, server_to_client_result, completion_status] =
        co_await boost::asio::experimental::make_parallel_group(
            boost::asio::co_spawn(co_await boost::asio::this_coro::executor,
                forward(tcp_socket, target_socket), boost::asio::deferred),
            boost::asio::co_spawn(co_await boost::asio::this_coro::executor,
                forward(target_socket, tcp_socket), boost::asio::deferred))
            .async_wait(boost::asio::experimental::wait_for_all(),
                boost::asio::use_awaitable);
    (void)client_to_server_result;
    (void)server_to_client_result;
    (void)completion_status;
    status = true;
  } catch (const boost::system::system_error& e) {
    SPDLOG_ERROR("Proxy system error: {} [{}] (client_id={})", e.what(),
        e.code().message(), client_id_);
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Proxy error (client_id={}): {} ", e.what(), client_id_);
  }

  // close socket
  try {
    tcp_socket.close();
  } catch (const boost::system::system_error& e) {
    SPDLOG_ERROR(
        "Failed to close the socket after proxy completion (client_id={}): "
        "{} "
        "[{}]",
        client_id_, e.what(), e.code().message());
  }
  // close target socket
  boost::system::error_code ec;
  target_socket.close(ec);

  SPDLOG_INFO("Close proxy (client_id={})", client_id_);

  co_return status;
}

boost::asio::awaitable<void> Session::ProxyWithFallback(
    const std::string& sni) {
  if (co_await HandleProxy(sni, 443)) {
    co_return;
  }
  for (const auto& domain : allowed_sni_list_) {
    if (domain == sni || handshake_cache_manager_->IsDead(domain) ||
        !boost::beast::get_lowest_layer(ws_).socket().is_open()) {
      continue;
    }
    SPDLOG_WARN("Proxy to {} failed, falling back to {} (client_id={})", sni,
        domain, client_id_);
    if (co_await HandleProxy(domain, 443)) {
      co_return;
    }
  }
  co_return;
}

boost::asio::awaitable<void> Session::RunReader() {
  boost::system::error_code ec;
  boost::beast::flat_buffer buffer;
  buffer.reserve(4 * 1024 * 1024);
  auto token = boost::asio::redirect_error(boost::asio::use_awaitable, ec);
  try {
    while (running_ && !ec) {
      co_await ws_.async_read(buffer, token);
      if (buffer.size() > 0 && running_) {
        if (support_batch_sending_) {
          // BATCH MODE
          auto batch_packets =
              use_yaff_serializer_
                  ? fptn::protocol::yaff::DeserializeBatchIPPacket(buffer)
                  : fptn::protocol::protobuf::DeserializeBatchIPPacket(buffer);
          for (auto& raw_ip : batch_packets) {
            auto packet = fptn::common::network::IPPacket::Parse(
                std::move(raw_ip), client_id_);
            if (packet != nullptr) {
              ws_new_ippacket_callback_(std::move(packet));
            }
          }
        } else {
          // DEPRECATED
          // SINGLE PACKET MODE
          auto raw_ip = fptn::protocol::protobuf::DeserializeIPPacket(buffer);
          if (raw_ip.has_value() && running_) {
            auto packet = fptn::common::network::IPPacket::Parse(
                std::move(raw_ip.value()), client_id_);
            if (packet != nullptr) {
              ws_new_ippacket_callback_(std::move(packet));
            }
          }
        }
        buffer.consume(buffer.size());
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("RunReader exception: {}", e.what());
  }
  Close();
  co_return;
}

boost::asio::awaitable<void> Session::WriteFrame(BatchIPPacketPtr frame) {
  if (!support_batch_sending_) {
    // DEPRECATED
    // The old protocol carries one packet per message.
    for (auto& packet : frame) {
      auto msg = fptn::protocol::protobuf::SerializeIPPacket(std::move(packet));
      if (msg.has_value()) {
        co_await ws_.async_write(
            boost::asio::buffer(msg.value()), boost::asio::use_awaitable);
      }
    }
    co_return;
  }

  auto data =
      use_yaff_serializer_
          ? fptn::protocol::yaff::SerializeBatchIPPacket(std::move(frame))
          : fptn::protocol::protobuf::SerializeBatchIPPacket(std::move(frame));
  if (data.has_value()) {
    co_await ws_.async_write(
        boost::asio::buffer(data.value()), boost::asio::use_awaitable);
  }
}

boost::asio::awaitable<void> Session::RunSender() {
  constexpr std::size_t kMaxBatchSize = 128;
  auto token = boost::asio::bind_cancellation_slot(
      cancel_signal_.slot(), boost::asio::as_tuple(boost::asio::use_awaitable));
  try {
    BatchIPPacketPtr pending;
    while (running_) {
      BatchIPPacketPtr packets = std::move(pending);
      pending.clear();

      if (packets.empty()) {
        auto [ec, batch] = co_await write_channel_.async_receive(token);
        if (ec) {
          break;
        }
        packets = std::move(batch);
      }

      const auto merge = [&packets](auto ec2, auto more) {
        if (!ec2) {
          packets.insert(packets.end(), std::make_move_iterator(more.begin()),
              std::make_move_iterator(more.end()));
        }
      };
      while (
          packets.size() < kMaxBatchSize && write_channel_.try_receive(merge)) {
      }

      if (packets.size() > kMaxBatchSize) {
        const auto tail =
            packets.begin() + static_cast<std::ptrdiff_t>(kMaxBatchSize);
        pending.assign(std::make_move_iterator(tail),
            std::make_move_iterator(packets.end()));
        packets.erase(tail, packets.end());
      }

      if (!packets.empty()) {
        co_await WriteFrame(std::move(packets));
      }
    }
  } catch (const boost::system::system_error& err) {
    if (err.code() != boost::asio::error::operation_aborted &&
        err.code() != boost::beast::websocket::error::closed) {
      SPDLOG_ERROR(
          "RunSender error (client_id={}): {}", client_id_, err.what());
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR(
        "RunSender exception (client_id={}): {}", client_id_, e.what());
  }

  Close();
  co_return;
}

boost::asio::awaitable<bool> Session::ProcessRequest() {
  bool status = false;

  try {
    boost::system::error_code ec;
    boost::beast::flat_buffer buffer;
    boost::beast::http::request<boost::beast::http::string_body> request;

    co_await boost::beast::http::async_read(ws_.next_layer(), buffer, request,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));

    if (boost::beast::websocket::is_upgrade(request)) {
      if (request.target() == common::api::kApiWebSocketUrlOld) {
        // deprecated old protocol (single connection, its own session)
        status = co_await HandleWebSocket(request);
      } else if (request.target() == common::api::kApiWebSocketUrl) {
        status = co_await HandleWebSocket2(request);
      }
    } else {
      status = co_await HandleHttp(request);
    }
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Session::handshake failed (client_id={}): {} [{}]",
        client_id_, err.what(), err.code().message());
  }
  co_return status;
}

boost::asio::awaitable<bool> Session::HandleHttp(
    const boost::beast::http::request<boost::beast::http::string_body>&
        request) {
  const std::string url = request.target();
  const std::string method = request.method_string();

  boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));

  if (method.empty() && url.empty()) {
    SPDLOG_WARN(
        "HTTP request has empty method or URL (client_id={}): method='{}', "
        "url='{}'",
        client_id_, method, url);
    co_return false;
  }

  const auto t0 = std::chrono::steady_clock::now();

  const auto server_info = fmt::format("fptn/{}", FPTN_VERSION);
  const auto http_date = fptn::time::TimeProvider::Instance()->Rfc7231Date();

  boost::beast::http::response<boost::beast::http::string_body> resp;
  resp.set(boost::beast::http::field::server, server_info);
  resp.set(boost::beast::http::field::content_type,
      "application/json; charset=utf-8");
  resp.set(boost::beast::http::field::cache_control,
      "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0");
  resp.set(boost::beast::http::field::pragma, "no-cache");
  resp.set(boost::beast::http::field::expires, "0");
  resp.set(boost::beast::http::field::date, http_date);

  const ApiHandle handler = GetApiHandle(api_handles_, url, method);
  int http_status = 404;
  if (handler) {
    http_status = co_await handler(request, resp);
    resp.result(http_status);
  } else {
    resp.result(boost::beast::http::status::not_found);
    resp.body() = "404 Not Found";
  }

  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - t0)
                      .count();
  const std::string log_url =
      (url.find(common::api::kApiMetricsUrl) != std::string::npos)  // NOLINT
          ? std::string(common::api::kApiMetricsUrl) + "/<hidden>"
          : std::string(url);
  SPDLOG_INFO("HTTP {} {} -> {} ({}ms) (client_id={})", method, log_url,
      http_status, ms, client_id_);

  resp.prepare_payload();

  auto res_ptr = std::make_shared<
      boost::beast::http::response<boost::beast::http::string_body>>(
      std::move(resp));
  try {
    co_await boost::beast::http::async_write(
        ws_.next_layer(), *res_ptr, boost::asio::use_awaitable);
  } catch (const boost::beast::system_error& e) {
    SPDLOG_ERROR("Session::HandleHttp write error (client_id={}): {}",
        client_id_, e.what());
  } catch (...) {
    SPDLOG_ERROR(
        "Session::HandleHttp write unknown error (client_id={})", client_id_);
  }
  co_return false;
}

// deprecated (kept for backward compatibility with old-protocol clients)
boost::asio::awaitable<bool> Session::HandleWebSocket(
    const boost::beast::http::request<boost::beast::http::string_body>&
        request) {
  boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::hours(12));

  if (request.contains("Authorization") && request.contains("ClientIP")) {
    std::string token = request["Authorization"];
    boost::replace_first(token, "Bearer ", "");

    boost::system::error_code ec;
    const std::string client_ip_str = boost::beast::get_lowest_layer(ws_)
                                          .socket()
                                          .remote_endpoint(ec)
                                          .address()
                                          .to_string();
    if (ec) {
      SPDLOG_ERROR("Failed to get remote endpoint: {}", ec.message());
      co_return false;
    }

    try {
      const std::string client_vpn_ipv4_str = request["ClientIP"];
      const std::string client_vpn_ipv6_str =
          (request.contains("ClientIPv6") ? request["ClientIPv6"]
                                          : FPTN_CLIENT_DEFAULT_ADDRESS_IP6);

      fptn::nat::ConnectParams params;
      params.client_id = client_id_;
      params.request.url = request.target();
      params.request.jwt_auth_token = token;
      // Old protocol carries no SessionID: each connection is its own unique
      // logical session (1:1), never pooled.
      params.request.session_id = common::utils::GenerateRandomString(64);
      params.request.connection_weight = 1;
      params.request.client_ipv4 = common::network::IPv4Address(client_ip_str);
      params.request.client_tun_vpn_ipv4 =
          common::network::IPv4Address(client_vpn_ipv4_str);
      params.request.client_tun_vpn_ipv6 =
          common::network::IPv6Address(client_vpn_ipv6_str);

      const auto nat_session = ws_open_callback_(params, shared_from_this());
      ws_session_was_opened_ = nat_session != nullptr;
      // Old protocol: single-packet protobuf and server-side NAT (checksum
      // recalculation stays enabled, i.e. DisableChecksumCalculation is NOT
      // called).
      support_batch_sending_ = false;
      if (ws_session_was_opened_) {
        co_await ws_.async_accept(request,
            boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        co_return !ec;
      }
    } catch (const std::exception& ex) {
      SPDLOG_ERROR(
          "Session::Open (client_id={}): Exception caught while creating IP "
          "addresses or running callback: {}",
          client_id_, ex.what());
    } catch (...) {
      SPDLOG_ERROR(
          "Session::Open (client_id={}): Unknown fatal error caught while "
          "creating IP addresses or running callback",
          client_id_);
    }
  }
  co_return false;
}

boost::asio::awaitable<bool> Session::HandleWebSocket2(
    const boost::beast::http::request<boost::beast::http::string_body>&
        request) {
  boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::hours(12));

  if (request.contains("Authorization")) {
    std::string token = request["Authorization"];
    boost::replace_first(token, "Bearer ", "");

    boost::system::error_code ec;
    const std::string client_ip_str = boost::beast::get_lowest_layer(ws_)
                                          .socket()
                                          .remote_endpoint(ec)
                                          .address()
                                          .to_string();
    if (ec) {
      SPDLOG_ERROR("Failed to get remote endpoint: {}", ec.message());
      co_return false;
    }
    const common::network::IPv4Address client_ip(client_ip_str);
    try {
      fptn::nat::ConnectParams params;
      params.client_id = client_id_;
      params.request.url = request.target();
      params.request.jwt_auth_token = token;
      // No SessionID -> a fresh unique id, so a lone connection behaves exactly
      // like today (its own logical session). Pooled clients send a shared id.
      params.request.session_id = ParseRequestStr(
          request, "SessionID", common::utils::GenerateRandomString(64));
      params.request.connection_weight =
          ParseRequestUint(request, "ConnectionWeight", 1);
      params.request.client_ipv4 = client_ip;
      if (request.contains("ClientIP")) {
        params.request.client_tun_vpn_ipv4 =
            common::network::IPv4Address(std::string(request["ClientIP"]));
      }
      if (request.contains("ClientIPv6")) {
        params.request.client_tun_vpn_ipv6 =
            common::network::IPv6Address(std::string(request["ClientIPv6"]));
      }
      // Durations (ms) that drive the connection's SENDING -> RECEIVING ->
      // CLOSING lifecycle; absent (0) means a plain always-receiving link.
      params.request.send_duration_ms =
          ParseRequestUint(request, "X-Send-Duration", 0);
      params.request.ttl_ms = ParseRequestUint(request, "X-Ttl", 0);

      const auto nat_session = ws_open_callback_(params, shared_from_this());

      if (nat_session == nullptr) {
        co_return false;
      }

      nat_session->DisableChecksumCalculation(true);
      ws_session_was_opened_ = true;
      support_batch_sending_ = true;
      use_yaff_serializer_ =
          request.contains("X-Serializer") && request["X-Serializer"] == "yaff";
      SPDLOG_INFO("Session serializer: {} (client_id={})",
          use_yaff_serializer_ ? "yaff" : "protobuf", client_id_);

      co_await ws_.async_accept(
          request, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec) {
        SPDLOG_WARN("Failed to connect to client: {}", ec.message());
        co_return false;
      }
      SPDLOG_INFO("Successfully connected to {}", client_ip.ToString());

      // send IP address to client
      const auto message =
          use_yaff_serializer_
              ? protocol::yaff::SerializeIPAssignmentMessage(
                    nat_session->FakeClientIPv4().ToString(),
                    nat_session->FakeClientIPv6().ToString())
              : protocol::protobuf::SerializeIPAssignmentMessage(
                    nat_session->FakeClientIPv4().ToString(),
                    nat_session->FakeClientIPv6().ToString());

      if (message.has_value()) {
        co_await ws_.async_write(
            boost::asio::buffer(std::move(message.value())),
            boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec) {
          SPDLOG_ERROR("Failed to send IP assignment: {}", ec.message());
          co_return false;
        }
        co_return true;
      }
    } catch (const std::exception& ex) {
      SPDLOG_ERROR(
          "Session::Open (client_id={}): Exception caught while creating IP "
          "addresses or running callback: {}",
          client_id_, ex.what());
    } catch (...) {
      SPDLOG_ERROR(
          "Session::Open (client_id={}): Unknown fatal error caught while "
          "creating IP addresses or running callback",
          client_id_);
    }
  }
  co_return false;
}

void Session::Close() {
  if (!running_.exchange(false)) {
    return;
  }

  boost::asio::dispatch(
      strand_, [self = shared_from_this()]() { self->DoClose(); });
}

void Session::DoClose() {
  try {
    cancel_signal_.emit(boost::asio::cancellation_type::all);
    write_channel_.close();
  } catch (const std::exception& err) {
    SPDLOG_WARN(
        "Failed to cancel session or close write_channel: {}", err.what());
  } catch (...) {
    SPDLOG_WARN(
        "Session::Close unknown fatal error (client_id={})", client_id_);
  }

  // Close TCP socket first
  try {
    auto& tcp_layer = boost::beast::get_lowest_layer(ws_);
    if (tcp_layer.socket().is_open()) {
      boost::system::error_code ec;
      tcp_layer.expires_never();

      tcp_layer.socket().shutdown(
          boost::asio::ip::tcp::socket::shutdown_both, ec);
      tcp_layer.socket().close(ec);
    }
  } catch (const std::exception& err) {
    SPDLOG_WARN("Session::Close TCP socket error (client_id={}): {}",
        client_id_, err.what());
  } catch (...) {
    SPDLOG_WARN(
        "Session::Close TCP socket unknown error (client_id={})", client_id_);
  }

  // Close SSL
  try {
    auto& ssl_layer = ws_.next_layer();
    if (ssl_layer.native_handle()) {
      ::SSL_set_quiet_shutdown(ssl_layer.native_handle(), 1);
    }
  } catch (const std::exception& err) {
    SPDLOG_ERROR("Session::Close SSL shutdown exception (client_id={}): {}",
        client_id_, err.what());
  } catch (...) {
    SPDLOG_ERROR(
        "Session::Close SSL shutdown unknown error (client_id={})", client_id_);
  }

  if (ws_close_callback_ && ws_session_was_opened_) {
    try {
      ws_close_callback_(client_id_);
    } catch (const std::exception& e) {
      SPDLOG_WARN("WebSocket close callback threw exception (client_id={}): {}",
          client_id_, e.what());
    } catch (...) {
      SPDLOG_WARN(
          "WebSocket close callback threw unknown exception (client_id={})",
          client_id_);
    }
  }
}

void Session::SendBatch(common::network::BatchIPPacketPtr pkts) {
  if (!running_.load(std::memory_order_acquire) || pkts.empty()) {
    return;
  }

  boost::system::error_code ec;
  const bool status = write_channel_.try_send(ec, std::move(pkts));
  if (!status && !full_queue_) {
    full_queue_ = true;
    SPDLOG_WARN("Session::send queue is full (client_id={})", client_id_);
  }
}

boost::asio::awaitable<IObfuscator> Session::DetectObfuscator() {
  try {
    boost::system::error_code ec;
    auto& tcp_socket = boost::beast::get_lowest_layer(ws_).socket();

    // Peek data without consuming it from the socket buffer
    // This allows inspection without affecting subsequent reads
    std::array<std::uint8_t, 16384> buffer{};
    const std::size_t bytes_read = co_await PeekWithTimeout(
        tcp_socket, boost::asio::buffer(buffer), std::chrono::seconds(3), ec);

    if (ec || !bytes_read) {
      co_return std::nullopt;
    }

    // Detect the appropriate obfuscator based on the peeked data
    auto obfuscator = fptn::protocol::https::obfuscator::DetectObfuscator(
        buffer.data(), bytes_read);
    co_return obfuscator;
  } catch (const boost::system::system_error& e) {
    SPDLOG_ERROR(
        "System error during obfuscator setup [client_id: {}, error: '{}', "
        "code: {}]",
        client_id_, e.what(), e.code().message());
  } catch (const std::exception& e) {
    SPDLOG_ERROR(
        "Exception during obfuscator setup [client_id: {}, error: '{}']",
        client_id_, e.what());
  } catch (...) {
    SPDLOG_ERROR(
        "Unknown error during obfuscator setup [client_id: {}]", client_id_);
  }
  co_return std::nullopt;
}

};  // namespace fptn::web
