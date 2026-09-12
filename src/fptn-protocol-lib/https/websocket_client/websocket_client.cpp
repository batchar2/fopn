/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/websocket_client/websocket_client.h"

#include <https/utils/change_cipher_spec.h>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <camouflage/tls/builder.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/api/handle.h"
#include "common/network/utils.h"  // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/api_client/api_client.h"
#include "fptn-protocol-lib/https/obfuscator/methods/tls2/tls_obfuscator2.h"
#include "fptn-protocol-lib/protocol/yaff/yaff_serializer.h"

#ifdef __APPLE__
#include <TargetConditionals.h>
#include <netinet/tcp.h>
#elif defined(__linux__) && !defined(__ANDROID__)
#include <netinet/tcp.h>
#endif

#ifdef _WIN32
#include <mstcpip.h>  // NOLINT(build/include_order)
#endif

namespace fptn::protocol::https {

fptn::protocol::SerializerPolicy WebsocketClient::Serializer() const noexcept {
  return fptn::protocol::ResolveSerializerPolicy(
      config_.common.serializer_policy);
}

WebsocketClient::WebsocketClient(std::string jwt_access_token,
    ConnectionConfig config,
    boost::asio::io_context& ioc)
    : ioc_(ioc),
      ctx_(https::utils::CreateNewSslCtx()),
      resolver_(boost::asio::make_strand(ioc_)),
      strand_(boost::asio::make_strand(ioc_)),
      watchdog_timer_(strand_),
      ws_(ssl_stream_type(
          obfuscator_socket_type(boost::asio::make_strand(ioc_), nullptr),
          ctx_)),
      write_channel_(strand_, kMaxSizeOutQueue_),
      outbound_queue_budget_(config.common.max_outbound_queue_bytes),
      jwt_access_token_(std::move(jwt_access_token)),
      config_(std::move(config)) {
  auto* ssl = ws_.next_layer().native_handle();
  https::utils::SetHandshakeSni(ssl, config_.common.sni);
  https::utils::SetHandshakeSessionID(ssl);

  // Set SSL buffer sizes
  SSL_set_mode(ssl, SSL_MODE_RELEASE_BUFFERS);

  if (config_.common.censorship_strategy ==
      CensorshipStrategy::kTlsObfuscator) {
    obfuscator_ =
        std::make_shared<fptn::protocol::https::obfuscator::TlsObfuscator2>();
    ws_.next_layer().next_layer().set_obfuscator(obfuscator_);
  }

  https::utils::AttachCertificateVerificationCallback(
      ssl, [this](const std::string& md5_fingerprint) mutable {
        if (config_.common.md5_fingerprint.empty()) {
          return true;
        }
        if (md5_fingerprint == config_.common.md5_fingerprint) {
          return true;
        }
        SPDLOG_ERROR("Certificate MD5 mismatch. Expected: {}, got: {}.",
            config_.common.md5_fingerprint, md5_fingerprint);
        return false;
      });

  ws_.text(false);
  ws_.binary(true);
  ws_.auto_fragment(false);
  ws_.read_message_max(256 * 1024);
  ws_.set_option(boost::beast::websocket::stream_base::timeout::suggested(
      boost::beast::role_type::client));
}

WebsocketClient::~WebsocketClient() {
  try {
    running_ = false;
    was_connected_ = false;
    was_stopped_ = true;
    DoStop();  // no owners left, so nothing can run on strand_ concurrently
  } catch (...) {
    SPDLOG_WARN("Unknown error in ~WebsocketClient");
  }
  // NOTE: io_context is owned externally (by the connection strategy) and
  // shared across pooled clients, so it must NOT be stopped here.
  SPDLOG_INFO("WebsocketClient removed");
}

void WebsocketClient::Run() {
  if (running_.exchange(true)) {
    SPDLOG_WARN("WebsocketClient is already running");
    return;
  }

  SPDLOG_INFO("Connecting to {}:{} [strategy={}]",
      config_.common.server_ip.ToString(), config_.common.server_port,
      ToString(config_.common.censorship_strategy));

  // The io_context is owned and driven by the connection strategy, so we only
  // schedule the connection coroutine here and return immediately.
  auto self = weak_from_this();
  boost::asio::co_spawn(
      ioc_,
      [self]() -> boost::asio::awaitable<void> {
        if (auto shared_self = self.lock()) {
          const bool status = co_await shared_self->RunInternal();
          if (!status) {
            shared_self->Stop();
          }
        }
      },
      boost::asio::detached);
}

bool WebsocketClient::Stop() {
  if (!running_) {
    return false;
  }

  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    // cppcheck-suppress identicalConditionAfterEarlyExit
    if (!running_) {  // Double-check after acquiring lock
      return false;
    }

    SPDLOG_INFO("Marked client as stopped and disconnected");

    running_ = false;
    was_connected_ = false;
    was_stopped_ = true;
  }

  // The socket, the SSL layer and the cancellation signal belong to strand_:
  // tearing them down from the caller's thread races with the reader and the
  // sender coroutines. When nothing drives the io_context any more the posted
  // teardown is dropped and the destructor performs it instead.
  if (strand_.running_in_this_thread()) {
    DoStop();
  } else {
    boost::asio::dispatch(
        strand_, [self = shared_from_this()]() { self->DoStop(); });
  }

  return true;
}

void WebsocketClient::DoStop() {
  if (teardown_done_.exchange(true)) {
    return;
  }

  boost::system::error_code ec;

  try {
    watchdog_timer_.cancel();
  } catch (const boost::system::system_error&) {
    SPDLOG_WARN("Cancellation timer error");
  } catch (...) {
    SPDLOG_ERROR("Unknown exception while stopping timer");
  }

  try {
    SPDLOG_INFO("Emit cancel signal");
    if (was_inited_) {
      cancel_signal_.emit(boost::asio::cancellation_type::all);
    }
  } catch (const std::exception&) {
    SPDLOG_DEBUG("Exception during cancellation");
  } catch (...) {
    SPDLOG_ERROR("Unknown exception during cancellation");
  }

  try {
    SPDLOG_INFO("Closing write_channel");
    if (was_inited_) {
      write_channel_.close();
    }
  } catch (const std::exception&) {
    SPDLOG_DEBUG("Exception closing write channel");
  } catch (...) {
    SPDLOG_ERROR("Unknown exception during closing write channel");
  }

  try {
    SPDLOG_INFO("Closing resolver");
    if (was_inited_) {
      resolver_.cancel();
    }
  } catch (const std::exception&) {
    SPDLOG_DEBUG("Exception cancelling resolver");
  } catch (...) {
    SPDLOG_ERROR("Unknown exception during closing resolver");
  }

  // Close TCP connection
  try {
    if (was_inited_) {
      SPDLOG_INFO("Shutting down TCP socket...");

      auto& tcp = boost::beast::get_lowest_layer(ws_);
      const boost::asio::socket_base::linger linger(true, 0);
      tcp.socket().set_option(linger);

      if (tcp.socket().is_open()) {
        tcp.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != boost::asio::error::not_connected) {
          SPDLOG_WARN("TCP socket shutdown error: {}", ec.message());
        } else {
          SPDLOG_INFO("TCP socket shutdown successfully");
        }

        tcp.socket().close(ec);
        if (ec) {
          SPDLOG_WARN("TCP socket close error: {}", ec.message());
        } else {
          SPDLOG_INFO("TCP socket closed successfully");
        }
      }
    }
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception during TCP shutdown: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception during TCP shutdown");
  }

  // Close SSL
  try {
    if (was_inited_) {
      SPDLOG_INFO("Shutting down SSL layer...");
      auto& ssl = ws_.next_layer();
      if (ssl.native_handle()) {
        // More robust SSL shutdown
        ::SSL_set_quiet_shutdown(ssl.native_handle(), 1);
        ::SSL_shutdown(ssl.native_handle());
      }
      ssl.shutdown(ec);
    }
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception during SSL shutdown: {}", err.what());
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Unexpected exception during SSL shutdown: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception occurred during SSL shutdown");
  }

  if (auto* ssl = ws_.next_layer().native_handle()) {
    https::utils::AttachCertificateVerificationCallbackDelete(ssl);
  }

  SPDLOG_INFO("WebSocket client stopped successfully");
}

bool WebsocketClient::Send(fptn::common::network::IPPacketPtr packet) {
  if (!running_ || !was_connected_ || !packet) {
    return false;
  }

  const std::size_t packet_bytes = packet->Size();
  if (!outbound_queue_budget_.TryAcquire(packet_bytes)) {
    SPDLOG_WARN("Client write queue byte budget is exhausted (used={} max={})",
        outbound_queue_budget_.UsedBytes(), outbound_queue_budget_.MaxBytes());
    return false;
  }

  try {
    const bool queued = write_channel_.try_send(
        boost::system::error_code(), std::move(packet));
    if (!queued) {
      outbound_queue_budget_.Release(packet_bytes);
    }
    return queued;
  } catch (...) {
    outbound_queue_budget_.Release(packet_bytes);
    return false;
  }
}

bool WebsocketClient::IsStarted() const { return running_ && was_connected_; }

bool WebsocketClient::IsStopped() const { return was_stopped_; }

boost::asio::awaitable<bool> WebsocketClient::RunInternal() {
  try {
    const bool connected = co_await Connect();
    if (!connected) {
      co_return false;
    }

    const bool ip_assigned = co_await ReceiveIPAssignment();
    if (!ip_assigned) {
      co_return false;
    }

    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::hours(3));

    // Start timer
    StartWatchdog();

    // Start reader and sender
    was_inited_ = true;
    auto self = shared_from_this();
    boost::asio::co_spawn(
        strand_, [self]() { return self->RunReader(); }, boost::asio::detached);
    boost::asio::co_spawn(
        strand_, [self]() { return self->RunSender(); }, boost::asio::detached);

    SPDLOG_INFO("WebSocket connection established successfully");
    SPDLOG_INFO("Using serializer: {}", fptn::protocol::ToString(Serializer()));

    if (config_.common.on_connected_callback) {
      config_.common.on_connected_callback();
    }

    if (config_.common.on_socket_opened_callback) {
      const int fd = static_cast<int>(
          boost::beast::get_lowest_layer(ws_).socket().native_handle());
      config_.common.on_socket_opened_callback(fd);
    }

    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("RunInternal exception: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception while running");
  }
  co_return false;
}

boost::asio::awaitable<bool> WebsocketClient::Connect() {
  try {
    boost::system::error_code ec;

    // DNS resolution
    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(5));
    const auto server_port_str = std::to_string(config_.common.server_port);
    const auto results = co_await resolver_.async_resolve(
        config_.common.server_ip.ToString(), server_port_str,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("Resolve error: {}", ec.message());
      co_return false;
    }

    // TCP connect
    co_await boost::beast::get_lowest_layer(ws_).async_connect(
        results, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("Connect error: {}", ec.message());
      co_return false;
    }

    auto& socket = boost::beast::get_lowest_layer(ws_).socket();
    if (!socket.is_open()) {
      SPDLOG_ERROR("Socket not open after connect");
      co_return false;
    }

    const auto remote_ep = socket.remote_endpoint(ec);
    if (ec) {
      SPDLOG_ERROR("Socket reported connected but remote_endpoint() failed: {}",
          ec.message());
      co_return false;
    }

    SPDLOG_INFO("Successfully connected to {}:{}",
        remote_ep.address().to_string(), remote_ep.port());

    // TCP options
    socket.set_option(boost::asio::ip::tcp::no_delay(true));
    socket.set_option(boost::asio::socket_base::reuse_address(true));

    socket.set_option(boost::asio::socket_base::keep_alive(true));

#if defined(__APPLE__) && TARGET_OS_OSX
    {
      int fd = socket.native_handle();
      int keepidle = 5;
      int keepintvl = 2;
      int keepcnt = 3;
      int rxt_droptime = 10;
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &keepidle, sizeof(keepidle));
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
      setsockopt(fd, IPPROTO_TCP, TCP_RXT_CONNDROPTIME, &rxt_droptime,
          sizeof(rxt_droptime));
    }
#elif defined(__linux__) && !defined(__ANDROID__)
    {
      int fd = socket.native_handle();
      int keepidle = 5;
      int keepintvl = 2;
      int keepcnt = 3;
      int user_timeout = 10000;
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
      setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
      setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout,
          sizeof(user_timeout));
    }
#elif defined(_WIN32)
    {
      SOCKET s = socket.native_handle();
      tcp_keepalive ka = {1, 4000, 1000};
      DWORD bytes = 0;
      WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &bytes,
          nullptr, nullptr);
      DWORD maxrt = 10;
      setsockopt(s, IPPROTO_TCP, TCP_MAXRT,
          reinterpret_cast<const char*>(&maxrt), sizeof(maxrt));
    }
#endif

    // Reality Mode: Enhanced stealth connection protocol
    // First, establishes a genuine TLS handshake as a decoy to bypass deep
    // packet inspection Then resets the connection state and activates
    // obfuscation for the real encrypted tunnel This dual-handshake approach
    // makes traffic analysis significantly more difficult
    if (IsRealityModeWithFakeHandshake(config_.common.censorship_strategy)) {
      const bool status = co_await PerformFakeHandshake2();
      if (!status) {
        co_return false;
      }
      // For Reality Mode we use TLS obfuscator after fake handshake
      // This provides additional encryption layer for the real connection
      ws_.next_layer().next_layer().set_obfuscator(
          std::make_shared<protocol::https::obfuscator::TlsObfuscator2>());
    } else if (obfuscator_ != nullptr) {  // Set obfuscator
      ws_.next_layer().next_layer().set_obfuscator(obfuscator_);
    }

    // SSL handshake
    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(10));

    // timeout
    co_await boost::asio::steady_timer{
        co_await boost::asio::this_coro::executor,
        std::chrono::milliseconds(150)}
        .async_wait(boost::asio::use_awaitable);

    co_await ws_.next_layer().async_handshake(
        boost::asio::ssl::stream_base::client,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));

    if (ec) {
      SPDLOG_ERROR("SSL handshake error: {}", ec.message());
      co_return false;
    }

    // [diag] before detaching, check for leftover obfuscated bytes. If the peer
    // sent post-handshake records (e.g. a TLS 1.3 NewSessionTicket) while its
    // obfuscator was still attached, they get read raw after we detach here and
    // desync the WebSocket -- a likely cause of the intermittent reality drop.
    {
      boost::system::error_code diag_ec;
      const std::size_t raw_available =
          boost::beast::get_lowest_layer(ws_).socket().available(diag_ec);
      const auto diag_obf = ws_.next_layer().next_layer().get_obfuscator();
      SPDLOG_INFO(
          "Detaching obfuscator after TLS handshake: raw_bytes_available={}, "
          "obfuscator_pending={}",
          raw_available, (diag_obf && diag_obf->HasPendingData()));
    }
    // Reset obfuscator after TLS-handshake
    ws_.next_layer().next_layer().set_obfuscator(nullptr);

    // timeout
    co_await boost::asio::steady_timer{
        co_await boost::asio::this_coro::executor,
        std::chrono::milliseconds(150)}
        .async_wait(boost::asio::use_awaitable);

    SPDLOG_INFO("SSL handshake completed");

    // WebSocket connection options
    try {
      boost::beast::websocket::stream_base::timeout timeout_option;
      timeout_option.handshake_timeout = std::chrono::seconds(10);
      timeout_option.idle_timeout = std::chrono::seconds(10);
      timeout_option.keep_alive_pings = true;
      ws_.set_option(timeout_option);
    } catch (const std::exception& e) {
      SPDLOG_ERROR("Failed to set timeout: {}", e.what());
    }
    // WebSocket handshake
    ws_.set_option(boost::beast::websocket::stream_base::decorator(
        [this](boost::beast::websocket::request_type& req) {
          req.set("Authorization", "Bearer " + jwt_access_token_);
          req.set("X-Serializer",
              std::string(fptn::protocol::ToString(Serializer())));
          req.set("Client-Agent",
              fmt::format("FptnClient({}/{})", FPTN_USER_OS,
                  config_.common.client_version));
          // Present only for pooled connections; groups them server-side.
          if (!config_.common.session_id.empty()) {
            req.set("SessionID", config_.common.session_id);
          }
          // Pool scheduling: tells the server this connection's send window and
          // lifetime so it can route downstream to receivers and expire it.
          if (config_.common.send_duration_ms > 0) {
            req.set("X-Send-Duration",
                std::to_string(config_.common.send_duration_ms));
          }
          if (config_.common.ttl_ms > 0) {
            req.set("X-Ttl", std::to_string(config_.common.ttl_ms));
          }
        }));
    // Websocket handshake
    co_await ws_.async_handshake(config_.common.server_ip.ToString(),
        common::api::kApiWebSocketUrl,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("WebSocket handshake error: {}", ec.message());
      co_return false;
    }

    was_connected_ = true;
    // WebSocket options
    try {
      boost::beast::websocket::stream_base::timeout timeout_option;
      timeout_option.handshake_timeout = std::chrono::seconds(10);
      timeout_option.idle_timeout = std::chrono::seconds(15);
      timeout_option.keep_alive_pings = true;
      ws_.set_option(timeout_option);
    } catch (const std::exception& e) {
      SPDLOG_ERROR("Failed to set timeout: {}", e.what());
    }

    // timeout
    co_await boost::asio::steady_timer{
        co_await boost::asio::this_coro::executor,
        std::chrono::milliseconds(10)}
        .async_wait(boost::asio::use_awaitable);

    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Connect exception: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception");
  }
  co_return false;
}

boost::asio::awaitable<bool> WebsocketClient::ReceiveIPAssignment() {
  boost::beast::flat_buffer buffer;
  buffer.reserve(16 * 1024);
  try {
    boost::system::error_code ec;
    co_await ws_.async_read(
        buffer, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec || buffer.size() == 0) {
      SPDLOG_ERROR("Failed to read IP assignment: {}", ec.message());
      co_return false;
    }

    const auto assignment = boost::beast::buffers_to_string(buffer.data());
    const auto ip_pair = Serializer() == fptn::protocol::SerializerPolicy::kYaff
                             ? fptn::protocol::yaff::DeserializeIPAssignmentMessage(
                                   assignment)
                             : fptn::protocol::protobuf::DeserializeIPAssignmentMessage(
                                   assignment);

    if (!ip_pair.has_value()) {
      SPDLOG_ERROR("Failed to parse IP assignment message");
      co_return false;
    }
    const auto& [ipv4_str, ipv6_str] = ip_pair.value();
    if (ipv4_str.empty() || ipv6_str.empty()) {
      SPDLOG_ERROR(
          "Invalid IP assignment: IPv4='{}', IPv6='{}'", ipv4_str, ipv6_str);
      co_return false;
    }

    ip_assigned_ = true;
    assigned_ipv4_ = common::network::IPv4Address(ipv4_str);
    assigned_ipv6_ = common::network::IPv6Address(ipv6_str);

    SPDLOG_INFO("Received IP assignment from server: IPv4={}, IPv6={}",
        ipv4_str, ipv6_str);

    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("ReceiveIPAssignment exception: {}", e.what());
    co_return false;
  }
}

boost::asio::awaitable<void> WebsocketClient::RunReader() {
  boost::beast::flat_buffer buffer;
  buffer.reserve(4 * 1024 * 1024);
  // cppcheck-suppress variableScope
  std::size_t inbound_batches = 0;  // [diag] persists across the read loop
  try {
    boost::system::error_code ec;
    while (running_ && was_connected_ && ws_.is_open()) {
      co_await ws_.async_read(
          buffer, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec) {
        // [diag] always surface why the reader stopped (was DEBUG, and silent
        // on a clean close) so the disconnect reason is not hidden behind the
        // watchdog. closed=true means the peer (likely the server) closed it.
        SPDLOG_WARN(
            "RunReader stopped after {} inbound batches: {} [closed={}]",
            inbound_batches, ec.message(),
            ec == boost::beast::websocket::error::closed);
        break;
      }

      if (buffer.size() == 0) {
        continue;
      }
      ++inbound_batches;  // [diag]

      auto batch_packets = Serializer() == fptn::protocol::SerializerPolicy::kYaff
                               ? fptn::protocol::yaff::DeserializeBatchIPPacket(
                                     buffer)
                               : fptn::protocol::protobuf::DeserializeBatchIPPacket(
                                     buffer);
      if (!batch_packets.empty()) {
        fptn::common::network::BatchIPPacketPtr packets;
        packets.reserve(batch_packets.size());
        for (auto& raw_ip_opt : batch_packets) {
          auto packet =
              fptn::common::network::IPPacket::Parse(std::move(raw_ip_opt));
          if (!running_ || !packet) {
            continue;
          }
          // change IP addresses
          if (packet->IsIPv4()) {
            packet->SetDstIPv4Address(
                config_.common.tun_interface_address_ipv4);
          } else if (packet->IsIPv6()) {
            packet->SetDstIPv6Address(
                config_.common.tun_interface_address_ipv6);
          } else {
            continue;
          }
          packets.push_back(std::move(packet));
        }
        if (!packets.empty() && config_.common.recv_ip_packet_batch_callback) {
          config_.common.recv_ip_packet_batch_callback(std::move(packets));
        }
      }
      buffer.consume(buffer.size());
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("RunReader exception: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("RunReader unknown exception");
  }
  was_connected_ = false;
  co_return;
}

boost::asio::awaitable<void> WebsocketClient::RunSender() {
  constexpr std::size_t kMaxBatchSize = 32;
  auto token = boost::asio::bind_cancellation_slot(
      cancel_signal_.slot(), boost::asio::as_tuple(boost::asio::use_awaitable));
  std::size_t reserved_bytes = 0;
  try {
    while (running_ && was_connected_ && ws_.is_open()) {
      fptn::common::network::BatchIPPacketPtr packets;
      auto [ec, packet] = co_await write_channel_.async_receive(token);
      if (ec) {
        break;
      }
      if (packet) {
        const std::size_t packet_bytes = packet->Size();
        if (packet->IsIPv4()) {
          packet->SetSrcIPv4Address(assigned_ipv4_);
        } else if (packet->IsIPv6()) {
          packet->SetSrcIPv6Address(assigned_ipv6_);
        } else {
          outbound_queue_budget_.Release(packet_bytes);
          continue;
        }

        reserved_bytes += packet_bytes;
        packets.push_back(std::move(packet));
        while (packets.size() < kMaxBatchSize) {
          const bool has_packet = write_channel_.try_receive(
              [&packets, &reserved_bytes, this](
                  const boost::system::error_code& ec2,
                  fptn::common::network::IPPacketPtr p) {
                if (!ec2 && p) {
                  const std::size_t packet_bytes = p->Size();
                  if (p->IsIPv4()) {
                    p->SetSrcIPv4Address(assigned_ipv4_);
                  } else if (p->IsIPv6()) {
                    p->SetSrcIPv6Address(assigned_ipv6_);
                  } else {
                    outbound_queue_budget_.Release(packet_bytes);
                    return;
                  }
                  reserved_bytes += packet_bytes;
                  packets.push_back(std::move(p));
                }
              });
          if (!has_packet) {
            break;
          }
        }
      }
      if (!packets.empty()) {
        auto batch_data = Serializer() == fptn::protocol::SerializerPolicy::kYaff
                              ? fptn::protocol::yaff::SerializeBatchIPPacket(
                                    std::move(packets))
                              : fptn::protocol::protobuf::SerializeBatchIPPacket(
                                    std::move(packets));
        if (batch_data.has_value()) {
          co_await ws_.async_write(boost::asio::buffer(batch_data.value()),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
          if (ec) {
            SPDLOG_ERROR("WebSocket error: {}", ec.message());
          }
        }
        outbound_queue_budget_.Release(reserved_bytes);
        reserved_bytes = 0;
        if (ec) {
          break;
        }
      }
    }
  } catch (const boost::system::system_error& err) {
    if (err.code() != boost::asio::error::operation_aborted) {
      SPDLOG_ERROR("RunSender error: {}", err.what());
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("RunSender exception: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("RunSender unknown exception");
  }
  outbound_queue_budget_.Release(reserved_bytes);
  was_connected_ = false;
  co_return;
}

boost::asio::awaitable<bool> WebsocketClient::PerformFakeHandshake2() {
  try {
    boost::system::error_code ec;
    auto& tcp_layer = boost::beast::get_lowest_layer(ws_);
    auto& tcp_socket = tcp_layer.socket();

    SPDLOG_INFO("Fake TLS handshake started for SNI: {}", config_.common.sni);

    /* Send client hello */
    const auto client_hello = GenerateHandshakePacket();
    if (client_hello.empty()) {
      SPDLOG_WARN(
          "Failed to generate ClientHello for SNI: {}", config_.common.sni);
      co_return false;
    }
    const std::size_t client_hello_bytes_size =
        co_await boost::asio::async_write(tcp_socket,
            boost::asio::buffer(client_hello),
            boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("Failed to send ClientHello to {}: {}", config_.common.sni,
          ec.message());
      co_return false;
    }
    if (client_hello_bytes_size != client_hello.size()) {
      SPDLOG_ERROR("Error ClientHello sent: {} of {} bytes",
          client_hello_bytes_size, client_hello.size());
      co_return false;
    }

    const auto server_hello =
        co_await common::network::WaitForServerTlsHelloAsync(
            tcp_socket, std::chrono::seconds(6));
    if (!server_hello.has_value()) {
      SPDLOG_ERROR("Failed to receive ServerHello from {}", config_.common.sni);
      co_return false;
    }

    /* Send change cipher spec */
    const auto change_cipher_spec =
        fptn::protocol::https::utils::MakeClientChangeCipherSpec();
    const std::size_t change_cipher_spec_size =
        co_await boost::asio::async_write(tcp_socket,
            boost::asio::buffer(change_cipher_spec),
            boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("Failed to send ClientHello to {}: {}", config_.common.sni,
          ec.message());
      co_return false;
    }
    if (change_cipher_spec_size != change_cipher_spec.size()) {
      SPDLOG_ERROR("Failed to send ClientHello to {}: {}",
          change_cipher_spec_size, change_cipher_spec.size());
      co_return false;
    }

    // timeout
    boost::asio::steady_timer timer(co_await boost::asio::this_coro::executor,
        std::chrono::milliseconds(150));
    co_await timer.async_wait(boost::asio::use_awaitable);

    SPDLOG_INFO(
        "Fake TLS handshake completed for {}, received {} bytes from server",
        config_.common.sni, server_hello.value().size());
    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Fake TLS handshake exception for {}: {}", config_.common.sni,
        e.what());
  }
  co_return false;
}

void WebsocketClient::StartWatchdog() {
  if (!running_) return;

  constexpr std::chrono::milliseconds kTimeout(300);

  auto weak_self = weak_from_this();
  watchdog_timer_.expires_after(kTimeout);
  watchdog_timer_.async_wait([weak_self](const boost::system::error_code& ec) {
    auto shared_self = weak_self.lock();
    if (!shared_self) {
      return;
    }

    if (ec == boost::asio::error::operation_aborted) {
      return;
    }

    if (shared_self->running_ && !shared_self->was_connected_) {
      SPDLOG_INFO("Watchdog detected disconnected state");
      shared_self->Stop();
    } else if (shared_self->running_) {
      shared_self->StartWatchdog();
    }
  });
}

std::vector<std::uint8_t> WebsocketClient::GenerateHandshakePacket() const {
  auto builder = camouflage::tls::Builder::Create();
  switch (config_.common.censorship_strategy) {
    /* Chrome */
    case CensorshipStrategy::kSniRealityModeChrome149:
      SPDLOG_INFO("Selected strategy: Chrome 149");
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_149_0_7827_103);
      break;
    case CensorshipStrategy::kSniRealityModeChrome148:
      SPDLOG_INFO("Selected strategy: Chrome 148");
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_148_0_7778_216);
      break;
    case CensorshipStrategy::kSniRealityModeChrome147:
      SPDLOG_INFO("Selected strategy: Chrome 147");
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_147_0_7727_56);
      break;
    case CensorshipStrategy::kSniRealityModeChrome146:
      SPDLOG_INFO("Selected strategy: Chrome 146");
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_146_0_7680_178);
      break;
    case CensorshipStrategy::kSniRealityModeChrome145:
      SPDLOG_INFO("Selected strategy: Chrome 145");
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_145_0_7632_46);
      break;
      /* Firefox */
    case CensorshipStrategy::kSniRealityModeFirefox151:
      SPDLOG_INFO("Selected strategy: Firefox 151");
      builder.Firefox(camouflage::tls::firefox::Version::kV_151_0_3);
      break;
    case CensorshipStrategy::kSniRealityModeFirefox150:
      SPDLOG_INFO("Selected strategy: Firefox 150");
      builder.Firefox(camouflage::tls::firefox::Version::kV_150_0_3);
      break;
    case CensorshipStrategy::kSniRealityModeFirefox149:
      SPDLOG_INFO("Selected strategy: Firefox 149");
      builder.Firefox(camouflage::tls::firefox::Version::kV_149_0);
      break;
    /* Safari */
    case CensorshipStrategy::kSniRealityModeSafari26_5:
      SPDLOG_INFO("Selected strategy: Safari 26.5");
      builder.Safari(camouflage::tls::safari::Version::kV_26_5);
      break;
    case CensorshipStrategy::kSniRealityModeSafari26_4:
      SPDLOG_INFO("Selected strategy: Safari 26.4");
      builder.Safari(camouflage::tls::safari::Version::kV_26_4);
      break;
    /* Yandex */
    case CensorshipStrategy::kSniRealityModeYandex26_4:
      SPDLOG_INFO("Selected strategy: Yandex 26.4");
      builder.YandexBrowser(
          camouflage::tls::yandex_browser::Version::kV_26_4_3_897);
      break;
    case CensorshipStrategy::kSniRealityModeYandex26_3:
      SPDLOG_INFO("Selected strategy: Yandex 26.3");
      builder.YandexBrowser(
          camouflage::tls::yandex_browser::Version::kV_26_3_3_881);
      break;
    case CensorshipStrategy::kSniRealityModeYandex25:
      SPDLOG_INFO("Selected strategy: Yandex 25");
      builder.YandexBrowser(
          camouflage::tls::yandex_browser::Version::kV_25_8_3_828);
      break;
    case CensorshipStrategy::kSniRealityModeYandex24:
      SPDLOG_INFO("Selected strategy: Yandex 24");
      builder.YandexBrowser(
          camouflage::tls::yandex_browser::Version::kV_24_12_0_1772);
      break;
    default:
      SPDLOG_DEBUG(
          "Using fallback handshake generator for SNI: {}", config_.common.sni);
      return utils::GenerateDecoyTlsHandshake(config_.common.sni);
  }

  const auto session_id = utils::GenerateDecoyTlsSessionId2();
  if (!session_id.has_value()) {
    SPDLOG_WARN("Session ID generation failed");
    return utils::GenerateDecoyTlsHandshake(config_.common.sni);
  }

  const auto handshake = builder.SetSNI(config_.common.sni)
                             .SetSessionId(session_id.value())
                             .Generate();
  if (!handshake.has_value()) {
    SPDLOG_WARN("Handshake generation failed for SNI: {}, using fallback",
        config_.common.sni);
    return utils::GenerateDecoyTlsHandshake(config_.common.sni);
  }

  SPDLOG_INFO("Handshake generated: SNI={}, size={} bytes", config_.common.sni,
      handshake->handshake_packet_size);

  return std::vector<std::uint8_t>(handshake->handshake_packet,
      handshake->handshake_packet + handshake->handshake_packet_size);
}

}  // namespace fptn::protocol::https
