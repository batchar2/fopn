/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>

#include "common/data/byte_budget.h"
#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/https/connection_config.h"
#include "fptn-protocol-lib/https/obfuscator/tcp_stream/tcp_stream.h"
#include "fptn-protocol-lib/https/utils/tls/tls.h"
#include "fptn-protocol-lib/protocol/protobuf/protobuf_serializer.h"

namespace fptn::protocol::https {

using fptn::common::network::IPPacketPtr;
using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;

using OnIPAssignedCallback =
std::function<void(const IPv4Address& ipv4, const IPv6Address& ipv6)>;

class WebsocketClient : public std::enable_shared_from_this<WebsocketClient> {
 public:
  explicit WebsocketClient(std::string jwt_access_token,
      ConnectionConfig config,
      boost::asio::io_context& ioc);

  virtual ~WebsocketClient();

  WebsocketClient(const WebsocketClient&) = delete;
  WebsocketClient& operator=(const WebsocketClient&) = delete;
  WebsocketClient(WebsocketClient&&) = delete;
  WebsocketClient& operator=(WebsocketClient&&) = delete;

  void Run();
  bool Stop();
  bool Send(fptn::common::network::IPPacketPtr packet);
  bool IsStarted() const;
  // True once the client has reached a terminal state (connection dropped or
  // failed to establish). Used by strategies driving the shared io_context to
  // know when to stop their event loop and let the manager reconnect.
  bool IsStopped() const;

 protected:
  boost::asio::awaitable<bool> RunInternal();
  boost::asio::awaitable<void> RunReader();
  boost::asio::awaitable<void> RunSender();
  boost::asio::awaitable<bool> Connect();
  boost::asio::awaitable<bool> ReceiveIPAssignment();

  boost::asio::awaitable<bool> PerformFakeHandshake2();

  // Closes the transport. Must run on strand_ (or when nothing drives the
  // io_context any more, e.g. from the destructor).
  void DoStop();

  void StartWatchdog();

  std::vector<std::uint8_t> GenerateHandshakePacket() const;
  fptn::protocol::SerializerPolicy Serializer() const noexcept;

 private:
  const std::size_t kMaxSizeOutQueue_ = 256;

  mutable std::mutex mutex_;
  std::atomic<bool> running_{false};
  std::atomic<bool> was_stopped_{false};
  std::atomic<bool> teardown_done_{false};
  std::atomic<bool> was_inited_{false};
  std::atomic<bool> was_connected_{false};
  std::atomic<bool> ip_assigned_{false};

  boost::asio::io_context& ioc_;
  boost::asio::ssl::context ctx_;
  boost::asio::ip::tcp::resolver resolver_;

  boost::asio::strand<boost::asio::io_context::executor_type> strand_;
  boost::asio::steady_timer watchdog_timer_;

  // TCP -> obfuscator -> SSL -> WebSocket
  using tcp_stream_type = boost::beast::tcp_stream;
  using obfuscator_socket_type = obfuscator::TcpStream<tcp_stream_type>;
  using ssl_stream_type = boost::beast::ssl_stream<obfuscator_socket_type>;
  using websocket_type = boost::beast::websocket::stream<ssl_stream_type>;

  websocket_type ws_;

  boost::asio::experimental::concurrent_channel<void(
      boost::system::error_code, fptn::common::network::IPPacketPtr)>
      write_channel_;
  fptn::common::data::ByteBudget outbound_queue_budget_;

  boost::asio::cancellation_signal cancel_signal_;
  obfuscator::IObfuscatorSPtr obfuscator_;

  const std::string jwt_access_token_;
  const ConnectionConfig config_;

  IPv4Address assigned_ipv4_;
  IPv6Address assigned_ipv6_;
};

using WebsocketClientSPtr = std::shared_ptr<WebsocketClient>;

}  // namespace fptn::protocol::https
