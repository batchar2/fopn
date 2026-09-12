
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
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>

#include "common/data/byte_budget.h"
#include "common/data/channel.h"

#include "fptn-protocol-lib/https/obfuscator/tcp_stream/tcp_stream.h"
#include "web/api/handle.h"
#include "web/handshake/handshake_cache_manager.h"

namespace fptn::web {

using IObfuscator = std::optional<protocol::https::obfuscator::IObfuscatorSPtr>;

class Session : public std::enable_shared_from_this<Session> {
 public:
  explicit Session(bool enable_detect_probing,
      std::vector<std::string> allowed_sni_list,
      std::string server_external_ips,
      boost::asio::ip::tcp::socket&& socket,
      boost::asio::ssl::context& ctx,
      const ApiHandleMap& api_handles,
      HandshakeCacheManagerSPtr handshake_cache_manager,
      WebSocketOpenConnectionCallback ws_open_callback,
      WebSocketNewIPPacketCallback ws_new_ippacket_callback,
      WebSocketCloseConnectionCallback ws_close_callback);
  virtual ~Session();
  void Close();

  void SendBatch(common::network::BatchIPPacketPtr pkts);

  boost::asio::any_io_executor GetExecutor() const noexcept;

  // async
  boost::asio::awaitable<void> Run();

 protected:
  void DoClose();

  boost::asio::awaitable<void> RunReader();
  boost::asio::awaitable<void> RunSender();
  boost::asio::awaitable<void> WriteFrame(
      common::network::BatchIPPacketPtr frame);

 protected:
  struct ProbingResult {
    bool is_probing;
    std::string sni;
    bool should_close;
  };

  boost::asio::awaitable<ProbingResult> DetectProbing(
      const std::uint8_t* client_hello, std::size_t size, std::string sni);

 protected:
  boost::asio::awaitable<bool> IsSniSelfProxyAttempt(
      const std::string& sni) const;

  struct RealityResult {
    bool is_reality_mode;  // DEPRICATED
    bool is_reality_mode2;
    std::string sni;
    bool should_close;
  };

  RealityResult IsRealityHandshake(const std::uint8_t* client_hello,
      std::size_t size,
      std::string sni) const;

  // DEPRECATED
  boost::asio::awaitable<bool> PerformFakeHandshake(const std::string& sni);

  boost::asio::awaitable<bool> PerformFakeHandshake2(const std::string& sni);

  boost::asio::awaitable<bool> HandleProxy(const std::string& sni, int port);

  boost::asio::awaitable<void> ProxyWithFallback(const std::string& sni);

  std::string ProxyFallbackDomain() const;

  boost::asio::awaitable<IObfuscator> DetectObfuscator();

 protected:
  boost::asio::awaitable<bool> ProcessRequest();
  boost::asio::awaitable<bool> HandleHttp(
      const boost::beast::http::request<boost::beast::http::string_body>&
          request);

  // deprecated (kept for backward compatibility with old-protocol clients):
  // every such connection gets its own unique session id (a standalone 1:1
  // logical client), unlike the new pooled path.
  boost::asio::awaitable<bool> HandleWebSocket(
      const boost::beast::http::request<boost::beast::http::string_body>&
          request);

  boost::asio::awaitable<bool> HandleWebSocket2(
      const boost::beast::http::request<boost::beast::http::string_body>&
          request);

 private:
  static constexpr std::size_t kMaxWriteQueueBatches = 32;
  static constexpr std::size_t kMaxWriteQueueBytes = 4U * 1024U * 1024U;
  static constexpr std::size_t kInitialReadBufferBytes = 64U * 1024U;
  static constexpr std::size_t kMaxReadMessageBytes = 256U * 1024U;

  fptn::ClientID client_id_ = MAX_CLIENT_ID;

  const bool enable_detect_probing_;
  const std::vector<std::string> allowed_sni_list_;

  const std::string server_external_ips_;

  // TCP -> obfuscator -> SSL -> WebSocket
  using tcp_stream_type = boost::beast::tcp_stream;
  using obfuscator_socket_type =
      fptn::protocol::https::obfuscator::TcpStream<tcp_stream_type>;
  using ssl_stream_type = boost::beast::ssl_stream<obfuscator_socket_type>;
  using websocket_type = boost::beast::websocket::stream<ssl_stream_type>;

  websocket_type ws_;

  boost::asio::any_io_executor strand_;
  boost::asio::experimental::concurrent_channel<void(
      boost::system::error_code, fptn::common::network::BatchIPPacketPtr)>
      write_channel_;
  fptn::common::data::ByteBudget write_queue_budget_{kMaxWriteQueueBytes};

  const ApiHandleMap& api_handles_;

  HandshakeCacheManagerSPtr handshake_cache_manager_;

  const WebSocketOpenConnectionCallback ws_open_callback_;
  const WebSocketNewIPPacketCallback ws_new_ippacket_callback_;
  const WebSocketCloseConnectionCallback ws_close_callback_;

  std::atomic<bool> running_;
  std::atomic<bool> init_completed_;
  std::atomic<bool> ws_session_was_opened_;
  std::atomic<bool> full_queue_;

  bool support_batch_sending_;
  bool use_yaff_serializer_;

  boost::asio::cancellation_signal cancel_signal_;
};

using SessionSPtr = std::shared_ptr<Session>;
}  // namespace fptn::web
