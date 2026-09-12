/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include "common/jwt_token/token_manager.h"

#include "web/api/handle.h"
#include "web/handshake/handshake_cache_manager.h"
#include "web/session/session.h"

namespace fptn::web {

class Listener final {
 public:
  explicit Listener(std::uint16_t port,
      bool enable_detect_probing,
      std::vector<std::string> allowed_sni_list,
      boost::asio::io_context& ioc,
      fptn::common::jwt_token::TokenManagerSPtr token_manager,
      HandshakeCacheManagerSPtr handshake_cache_manager,
      std::string server_external_ips,
      WebSocketOpenConnectionCallback ws_open_callback,
      WebSocketNewIPPacketCallback ws_new_ippacket_callback,
      WebSocketCloseConnectionCallback ws_close_callback);

  boost::asio::awaitable<void> Run();
  bool Stop();
  void AddApiHandle(const std::string& url,
      const std::string& method,
      const ApiHandle& handle);

 protected:
  const bool enable_detect_probing_;
  const std::vector<std::string> allowed_sni_list_;

  boost::asio::io_context& ioc_;
  boost::asio::ssl::context ctx_;
  boost::asio::ip::tcp::acceptor acceptor_;

  const fptn::common::jwt_token::TokenManagerSPtr token_manager_;

  HandshakeCacheManagerSPtr handshake_cache_manager_;

  const std::string server_external_ips_;

  const WebSocketOpenConnectionCallback ws_open_callback_;
  const WebSocketNewIPPacketCallback ws_new_ippacket_callback_;
  const WebSocketCloseConnectionCallback ws_close_callback_;

  boost::asio::ip::tcp::endpoint endpoint_;
  std::atomic<bool> running_;

  ApiHandleMap api_handles_;
};

using ListenerSPtr = std::shared_ptr<Listener>;
}  // namespace fptn::web
