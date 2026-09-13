/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "web/listener/listener.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

using fptn::web::Listener;

Listener::Listener(std::uint16_t port,
    bool enable_detect_probing,
    std::vector<std::string> allowed_sni_list,
    boost::asio::io_context& ioc,
    fptn::common::jwt_token::TokenManagerSPtr token_manager,
    HandshakeCacheManagerSPtr handshake_cache_manager,
    std::string server_external_ips,
    WebSocketOpenConnectionCallback ws_open_callback,
    WebSocketNewIPPacketCallback ws_new_ippacket_callback,
    WebSocketCloseConnectionCallback ws_close_callback)
    : enable_detect_probing_(enable_detect_probing),
      allowed_sni_list_(std::move(allowed_sni_list)),
      ioc_(ioc),
      ctx_(boost::asio::ssl::context::tlsv13_server),
      acceptor_(ioc_),
      token_manager_(std::move(token_manager)),
      handshake_cache_manager_(std::move(handshake_cache_manager)),
      server_external_ips_(std::move(server_external_ips)),
      ws_open_callback_(std::move(ws_open_callback)),
      ws_new_ippacket_callback_(std::move(ws_new_ippacket_callback)),
      ws_close_callback_(std::move(ws_close_callback)),
      endpoint_(
          boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
      running_(false) {
  ctx_.set_options(boost::asio::ssl::context::default_workarounds |
                   boost::asio::ssl::context::no_sslv2 |
                   boost::asio::ssl::context::no_sslv3 |
                   boost::asio::ssl::context::single_dh_use);
  ctx_.use_certificate_chain_file(token_manager_->ServerCrtPath());
  ctx_.use_private_key_file(
      token_manager_->ServerKeyPath(), boost::asio::ssl::context::pem);
  ctx_.set_verify_mode(boost::asio::ssl::verify_none);
}

void Listener::AddApiHandle(const std::string& url,
    const std::string& method,
    const ApiHandle& handle) {
  fptn::web::AddApiHandle(api_handles_, url, method, handle);
}

boost::asio::awaitable<void> Listener::Run() {
  try {
    acceptor_.open(endpoint_.protocol());
    acceptor_.set_option(boost::asio::ip::tcp::no_delay(true));
    acceptor_.set_option(boost::asio::socket_base::reuse_address(true));

    acceptor_.bind(endpoint_);
    acceptor_.listen(boost::asio::socket_base::max_listen_connections);
  } catch (boost::system::system_error& err) {
    SPDLOG_ERROR("Listener::prepare error: {}", err.what());
    co_return;
  }
  running_ = true;

  boost::system::error_code ec;
  while (running_) {
    try {
      boost::asio::ip::tcp::socket socket(boost::asio::make_strand(ioc_));
      co_await acceptor_.async_accept(
          socket, boost::asio::redirect_error(boost::asio::use_awaitable, ec));

      if (!ec) {
        socket.set_option(boost::asio::ip::tcp::no_delay(true));

        auto session = std::make_shared<Session>(
            // probing settings
            enable_detect_probing_, allowed_sni_list_,
            server_external_ips_, std::move(socket), ctx_,
            // handlers
            api_handles_, handshake_cache_manager_, ws_open_callback_,
            ws_new_ippacket_callback_, ws_close_callback_);
        // run coroutine on the session's own strand
        boost::asio::co_spawn(
            session->GetExecutor(),
            [session]() mutable -> boost::asio::awaitable<void> {
              try {
                co_await session->Run();
              } catch (const std::exception& e) {
                SPDLOG_ERROR("Session::Run exception: {}", e.what());
                session->Close();
              } catch (...) {
                SPDLOG_ERROR("Session::Run unknown exception");
                session->Close();
              }
            },
            boost::asio::detached);
      } else if (running_) {
        SPDLOG_ERROR("Error onAccept: {}", ec.message());
        // Add delay after exception
        boost::asio::steady_timer timer(ioc_);
        timer.expires_after(std::chrono::milliseconds(300));
        co_await timer.async_wait(boost::asio::use_awaitable);
      }
    } catch (boost::system::system_error& err) {
      if (running_) {
        SPDLOG_ERROR("Listener::run error: {}", err.what());
      }
      co_return;
    }
  }
  co_return;
}

bool Listener::Stop() {
  try {
    running_ = false;
    acceptor_.close();
  } catch (boost::system::system_error& err) {
    SPDLOG_ERROR("Listener::stop error: {}", err.what());
    return false;
  }
  return true;
}
