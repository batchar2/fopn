/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-client/socks/socks5_server.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <iterator>
#include <memory>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/system/command.h"
#include "fptn-client/socks/udp_associate.h"
#include "fptn-protocol-lib/https/socket_options.h"

namespace fptn::socks {

namespace {

constexpr std::uint8_t kVersion = 0x05;
constexpr std::uint8_t kAuthNone = 0x00;
constexpr std::uint8_t kAuthUnacceptable = 0xFF;

constexpr std::uint8_t kCmdConnect = 0x01;
constexpr std::uint8_t kCmdUdpAssociate = 0x03;

constexpr std::uint8_t kAtypIPv4 = 0x01;
constexpr std::uint8_t kAtypDomain = 0x03;
constexpr std::uint8_t kAtypIPv6 = 0x04;

constexpr std::uint8_t kRepSuccess = 0x00;
constexpr std::uint8_t kRepGeneralFailure = 0x01;
constexpr std::uint8_t kRepNetworkUnreachable = 0x03;
constexpr std::uint8_t kRepHostUnreachable = 0x04;
constexpr std::uint8_t kRepConnectionRefused = 0x05;
constexpr std::uint8_t kRepTtlExpired = 0x06;
constexpr std::uint8_t kRepCommandNotSupported = 0x07;
constexpr std::uint8_t kRepAddressNotSupported = 0x08;

// По буферу на каждое направление, то есть два на сессию: при потолке в 512
// сессий 32 КБ обошлись бы в 32 МБ только на релей.
constexpr std::size_t kRelayBufferSize = 16 * 1024;

// Потолок паузы между попытками принять соединение, когда кончились
// дескрипторы.
constexpr std::chrono::milliseconds kAcceptBackoffMax{2000};

std::uint8_t ErrorToReply(const boost::system::error_code& ec) {
  if (ec == boost::asio::error::connection_refused) {
    return kRepConnectionRefused;
  }
  if (ec == boost::asio::error::network_unreachable) {
    return kRepNetworkUnreachable;
  }
  if (ec == boost::asio::error::host_unreachable ||
      ec == boost::asio::error::host_not_found) {
    return kRepHostUnreachable;
  }
  if (ec == boost::asio::error::timed_out) {
    return kRepTtlExpired;
  }
  return kRepGeneralFailure;
}

// Reply to the client. Nothing meaningful goes in BND.ADDR/BND.PORT, so it is
// zeroes - every practical implementation does that and clients accept it.
boost::asio::awaitable<void> SendReply(
    boost::asio::ip::tcp::socket& client, std::uint8_t reply) {
  const std::array<std::uint8_t, 10> response{
      kVersion, reply, 0x00, kAtypIPv4, 0, 0, 0, 0, 0, 0};
  boost::system::error_code ec;
  co_await boost::asio::async_write(client, boost::asio::buffer(response),
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
}

// Reply carrying a real BND.ADDR/BND.PORT, which UDP ASSOCIATE needs: it tells
// the client where to send its datagrams.
boost::asio::awaitable<void> SendReplyWithEndpoint(
    boost::asio::ip::tcp::socket& client,
    std::uint8_t reply,
    const boost::asio::ip::udp::endpoint& endpoint) {
  std::vector<std::uint8_t> response{kVersion, reply, 0x00};
  if (endpoint.address().is_v4()) {
    const auto bytes = endpoint.address().to_v4().to_bytes();
    response.push_back(kAtypIPv4);
    response.insert(response.end(), bytes.begin(), bytes.end());
  } else {
    const auto bytes = endpoint.address().to_v6().to_bytes();
    response.push_back(kAtypIPv6);
    response.insert(response.end(), bytes.begin(), bytes.end());
  }
  response.push_back(static_cast<std::uint8_t>(endpoint.port() >> 8));
  response.push_back(static_cast<std::uint8_t>(endpoint.port() & 0xFF));

  boost::system::error_code ec;
  co_await boost::asio::async_write(client, boost::asio::buffer(response),
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
}


// Проходит приветствие и отвечает отказом с кодом: клиент, уже отправивший
// запрос, получает внятную ошибку вместо закрытого сокета.
boost::asio::awaitable<void> RefuseSession(
    boost::asio::ip::tcp::socket& client, std::uint8_t reply) {
  boost::system::error_code ec;

  std::array<std::uint8_t, 2> greeting{};
  co_await boost::asio::async_read(client, boost::asio::buffer(greeting),
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec || greeting[0] != kVersion) {
    co_return;
  }
  std::vector<std::uint8_t> methods(greeting[1]);
  if (greeting[1] > 0) {
    co_await boost::asio::async_read(client, boost::asio::buffer(methods),
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      co_return;
    }
  }
  const std::array<std::uint8_t, 2> method_reply{kVersion, kAuthNone};
  co_await boost::asio::async_write(client, boost::asio::buffer(method_reply),
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec) {
    co_return;
  }

  // Запрос дочитывать не обязательно: ответ с кодом отказа допустим в любой
  // момент после согласования метода.
  const std::array<std::uint8_t, 10> response{
      kVersion, reply, 0x00, kAtypIPv4, 0, 0, 0, 0, 0, 0};
  co_await boost::asio::async_write(client, boost::asio::buffer(response),
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));

  boost::system::error_code ignored;
  client.close(ignored);
}

}  // namespace

// Резолвер собирается в Serve(): к тому моменту известны адрес туннеля и DNS,
// а до этого их может ещё не быть.
Socks5Server::Socks5Server(Config config) : config_(std::move(config)) {}

Socks5Server::~Socks5Server() { Stop(); }

bool Socks5Server::Listen() {
  if (acceptor_) {
    return true;
  }

  boost::system::error_code ec;
  const auto address =
      boost::asio::ip::make_address(config_.listen_address, ec);
  if (ec) {
    SPDLOG_ERROR("SOCKS5: bad listen address '{}': {}", config_.listen_address,
        ec.message());
    return false;
  }

  const boost::asio::ip::tcp::endpoint endpoint(address, config_.listen_port);
  acceptor_ = std::make_unique<boost::asio::ip::tcp::acceptor>(ioc_);
  acceptor_->open(endpoint.protocol(), ec);
  if (ec) {
    SPDLOG_ERROR("SOCKS5: acceptor open failed: {}", ec.message());
    acceptor_.reset();
    return false;
  }
  acceptor_->set_option(boost::asio::socket_base::reuse_address(true), ec);
  acceptor_->bind(endpoint, ec);
  if (ec) {
    SPDLOG_ERROR("SOCKS5: bind to {}:{} failed: {}", config_.listen_address,
        config_.listen_port, ec.message());
    acceptor_.reset();
    return false;
  }
  acceptor_->listen(boost::asio::socket_base::max_listen_connections, ec);
  if (ec) {
    SPDLOG_ERROR("SOCKS5: listen failed: {}", ec.message());
    acceptor_.reset();
    return false;
  }

  SPDLOG_INFO("SOCKS5 port {}:{} is open, waiting for the tunnel",
      config_.listen_address, config_.listen_port);
  return true;
}

void Socks5Server::SetTunnel(const std::string& tun_address_ipv4,
    const std::string& tun_address_ipv6,
    const std::string& dns_server_ipv4) {
  config_.tun_address_ipv4 = tun_address_ipv4;
  config_.tun_address_ipv6 = tun_address_ipv6;
  config_.dns_server_ipv4 = dns_server_ipv4;
}

bool Socks5Server::Serve() {
  if (running_.load()) {
    return true;
  }
  if (!acceptor_ && !Listen()) {
    return false;
  }

  resolver_ = std::make_unique<TunnelResolver>(TunnelResolver::Config{
      .dns_server_ipv4 = config_.dns_server_ipv4,
      .bind_address_ipv4 = config_.tun_address_ipv4,
  });

  running_.store(true);
  boost::asio::co_spawn(
      ioc_, [this]() -> boost::asio::awaitable<void> { co_await AcceptLoop(); },
      boost::asio::detached);

  thread_ = std::thread([this]() {
    try {
      ioc_.run();
    } catch (const std::exception& ex) {
      SPDLOG_ERROR("SOCKS5: io_context stopped with exception: {}", ex.what());
    }
  });

  SPDLOG_INFO("SOCKS5 proxy listening on {}:{} (via {} / {})",
      config_.listen_address, config_.listen_port, config_.tun_interface_name,
      config_.tun_address_ipv4);
  return true;
}

bool Socks5Server::Start() { return Listen() && Serve(); }

void Socks5Server::Stop() {
  if (!running_.exchange(false)) {
    return;
  }
  boost::system::error_code ec;
  if (acceptor_) {
    acceptor_->close(ec);
  }
  ioc_.stop();
  if (thread_.joinable()) {
    thread_.join();
  }
  SPDLOG_INFO("SOCKS5 proxy stopped");
}

boost::asio::awaitable<void> Socks5Server::AcceptLoop() {
  auto executor = co_await boost::asio::this_coro::executor;
  boost::asio::steady_timer backoff(executor);
  std::chrono::milliseconds pause{0};
  bool reported = false;

  while (running_.load()) {
    boost::system::error_code ec;
    auto client = co_await acceptor_->async_accept(
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      if (!running_.load()) {
        break;
      }
      // Дескрипторы кончились: повторять сразу же означает крутиться на месте,
      // забивая процессор и лог. Растущая пауза даёт закрыться тому, что уже
      // отработало.
      if (ec == boost::asio::error::no_descriptors ||
          ec == boost::system::errc::too_many_files_open_in_system) {
        pause = pause.count() == 0 ? std::chrono::milliseconds(100)
                                   : std::min(pause * 2, kAcceptBackoffMax);
        if (!reported) {
          SPDLOG_ERROR(
              "SOCKS5: out of file descriptors, throttling accepts "
              "({} sessions active, limit {})",
              active_sessions_.load(), config_.max_sessions);
          reported = true;
        }
        backoff.expires_after(pause);
        co_await backoff.async_wait(
            boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        continue;
      }
      SPDLOG_WARN("SOCKS5: accept failed: {}", ec.message());
      continue;
    }
    pause = std::chrono::milliseconds(0);
    reported = false;

    // За потолком клиенту отвечают отказом - это лучше, чем принять соединение
    // и оставить его висеть без дескрипторов на исходящее.
    if (active_sessions_.load() >= config_.max_sessions) {
      SPDLOG_WARN("SOCKS5: session limit {} reached, refusing",
          config_.max_sessions);
      // Отказ доводится до клиента по протоколу: он получит ошибку сразу, а не
      // будет ждать таймаута на оборванном соединении.
      boost::asio::co_spawn(
          ioc_,
          [sock = std::move(client)]() mutable
          -> boost::asio::awaitable<void> {
            co_await RefuseSession(sock, kRepGeneralFailure);
          },
          boost::asio::detached);
      continue;
    }

    boost::asio::co_spawn(
        ioc_,
        [this, sock = std::move(client)]() mutable
        -> boost::asio::awaitable<void> {
          ++active_sessions_;
          co_await HandleSession(std::move(sock));
          --active_sessions_;
        },
        boost::asio::detached);
  }
}

boost::asio::awaitable<void> Socks5Server::HandleSession(
    boost::asio::ip::tcp::socket client) {
  using boost::asio::experimental::awaitable_operators::operator&&;
  using boost::asio::experimental::awaitable_operators::operator||;

  const auto session_id = ++session_counter_;
  boost::system::error_code ec;
  auto executor = co_await boost::asio::this_coro::executor;

  // --- greeting: VER | NMETHODS | METHODS... ---
  std::array<std::uint8_t, 2> greeting{};
  co_await boost::asio::async_read(client, boost::asio::buffer(greeting),
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec || greeting[0] != kVersion) {
    SPDLOG_DEBUG("SOCKS5[{}]: bad greeting", session_id);
    co_return;
  }
  std::vector<std::uint8_t> methods(greeting[1]);
  if (greeting[1] > 0) {
    co_await boost::asio::async_read(client, boost::asio::buffer(methods),
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      co_return;
    }
  }
  const bool no_auth_supported =
      std::find(methods.begin(), methods.end(), kAuthNone) != methods.end();
  const std::array<std::uint8_t, 2> method_reply{
      kVersion, no_auth_supported ? kAuthNone : kAuthUnacceptable};
  co_await boost::asio::async_write(client, boost::asio::buffer(method_reply),
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec || !no_auth_supported) {
    co_return;
  }

  // --- request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT ---
  std::array<std::uint8_t, 4> header{};
  co_await boost::asio::async_read(client, boost::asio::buffer(header),
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec || header[0] != kVersion) {
    co_return;
  }
  const std::uint8_t command = header[1];
  if (command != kCmdConnect && command != kCmdUdpAssociate) {
    SPDLOG_WARN("SOCKS5[{}]: unsupported command {}", session_id, command);
    co_await SendReply(client, kRepCommandNotSupported);
    co_return;
  }

  std::string target_host;
  boost::asio::ip::address target_address;
  bool have_address = false;

  switch (header[3]) {
    case kAtypIPv4: {
      boost::asio::ip::address_v4::bytes_type bytes{};
      co_await boost::asio::async_read(client, boost::asio::buffer(bytes),
          boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec) {
        co_return;
      }
      target_address = boost::asio::ip::address_v4(bytes);
      have_address = true;
      break;
    }
    case kAtypIPv6: {
      boost::asio::ip::address_v6::bytes_type bytes{};
      co_await boost::asio::async_read(client, boost::asio::buffer(bytes),
          boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec) {
        co_return;
      }
      target_address = boost::asio::ip::address_v6(bytes);
      have_address = true;
      break;
    }
    case kAtypDomain: {
      std::uint8_t length = 0;
      co_await boost::asio::async_read(client,
          boost::asio::buffer(&length, 1),
          boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec || length == 0) {
        co_return;
      }
      std::vector<char> name(length);
      co_await boost::asio::async_read(client, boost::asio::buffer(name),
          boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec) {
        co_return;
      }
      target_host.assign(name.begin(), name.end());
      break;
    }
    default:
      co_await SendReply(client, kRepAddressNotSupported);
      co_return;
  }

  std::array<std::uint8_t, 2> port_bytes{};
  co_await boost::asio::async_read(client, boost::asio::buffer(port_bytes),
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec) {
    co_return;
  }
  const auto target_port =
      static_cast<std::uint16_t>((port_bytes[0] << 8) | port_bytes[1]);

  if (command == kCmdUdpAssociate) {
    co_await HandleUdpAssociate(client, session_id);
    co_return;
  }

  // Resolve through the tunnel: the local dnsmasq would hand back a FakeIP.
  if (!have_address) {
    const auto resolved = co_await resolver_->Resolve(target_host);
    if (resolved.empty()) {
      SPDLOG_WARN("SOCKS5[{}]: cannot resolve '{}'", session_id, target_host);
      co_await SendReply(client, kRepHostUnreachable);
      co_return;
    }
    target_address = resolved.front();
  }

  // --- outgoing connection through the tunnel ---
  const boost::asio::ip::tcp::endpoint target(target_address, target_port);
  boost::asio::ip::tcp::socket remote(executor);

  remote.open(target.protocol(), ec);
  if (ec) {
    co_await SendReply(client, kRepGeneralFailure);
    co_return;
  }
  fptn::protocol::https::ApplyRoutingMark(remote.native_handle());

  // Bind to the tunnel address: the policy rule steers packets into the TUN.
  const std::string& bind_ip = target_address.is_v4()
                                   ? config_.tun_address_ipv4
                                   : config_.tun_address_ipv6;
  if (!bind_ip.empty()) {
    const auto bind_addr = boost::asio::ip::make_address(bind_ip, ec);
    if (!ec) {
      remote.bind(boost::asio::ip::tcp::endpoint(bind_addr, 0), ec);
      if (ec) {
        SPDLOG_WARN("SOCKS5[{}]: bind to {} failed: {}", session_id, bind_ip,
            ec.message());
        co_await SendReply(client, kRepGeneralFailure);
        co_return;
      }
    }
  }

  boost::asio::steady_timer connect_timer(executor);
  connect_timer.expires_after(
      std::chrono::milliseconds(config_.connect_timeout_ms));
  boost::system::error_code connect_ec;
  boost::system::error_code timer_ec;
  const auto outcome = co_await(
      remote.async_connect(target,
          boost::asio::redirect_error(boost::asio::use_awaitable,
              connect_ec)) ||
      connect_timer.async_wait(
          boost::asio::redirect_error(boost::asio::use_awaitable, timer_ec)));

  if (outcome.index() == 1) {
    SPDLOG_WARN("SOCKS5[{}]: connect to {}:{} timed out", session_id,
        target_address.to_string(), target_port);
    remote.close(ec);
    co_await SendReply(client, kRepTtlExpired);
    co_return;
  }
  connect_timer.cancel();
  if (connect_ec) {
    SPDLOG_WARN("SOCKS5[{}]: connect to {}:{} failed: {}", session_id,
        target_address.to_string(), target_port, connect_ec.message());
    co_await SendReply(client, ErrorToReply(connect_ec));
    co_return;
  }

  remote.set_option(boost::asio::ip::tcp::no_delay(true), ec);
  client.set_option(boost::asio::ip::tcp::no_delay(true), ec);

  co_await SendReply(client, kRepSuccess);
  SPDLOG_DEBUG("SOCKS5[{}]: {} -> {}:{}", session_id,
      target_host.empty() ? "ip" : target_host, target_address.to_string(),
      target_port);

  // --- relay data in both directions ---
  // Таймер простоя перезаводится на каждом прочитанном куске; когда он всё же
  // срабатывает, обе стороны закрываются и релеи выходят по ошибке.
  boost::asio::steady_timer idle(executor);
  idle.expires_after(config_.idle_timeout);
  co_await(Relay(client, remote, idle) && Relay(remote, client, idle) &&
            WatchIdle(idle, client, remote));

  client.close(ec);
  remote.close(ec);
}

// Ждёт, пока таймер простоя не сработает по-настоящему: каждое чтение сдвигает
// его вперёд, и тогда ожидание отменяется и начинается заново.
boost::asio::awaitable<void> Socks5Server::WatchIdle(
    boost::asio::steady_timer& idle,
    boost::asio::ip::tcp::socket& client,
    boost::asio::ip::tcp::socket& remote) {
  for (;;) {
    boost::system::error_code ec;
    co_await idle.async_wait(
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (!ec) {
      SPDLOG_DEBUG("SOCKS5: closing idle session after {}s",
          config_.idle_timeout.count());
      boost::system::error_code ignored;
      client.close(ignored);
      remote.close(ignored);
      co_return;
    }
    if (!client.is_open() || !remote.is_open()) {
      co_return;
    }
  }
}

boost::asio::awaitable<void> Socks5Server::Relay(
    boost::asio::ip::tcp::socket& from,
    boost::asio::ip::tcp::socket& to,
    boost::asio::steady_timer& idle) {
  std::vector<std::uint8_t> buffer(kRelayBufferSize);
  boost::system::error_code ec;

  for (;;) {
    const std::size_t bytes = co_await from.async_read_some(
        boost::asio::buffer(buffer),
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec || bytes == 0) {
      break;
    }
    idle.expires_after(config_.idle_timeout);
    co_await boost::asio::async_write(to,
        boost::asio::buffer(buffer.data(), bytes),
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      break;
    }
  }

  // Half-close the peer socket, otherwise the opposite coroutine hangs forever.
  boost::system::error_code shutdown_ec;
  to.shutdown(boost::asio::ip::tcp::socket::shutdown_send, shutdown_ec);
}

// The association is owned by this coroutine, so it dies with the control
// connection exactly as RFC 1928 requires. Both directions are awaited
// together: whichever ends first tears the other down.
boost::asio::awaitable<void> Socks5Server::HandleUdpAssociate(
    boost::asio::ip::tcp::socket& client, std::uint64_t session_id) {
  using boost::asio::experimental::awaitable_operators::operator||;

  auto executor = co_await boost::asio::this_coro::executor;
  UdpAssociate associate(executor,
      UdpAssociate::Config{
          .listen_address = config_.listen_address,
          .tun_address_ipv4 = config_.tun_address_ipv4,
          .tun_address_ipv6 = config_.tun_address_ipv6,
      },
      resolver_.get(), session_id);

  boost::system::error_code ec;
  if (!associate.Open(ec)) {
    SPDLOG_WARN("SOCKS5[{}]: UDP associate failed: {}", session_id,
        ec.message());
    co_await SendReply(client, kRepGeneralFailure);
    co_return;
  }

  co_await SendReplyWithEndpoint(
      client, kRepSuccess, associate.BoundEndpoint());
  SPDLOG_DEBUG("SOCKS5[{}]: UDP associate on {}:{}", session_id,
      associate.BoundEndpoint().address().to_string(),
      associate.BoundEndpoint().port());

  // Reading the control connection is how its close is noticed; a compliant
  // client sends nothing on it, so any byte just keeps the wait alive.
  co_await(associate.Run() || WaitForClose(client));
  associate.Close();
}

boost::asio::awaitable<void> Socks5Server::WaitForClose(
    boost::asio::ip::tcp::socket& client) {
  std::array<std::uint8_t, 64> scratch{};
  boost::system::error_code ec;
  for (;;) {
    co_await client.async_read_some(boost::asio::buffer(scratch),
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      co_return;
    }
  }
}

namespace {

constexpr std::uint16_t kTypeA = 1;
constexpr std::uint16_t kTypeAAAA = 28;
constexpr std::size_t kHeaderSize = 12;
constexpr std::size_t kMaxResponseSize = 1500;
constexpr std::size_t kMaxTcpResponseSize = 8 * 1024;

void PutU16(std::vector<std::uint8_t>& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value >> 8));
  out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

std::uint16_t GetU16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

// Encodes "example.com" into a sequence of DNS labels.
bool EncodeName(const std::string& host, std::vector<std::uint8_t>& out) {
  std::size_t start = 0;
  while (start <= host.size()) {
    const std::size_t dot = host.find('.', start);
    const std::size_t end = (dot == std::string::npos) ? host.size() : dot;
    const std::size_t len = end - start;
    if (len == 0) {
      // An empty label is only valid as the trailing dot at the end of a name.
      if (end != host.size()) {
        return false;
      }
      break;
    }
    if (len > 63) {
      return false;
    }
    out.push_back(static_cast<std::uint8_t>(len));
    out.insert(out.end(), host.begin() + static_cast<std::ptrdiff_t>(start),
        host.begin() + static_cast<std::ptrdiff_t>(end));
    if (dot == std::string::npos) {
      break;
    }
    start = end + 1;
  }
  out.push_back(0);
  return true;
}

// Skips a name in the response: either a label chain or a compression pointer.
bool SkipName(const std::uint8_t* data, std::size_t size, std::size_t& offset) {
  while (offset < size) {
    const std::uint8_t len = data[offset];
    if ((len & 0xC0) == 0xC0) {
      offset += 2;  // a pointer is exactly two bytes
      return offset <= size;
    }
    offset += 1;
    if (len == 0) {
      return true;
    }
    offset += len;
  }
  return false;
}

}  // namespace

TunnelResolver::TunnelResolver(Config config) : config_(std::move(config)) {}

bool TunnelResolver::LookupCache(
    const std::string& host, std::vector<boost::asio::ip::address>* out) {
  const auto it = cache_.find(host);
  if (it == cache_.end()) {
    return false;
  }
  if (it->second.expires_at <= std::chrono::steady_clock::now()) {
    cache_.erase(it);
    return false;
  }
  *out = it->second.addresses;
  return true;
}

void TunnelResolver::StoreCache(const std::string& host,
    const std::vector<boost::asio::ip::address>& addresses,
    std::chrono::seconds ttl) {
  if (addresses.empty()) {
    return;
  }
  ttl = std::clamp(ttl, config_.min_ttl, config_.max_ttl);

  // Кэш на роутере не должен расти без предела. Сначала выбрасываем протухшее,
  // и только если это не помогло - самую близкую к истечению запись.
  if (cache_.size() >= config_.max_cache_entries) {
    const auto now = std::chrono::steady_clock::now();
    for (auto it = cache_.begin(); it != cache_.end();) {
      it = (it->second.expires_at <= now) ? cache_.erase(it) : std::next(it);
    }
  }
  if (cache_.size() >= config_.max_cache_entries) {
    auto oldest = std::min_element(cache_.begin(), cache_.end(),
        [](const auto& a, const auto& b) {
          return a.second.expires_at < b.second.expires_at;
        });
    if (oldest != cache_.end()) {
      cache_.erase(oldest);
    }
  }

  cache_[host] = CacheEntry{addresses, std::chrono::steady_clock::now() + ttl};
}

void TunnelResolver::ReportReachable(bool reachable, const std::string& host) {
  if (reachable) {
    if (dns_unreachable_) {
      dns_unreachable_ = false;
      SPDLOG_INFO("TunnelResolver: DNS {} answers again",
          config_.dns_server_ipv4);
    }
    return;
  }
  if (!dns_unreachable_) {
    dns_unreachable_ = true;
    SPDLOG_WARN("TunnelResolver: DNS {} is not answering (first miss: '{}')",
        config_.dns_server_ipv4, host);
  }
}

boost::asio::awaitable<std::vector<boost::asio::ip::address>>
TunnelResolver::Resolve(std::string host) {
  if (!host.empty() && host.back() == '.') {
    host.pop_back();
  }

  std::vector<boost::asio::ip::address> cached;
  if (LookupCache(host, &cached)) {
    co_return cached;
  }

  auto answer = co_await Query(host, kTypeA);
  if (answer.answered && answer.addresses.empty()) {
    answer = co_await Query(host, kTypeAAAA);
  }
  if (!answer.answered) {
    co_return std::vector<boost::asio::ip::address>{};
  }

  StoreCache(host, answer.addresses, answer.ttl);
  co_return answer.addresses;
}

boost::asio::awaitable<TunnelResolver::Answer> TunnelResolver::Query(
    const std::string& host, std::uint16_t qtype) {
  const int attempts = std::max(1, config_.attempts);
  Answer answer;

  for (int attempt = 0; attempt < attempts; ++attempt) {
    answer = co_await QueryOverUdp(host, qtype);
    if (answer.truncated) {
      // Ответ не поместился в датаграмму - добираем его по TCP, как велит
      // RFC 1035; повторять по UDP смысла нет, придёт то же усечение.
      answer = co_await QueryOverTcp(host, qtype);
      break;
    }
    if (answer.answered) {
      break;
    }
  }

  ReportReachable(answer.answered, host);
  co_return answer;
}

namespace {

// Собирает запрос без длины: для TCP она приписывается отдельно.
bool BuildQuery(const std::string& host, std::uint16_t qtype,
    std::uint16_t query_id, std::vector<std::uint8_t>* out) {
  out->clear();
  out->reserve(64);
  PutU16(*out, query_id);
  PutU16(*out, 0x0100);  // RD - recursion desired
  PutU16(*out, 1);       // QDCOUNT
  PutU16(*out, 0);       // ANCOUNT
  PutU16(*out, 0);       // NSCOUNT
  PutU16(*out, 0);       // ARCOUNT
  if (!EncodeName(host, *out)) {
    return false;
  }
  PutU16(*out, qtype);
  PutU16(*out, 1);  // IN
  return true;
}

std::uint16_t MakeQueryId() {
  static thread_local std::random_device device;
  static thread_local std::mt19937 rng(device());
  return static_cast<std::uint16_t>(
      std::uniform_int_distribution<int>(1, 0xFFFF)(rng));
}

}  // namespace

TunnelResolver::Answer TunnelResolver::ParseResponse(const std::uint8_t* data,
    std::size_t size, std::uint16_t query_id, const std::string& host) {
  TunnelResolver::Answer answer;
  if (size < kHeaderSize || GetU16(data) != query_id) {
    SPDLOG_WARN("TunnelResolver: bad response for '{}'", host);
    return answer;
  }

  answer.answered = true;
  answer.truncated = (data[2] & 0x02) != 0;

  const std::uint16_t qdcount = GetU16(data + 4);
  const std::uint16_t ancount = GetU16(data + 6);

  std::size_t offset = kHeaderSize;
  for (std::uint16_t i = 0; i < qdcount; ++i) {
    if (!SkipName(data, size, offset)) {
      return answer;
    }
    offset += 4;  // QTYPE + QCLASS
  }

  std::uint32_t min_ttl = 0;
  for (std::uint16_t i = 0; i < ancount && offset + 10 <= size; ++i) {
    if (!SkipName(data, size, offset)) {
      break;
    }
    if (offset + 10 > size) {
      break;
    }
    const std::uint16_t rtype = GetU16(data + offset);
    const std::uint32_t ttl =
        (static_cast<std::uint32_t>(GetU16(data + offset + 4)) << 16) |
        GetU16(data + offset + 6);
    const std::uint16_t rdlength = GetU16(data + offset + 8);
    offset += 10;
    if (offset + rdlength > size) {
      break;
    }
    if (rtype == kTypeA && rdlength == 4) {
      boost::asio::ip::address_v4::bytes_type bytes{};
      std::memcpy(bytes.data(), data + offset, bytes.size());
      answer.addresses.emplace_back(boost::asio::ip::address_v4(bytes));
    } else if (rtype == kTypeAAAA && rdlength == 16) {
      boost::asio::ip::address_v6::bytes_type bytes{};
      std::memcpy(bytes.data(), data + offset, bytes.size());
      answer.addresses.emplace_back(boost::asio::ip::address_v6(bytes));
    } else {
      offset += rdlength;
      continue;
    }
    // Срок жизни набора - по самой недолговечной записи в нём.
    min_ttl = (min_ttl == 0) ? ttl : std::min(min_ttl, ttl);
    offset += rdlength;
  }

  answer.ttl = std::chrono::seconds(min_ttl);
  SPDLOG_DEBUG("TunnelResolver: '{}' -> {} address(es), ttl {}s", host,
      answer.addresses.size(), min_ttl);
  return answer;
}

boost::asio::awaitable<TunnelResolver::Answer> TunnelResolver::QueryOverUdp(
    const std::string& host, std::uint16_t qtype) {
  using boost::asio::experimental::awaitable_operators::operator||;

  Answer answer;
  const auto query_id = MakeQueryId();

  std::vector<std::uint8_t> request;
  if (!BuildQuery(host, qtype, query_id, &request)) {
    SPDLOG_WARN("TunnelResolver: bad hostname '{}'", host);
    answer.answered = true;  // имя негодное, повторять нечего
    co_return answer;
  }

  boost::system::error_code ec;
  auto executor = co_await boost::asio::this_coro::executor;
  boost::asio::ip::udp::socket socket(executor);

  socket.open(boost::asio::ip::udp::v4(), ec);
  if (ec) {
    SPDLOG_ERROR("TunnelResolver: socket open failed: {}", ec.message());
    co_return answer;
  }
  fptn::protocol::https::ApplyRoutingMark(socket.native_handle());

  if (!config_.bind_address_ipv4.empty()) {
    const auto bind_addr =
        boost::asio::ip::make_address(config_.bind_address_ipv4, ec);
    if (!ec) {
      socket.bind(boost::asio::ip::udp::endpoint(bind_addr, 0), ec);
      if (ec) {
        SPDLOG_ERROR("TunnelResolver: bind to {} failed: {}",
            config_.bind_address_ipv4, ec.message());
        co_return answer;
      }
    }
  }

  const auto dns_addr =
      boost::asio::ip::make_address(config_.dns_server_ipv4, ec);
  if (ec) {
    SPDLOG_ERROR("TunnelResolver: bad DNS server address '{}'",
        config_.dns_server_ipv4);
    co_return answer;
  }
  const boost::asio::ip::udp::endpoint dns_endpoint(dns_addr, 53);

  co_await socket.async_send_to(boost::asio::buffer(request), dns_endpoint,
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec) {
    SPDLOG_DEBUG("TunnelResolver: send failed: {}", ec.message());
    co_return answer;
  }

  std::array<std::uint8_t, kMaxResponseSize> response{};
  boost::asio::ip::udp::endpoint from;
  boost::asio::steady_timer timer(executor);
  timer.expires_after(std::chrono::milliseconds(config_.timeout_ms));

  boost::system::error_code recv_ec;
  const auto outcome = co_await(
      socket.async_receive_from(boost::asio::buffer(response), from,
          boost::asio::redirect_error(boost::asio::use_awaitable, recv_ec)) ||
      timer.async_wait(
          boost::asio::redirect_error(boost::asio::use_awaitable, ec)));

  if (outcome.index() == 1) {
    SPDLOG_DEBUG("TunnelResolver: timeout resolving '{}' via {}", host,
        config_.dns_server_ipv4);
    socket.close(ec);
    co_return answer;
  }
  const std::size_t received = std::get<0>(outcome);
  if (recv_ec || received < kHeaderSize) {
    SPDLOG_DEBUG("TunnelResolver: receive failed for '{}': {}", host,
        recv_ec.message());
    co_return answer;
  }

  co_return ParseResponse(response.data(), received, query_id, host);
}

boost::asio::awaitable<TunnelResolver::Answer> TunnelResolver::QueryOverTcp(
    const std::string& host, std::uint16_t qtype) {
  using boost::asio::experimental::awaitable_operators::operator||;

  Answer answer;
  const auto query_id = MakeQueryId();

  std::vector<std::uint8_t> body;
  if (!BuildQuery(host, qtype, query_id, &body)) {
    answer.answered = true;
    co_return answer;
  }
  std::vector<std::uint8_t> request;
  request.reserve(body.size() + 2);
  PutU16(request, static_cast<std::uint16_t>(body.size()));
  request.insert(request.end(), body.begin(), body.end());

  boost::system::error_code ec;
  auto executor = co_await boost::asio::this_coro::executor;

  const auto dns_addr =
      boost::asio::ip::make_address(config_.dns_server_ipv4, ec);
  if (ec) {
    co_return answer;
  }

  boost::asio::ip::tcp::socket socket(executor);
  socket.open(boost::asio::ip::tcp::v4(), ec);
  if (ec) {
    co_return answer;
  }
  fptn::protocol::https::ApplyRoutingMark(socket.native_handle());

  if (!config_.bind_address_ipv4.empty()) {
    const auto bind_addr =
        boost::asio::ip::make_address(config_.bind_address_ipv4, ec);
    if (!ec) {
      socket.bind(boost::asio::ip::tcp::endpoint(bind_addr, 0), ec);
    }
  }

  boost::asio::steady_timer timer(executor);
  timer.expires_after(std::chrono::milliseconds(config_.timeout_ms));

  const boost::asio::ip::tcp::endpoint dns_endpoint(dns_addr, 53);
  boost::system::error_code op_ec;
  // Каждое ожидание даёт свой тип variant, поэтому переменные разные.
  const auto connect_outcome = co_await(
      socket.async_connect(dns_endpoint,
          boost::asio::redirect_error(boost::asio::use_awaitable, op_ec)) ||
      timer.async_wait(
          boost::asio::redirect_error(boost::asio::use_awaitable, ec)));
  if (connect_outcome.index() == 1 || op_ec) {
    SPDLOG_DEBUG("TunnelResolver: TCP connect to {} failed for '{}'",
        config_.dns_server_ipv4, host);
    socket.close(ec);
    co_return answer;
  }

  co_await boost::asio::async_write(socket, boost::asio::buffer(request),
      boost::asio::redirect_error(boost::asio::use_awaitable, op_ec));
  if (op_ec) {
    socket.close(ec);
    co_return answer;
  }

  std::array<std::uint8_t, 2> length_buf{};
  const auto length_outcome = co_await(
      boost::asio::async_read(socket, boost::asio::buffer(length_buf),
          boost::asio::redirect_error(boost::asio::use_awaitable, op_ec)) ||
      timer.async_wait(
          boost::asio::redirect_error(boost::asio::use_awaitable, ec)));
  if (length_outcome.index() == 1 || op_ec) {
    socket.close(ec);
    co_return answer;
  }

  const std::size_t length = GetU16(length_buf.data());
  if (length < kHeaderSize || length > kMaxTcpResponseSize) {
    socket.close(ec);
    co_return answer;
  }

  std::vector<std::uint8_t> response(length);
  const auto body_outcome = co_await(
      boost::asio::async_read(socket, boost::asio::buffer(response),
          boost::asio::redirect_error(boost::asio::use_awaitable, op_ec)) ||
      timer.async_wait(
          boost::asio::redirect_error(boost::asio::use_awaitable, ec)));
  socket.close(ec);
  if (body_outcome.index() == 1 || op_ec) {
    co_return answer;
  }

  answer = ParseResponse(response.data(), response.size(), query_id, host);
  // По TCP усечения не бывает - флаг из ответа тут только запутает вызывающего.
  answer.truncated = false;
  co_return answer;
}


namespace {

// Commands whose failure is expected (deleting something that is absent).
void RunQuiet(const std::string& command) {
  fptn::common::system::command::run(command);
}
bool RunChecked(const std::string& command) {
  if (!fptn::common::system::command::run(command)) {
    SPDLOG_ERROR("Command failed: {}", command);
    return false;
  }
  return true;
}

}  // namespace

PolicyRoute::PolicyRoute(Config config) : config_(std::move(config)) {}

PolicyRoute::~PolicyRoute() { Clean(); }

bool PolicyRoute::Apply() {
  if (config_.tun_interface_name.empty()) {
    SPDLOG_ERROR("PolicyRoute: TUN interface name is empty");
    return false;
  }

  // Clean leftovers from a previous run (e.g. after the process crashed).
  Clean();

  const auto table = std::to_string(config_.table_id);

  if (!RunChecked(fmt::format("ip route replace default dev {} table {}",
          config_.tun_interface_name, table))) {
    return false;
  }

  if (!config_.tun_address_ipv4.empty()) {
    if (!RunChecked(fmt::format("ip rule add from {} lookup {} priority {}",
            config_.tun_address_ipv4, table, config_.rule_priority))) {
      Clean();
      return false;
    }
  }

  // IPv6 is optional: many ISPs do not provide it and that must not be fatal.
  if (!config_.tun_address_ipv6.empty()) {
    RunQuiet(fmt::format("ip -6 route replace default dev {} table {}",
        config_.tun_interface_name, table));
    RunQuiet(fmt::format("ip -6 rule add from {} lookup {} priority {}",
        config_.tun_address_ipv6, table, config_.rule_priority));
  }

  applied_ = true;
  SPDLOG_INFO(
      "Policy routing applied: from {} lookup {} (default dev {}), "
      "main table untouched",
      config_.tun_address_ipv4, table, config_.tun_interface_name);
  return true;
}

void PolicyRoute::Clean() {
  const auto table = std::to_string(config_.table_id);

  if (!config_.tun_address_ipv4.empty()) {
    RunQuiet(fmt::format("ip rule del from {} lookup {} priority {}",
        config_.tun_address_ipv4, table, config_.rule_priority));
  }
  if (!config_.tun_address_ipv6.empty()) {
    RunQuiet(fmt::format("ip -6 rule del from {} lookup {} priority {}",
        config_.tun_address_ipv6, table, config_.rule_priority));
  }
  RunQuiet(fmt::format("ip route flush table {}", table));
  RunQuiet(fmt::format("ip -6 route flush table {}", table));

  if (applied_) {
    SPDLOG_INFO("Policy routing removed (table {})", table);
    applied_ = false;
  }
}

}  // namespace fptn::socks
