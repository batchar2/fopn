/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio/connect.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "socks/socks5_server.h"

namespace {

using boost::asio::ip::tcp;
using fptn::socks::Socks5Server;

constexpr std::uint8_t kVersion = 0x05;
constexpr std::uint8_t kAuthNone = 0x00;
constexpr std::uint8_t kAuthGssapi = 0x01;
constexpr std::uint8_t kAuthUnacceptable = 0xFF;
constexpr std::uint8_t kCmdConnect = 0x01;
constexpr std::uint8_t kCmdBind = 0x02;
constexpr std::uint8_t kAtypIPv4 = 0x01;
constexpr std::uint8_t kRepSuccess = 0x00;
constexpr std::uint8_t kRepGeneralFailure = 0x01;
constexpr std::uint8_t kRepCommandNotSupported = 0x07;

// An echo server on localhost: a CONNECT target that keeps the test off the
// network. Accepting is asynchronous - closing a blocking accept from another
// thread is not reliable.
class EchoServer {
 public:
  EchoServer() : acceptor_(ioc_, tcp::endpoint(tcp::v4(), 0)) {
    port_ = acceptor_.local_endpoint().port();
    Accept();
    thread_ = std::thread([this]() { ioc_.run(); });
  }

  ~EchoServer() {
    boost::asio::post(ioc_, [this]() {
      boost::system::error_code ec;
      acceptor_.close(ec);
    });
    ioc_.stop();
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  std::uint16_t port() const { return port_; }

 private:
  class Session : public std::enable_shared_from_this<Session> {
   public:
    explicit Session(tcp::socket socket) : socket_(std::move(socket)) {}

    void Start() { Read(); }

   private:
    void Read() {
      auto self = shared_from_this();
      socket_.async_read_some(boost::asio::buffer(buffer_),
          [this, self](boost::system::error_code ec, std::size_t size) {
            if (ec) {
              return;
            }
            Write(size);
          });
    }

    void Write(std::size_t size) {
      auto self = shared_from_this();
      boost::asio::async_write(socket_,
          boost::asio::buffer(buffer_.data(), size),
          [this, self](boost::system::error_code ec, std::size_t) {
            if (ec) {
              return;
            }
            Read();
          });
    }

    tcp::socket socket_;
    std::array<char, 1024> buffer_{};
  };

  void Accept() {
    acceptor_.async_accept(
        [this](boost::system::error_code ec, tcp::socket socket) {
          if (ec) {
            return;
          }
          std::make_shared<Session>(std::move(socket))->Start();
          Accept();
        });
  }

  boost::asio::io_context ioc_;
  tcp::acceptor acceptor_;
  std::thread thread_;
  std::uint16_t port_ = 0;
};

// Claim a free port and release it at once: a race is possible, but on the
// machine running the test nothing else competes for it.
std::uint16_t PickFreePort() {
  boost::asio::io_context ioc;
  tcp::acceptor probe(ioc, tcp::endpoint(tcp::v4(), 0));
  return probe.local_endpoint().port();
}

class Socks5Client {
 public:
  Socks5Client(boost::asio::io_context& ioc, std::uint16_t port)
      : socket_(ioc) {
    socket_.connect(
        tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port), ec_);
  }

  bool connected() const { return !ec_; }

  // Returns the second byte of the greeting reply (the chosen method).
  std::uint8_t Greet(std::uint8_t method) {
    const std::array<std::uint8_t, 3> hello{kVersion, 1, method};
    boost::asio::write(socket_, boost::asio::buffer(hello), ec_);
    if (ec_) {
      return kAuthUnacceptable;
    }
    std::array<std::uint8_t, 2> reply{};
    boost::asio::read(socket_, boost::asio::buffer(reply), ec_);
    return ec_ ? kAuthUnacceptable : reply[1];
  }

  // Returns the reply code (REP) for the request.
  std::uint8_t Request(
      std::uint8_t command, std::uint16_t port, std::uint8_t last_octet = 1) {
    const std::array<std::uint8_t, 10> request{kVersion, command, 0x00,
        kAtypIPv4, 127, 0, 0, last_octet,
        static_cast<std::uint8_t>(port >> 8),
        static_cast<std::uint8_t>(port & 0xFF)};
    boost::asio::write(socket_, boost::asio::buffer(request), ec_);
    if (ec_) {
      return kRepGeneralFailure;
    }
    std::array<std::uint8_t, 10> reply{};
    boost::asio::read(socket_, boost::asio::buffer(reply), ec_);
    return ec_ ? kRepGeneralFailure : reply[1];
  }

  std::string RoundTrip(const std::string& payload) {
    boost::asio::write(socket_, boost::asio::buffer(payload), ec_);
    if (ec_) {
      return {};
    }
    std::vector<char> buffer(payload.size());
    boost::asio::read(socket_, boost::asio::buffer(buffer), ec_);
    return ec_ ? std::string{} : std::string(buffer.begin(), buffer.end());
  }

  // UDP ASSOCIATE with an all-zero address, as a client that does not know
  // its source port yet sends it. Returns the reply code.
  std::uint8_t UdpAssociate() {
    const std::array<std::uint8_t, 10> request{
        kVersion, 0x03, 0x00, kAtypIPv4, 0, 0, 0, 0, 0, 0};
    boost::asio::write(socket_, boost::asio::buffer(request), ec_);
    if (ec_) {
      return kRepGeneralFailure;
    }
    std::array<std::uint8_t, 10> reply{};
    boost::asio::read(socket_, boost::asio::buffer(reply), ec_);
    return ec_ ? kRepGeneralFailure : reply[1];
  }

  // Waits for the server to close the connection; false if it did not.
  bool WaitClosed(std::chrono::milliseconds limit) {  // NOLINT
    const auto deadline = std::chrono::steady_clock::now() + limit;
    std::array<char, 64> buffer{};
    socket_.non_blocking(true);
    while (std::chrono::steady_clock::now() < deadline) {
      boost::system::error_code ec;
      socket_.read_some(boost::asio::buffer(buffer), ec);
      if (ec == boost::asio::error::eof ||
          ec == boost::asio::error::connection_reset) {
        return true;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return false;
  }

 private:
  tcp::socket socket_;
  boost::system::error_code ec_;
};

Socks5Server::Config MakeConfig(std::uint16_t port) {
  Socks5Server::Config config;
  config.listen_address = "127.0.0.1";
  config.listen_port = port;
  // No TUN binding and no tunnel resolver: the target is given by address.
  config.tun_address_ipv4.clear();
  config.tun_address_ipv6.clear();
  config.dns_server_ipv4 = "127.0.0.1";
  config.connect_timeout_ms = 2000;
  return config;
}

}  // namespace

// cppcheck-suppress syntaxError
TEST(Socks5ServerTest, RelaysConnectToTarget) {
  EchoServer echo;
  const auto port = PickFreePort();
  Socks5Server server(MakeConfig(port));
  ASSERT_TRUE(server.Start());

  boost::asio::io_context ioc;
  Socks5Client client(ioc, port);
  ASSERT_TRUE(client.connected());
  EXPECT_EQ(client.Greet(kAuthNone), kAuthNone);
  EXPECT_EQ(client.Request(kCmdConnect, echo.port()), kRepSuccess);
  EXPECT_EQ(client.RoundTrip("hello fptn"), "hello fptn");

  server.Stop();
}

TEST(Socks5ServerTest, RejectsUnsupportedAuthMethod) {
  const auto port = PickFreePort();
  Socks5Server server(MakeConfig(port));
  ASSERT_TRUE(server.Start());

  boost::asio::io_context ioc;
  Socks5Client client(ioc, port);
  ASSERT_TRUE(client.connected());
  EXPECT_EQ(client.Greet(kAuthGssapi), kAuthUnacceptable);

  server.Stop();
}

TEST(Socks5ServerTest, RejectsUnsupportedCommand) {
  const auto port = PickFreePort();
  Socks5Server server(MakeConfig(port));
  ASSERT_TRUE(server.Start());

  boost::asio::io_context ioc;
  Socks5Client client(ioc, port);
  ASSERT_TRUE(client.connected());
  ASSERT_EQ(client.Greet(kAuthNone), kAuthNone);
  EXPECT_EQ(client.Request(kCmdBind, 9), kRepCommandNotSupported);

  server.Stop();
}

TEST(Socks5ServerTest, RefusesSessionsOverTheLimit) {
  EchoServer echo;
  const auto port = PickFreePort();
  auto config = MakeConfig(port);
  config.max_sessions = 1;
  Socks5Server server(config);
  ASSERT_TRUE(server.Start());

  boost::asio::io_context ioc;
  Socks5Client first(ioc, port);
  ASSERT_TRUE(first.connected());
  ASSERT_EQ(first.Greet(kAuthNone), kAuthNone);
  ASSERT_EQ(first.Request(kCmdConnect, echo.port()), kRepSuccess);

  // The counter grows when a session starts, so the second client is let
  // reach the server once the cap is already in place.
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  Socks5Client second(ioc, port);
  ASSERT_TRUE(second.connected());
  EXPECT_EQ(second.Greet(kAuthNone), kAuthNone);
  EXPECT_EQ(second.Request(kCmdConnect, echo.port()), kRepGeneralFailure);

  // The first session keeps working meanwhile.
  EXPECT_EQ(first.RoundTrip("still alive"), "still alive");

  server.Stop();
}

TEST(Socks5ServerTest, ClosesIdleSession) {
  EchoServer echo;
  const auto port = PickFreePort();
  auto config = MakeConfig(port);
  config.idle_timeout = std::chrono::seconds(1);
  Socks5Server server(config);
  ASSERT_TRUE(server.Start());

  boost::asio::io_context ioc;
  Socks5Client client(ioc, port);
  ASSERT_TRUE(client.connected());
  ASSERT_EQ(client.Greet(kAuthNone), kAuthNone);
  ASSERT_EQ(client.Request(kCmdConnect, echo.port()), kRepSuccess);

  EXPECT_TRUE(client.WaitClosed(std::chrono::seconds(5)));

  server.Stop();
}

// A client that connects and says nothing used to hold its descriptors until
// the process ended: the idle timer only starts once the relay is up.
TEST(Socks5ServerTest, SilentClientIsDroppedAfterTheHandshakeDeadline) {
  const auto port = PickFreePort();
  auto config = MakeConfig(port);
  config.handshake_timeout = std::chrono::seconds(1);

  Socks5Server server(config);
  ASSERT_TRUE(server.Start());

  boost::asio::io_context ioc;
  Socks5Client client(ioc, port);
  ASSERT_TRUE(client.connected());

  // Not a single byte is sent; the server has to give up on its own.
  EXPECT_TRUE(client.WaitClosed(std::chrono::milliseconds(5000)));
  server.Stop();
}

// The handshake deadline closes the control socket, so it has to be lifted
// once the association is up - otherwise SOCKS5 UDP would live exactly as
// long as the deadline, breaking DNS and QUIC through the proxy.
TEST(Socks5ServerTest, UdpAssociateOutlivesTheHandshakeDeadline) {
  const auto port = PickFreePort();
  auto config = MakeConfig(port);
  config.handshake_timeout = std::chrono::seconds(1);

  Socks5Server server(config);
  ASSERT_TRUE(server.Start());

  boost::asio::io_context ioc;
  Socks5Client client(ioc, port);
  ASSERT_TRUE(client.connected());
  ASSERT_EQ(client.Greet(kAuthNone), kAuthNone);
  ASSERT_EQ(client.UdpAssociate(), kRepSuccess);

  // Well past the deadline: the control connection has to stay open, because
  // it is what keeps the association alive.
  EXPECT_FALSE(client.WaitClosed(std::chrono::milliseconds(3000)));
  server.Stop();
}
