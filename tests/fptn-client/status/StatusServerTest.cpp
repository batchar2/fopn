/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <chrono>
#include <memory>
#include <string>
#include <thread>

#include <boost/asio.hpp>
#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "status/server_registry.h"
#include "status/status_server.h"

namespace {

using fptn::client::status::ServerRegistry;
using fptn::client::status::StatusServer;
using boost::asio::ip::tcp;

StatusServer::Options MakeOptions(const std::string& address,
    std::uint16_t port,
    const std::string& secret) {
  StatusServer::Options options;
  options.listen_address = address;
  options.listen_port = port;
  options.secret = secret;
  return options;
}

// A port nothing else holds right now. Binding and closing leaves a short
// window where another process could take it, which is why a failure to
// connect later is reported rather than retried forever.
std::uint16_t FreePort() {
  boost::asio::io_context ioc;
  tcp::acceptor probe(ioc, tcp::endpoint(tcp::v4(), 0));
  const auto port = probe.local_endpoint().port();
  probe.close();
  return port;
}

// Sends one raw request and returns everything up to the end of the headers,
// empty on failure. The status line is the first line of it.
std::string Request(std::uint16_t port,
    const std::string& target,
    const std::string& host_header,
    const std::string& authorization,
    const std::string& method = "GET",
    const std::string& extra_headers = "") {
  try {
    boost::asio::io_context ioc;
    tcp::socket socket(ioc);
    socket.connect(tcp::endpoint(
        boost::asio::ip::make_address("127.0.0.1"), port));

    std::string request = method + " " + target + " HTTP/1.1\r\n";
    request += "Host: " + host_header + "\r\n";
    if (!authorization.empty()) {
      request += "Authorization: " + authorization + "\r\n";
    }
    request += extra_headers;
    request += "Connection: close\r\n\r\n";
    boost::asio::write(socket, boost::asio::buffer(request));

    std::string response;
    boost::system::error_code ec;
    char buffer[1024];
    while (true) {
      const auto read = socket.read_some(boost::asio::buffer(buffer), ec);
      if (ec) {
        break;
      }
      response.append(buffer, read);
      if (response.find("\r\n\r\n") != std::string::npos) {
        break;
      }
    }
    const auto end = response.find("\r\n\r\n");
    return end == std::string::npos ? response : response.substr(0, end);
  } catch (const std::exception&) {
    return {};
  }
}

std::string StatusLine(const std::string& response) {
  const auto end = response.find("\r\n");
  return end == std::string::npos ? response : response.substr(0, end);
}

struct Server {
  std::shared_ptr<ServerRegistry> registry = std::make_shared<ServerRegistry>();
  std::unique_ptr<StatusServer> server;
  std::uint16_t port = 0;

  Server() = default;
  // Declaring the destructor takes the implicit move with it, and the handle
  // has to leave the factory somehow.
  Server(Server&&) = default;
  Server& operator=(Server&&) = default;
  Server(const Server&) = delete;
  Server& operator=(const Server&) = delete;

  ~Server() {
    if (server) {
      server->Stop();
    }
  }
};

Server Start(const std::string& address, const std::string& secret) {
  Server started;
  started.port = FreePort();
  started.server = std::make_unique<StatusServer>(
      MakeOptions(address, started.port, secret), started.registry);
  if (!started.server->Start()) {
    started.server.reset();
    return started;
  }
  // Start() returns once the acceptor is listening, so a connection cannot be
  // refused - but the worker threads still need a moment to reach the loop.
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  return started;
}

}  // namespace

// The endpoint hands out the server pool and accepts a switch request, so off
// the loopback the secret is the only thing in front of it.
// cppcheck-suppress syntaxError
TEST(StatusServerTest, RefusesToListenOffLoopbackWithoutSecret) {
  auto started = Start("0.0.0.0", "");
  EXPECT_EQ(started.server, nullptr) << "came up wide open on the wildcard";
}

TEST(StatusServerTest, ListensOffLoopbackWhenSecretIsSet) {
  auto started = Start("0.0.0.0", "s3cret");
  ASSERT_NE(started.server, nullptr);
  EXPECT_TRUE(started.server->IsRunning());
}

TEST(StatusServerTest, ListensOnLoopbackWithoutSecret) {
  auto started = Start("127.0.0.1", "");
  ASSERT_NE(started.server, nullptr);
  EXPECT_TRUE(started.server->IsRunning());
}

// The Host check guards an endpoint that asks for nothing: a page whose domain
// resolves to the loopback must not reach it as its own origin.
TEST(StatusServerTest, RejectsForeignHostWhenThereIsNoSecret) {
  auto started = Start("127.0.0.1", "");
  ASSERT_NE(started.server, nullptr);

  const auto allowed =
      StatusLine(Request(started.port, "/version", "127.0.0.1", ""));
  ASSERT_FALSE(allowed.empty()) << "no answer at all";
  EXPECT_NE(allowed.find("200"), std::string::npos) << allowed;

  const auto rebound =
      StatusLine(Request(started.port, "/version", "evil.example", ""));
  EXPECT_EQ(rebound.find("200"), std::string::npos) << rebound;
}

// With a secret the same check only gets in the way: an endpoint bound to a
// LAN address is reached by whatever name the caller used, and the token is
// what decides.
TEST(StatusServerTest, AcceptsForeignHostWhenSecretIsSet) {
  auto started = Start("127.0.0.1", "s3cret");
  ASSERT_NE(started.server, nullptr);

  const auto answer = StatusLine(Request(
      started.port, "/version", "router.lan:9091", "Bearer s3cret"));
  ASSERT_FALSE(answer.empty()) << "no answer at all";
  EXPECT_NE(answer.find("200"), std::string::npos) << answer;
}

TEST(StatusServerTest, RejectsWrongAndMissingToken) {
  auto started = Start("127.0.0.1", "s3cret");
  ASSERT_NE(started.server, nullptr);

  const auto wrong = StatusLine(
      Request(started.port, "/version", "127.0.0.1", "Bearer nope"));
  EXPECT_NE(wrong.find("401"), std::string::npos) << wrong;

  const auto missing =
      StatusLine(Request(started.port, "/version", "127.0.0.1", ""));
  EXPECT_NE(missing.find("401"), std::string::npos) << missing;

  // A token of the right length must not pass either - the comparison runs to
  // the end, it does not stop at the first mismatch.
  const auto same_length = StatusLine(
      Request(started.port, "/version", "127.0.0.1", "Bearer s3crXt"));
  EXPECT_NE(same_length.find("401"), std::string::npos) << same_length;
}

TEST(StatusServerTest, AcceptsTheRightToken) {
  auto started = Start("127.0.0.1", "s3cret");
  ASSERT_NE(started.server, nullptr);

  const auto answer = StatusLine(
      Request(started.port, "/version", "127.0.0.1", "Bearer s3cret"));
  EXPECT_NE(answer.find("200"), std::string::npos) << answer;
}

// A dashboard served from another origin has to be able to read the answer,
// and the preflight has to pass before it ever gets there. Withholding the
// header kept browsers out entirely without keeping anyone honest: the token
// is what decides.
TEST(StatusServerTest, SendsCorsHeaderEvenWithASecret) {
  auto started = Start("127.0.0.1", "s3cret");
  ASSERT_NE(started.server, nullptr);

  const auto answer =
      Request(started.port, "/version", "127.0.0.1", "Bearer s3cret");
  EXPECT_NE(answer.find("Access-Control-Allow-Origin: *"), std::string::npos)
      << answer;

  // Even the refusal carries it - otherwise the browser reports a CORS error
  // instead of the 401 that actually happened.
  const auto refused =
      Request(started.port, "/version", "127.0.0.1", "Bearer nope");
  EXPECT_NE(refused.find("Access-Control-Allow-Origin: *"), std::string::npos)
      << refused;
}

TEST(StatusServerTest, PreflightPassesWithASecret) {
  auto started = Start("127.0.0.1", "s3cret");
  ASSERT_NE(started.server, nullptr);

  // A preflight never carries Authorization, so it has to be answered before
  // the token is checked.
  const auto answer = Request(started.port, "/proxies", "127.0.0.1", "",
      "OPTIONS",
      "Access-Control-Request-Method: PUT\r\n"
      "Access-Control-Request-Headers: authorization\r\n");
  EXPECT_NE(StatusLine(answer).find("204"), std::string::npos) << answer;
  EXPECT_NE(answer.find("Access-Control-Allow-Origin: *"), std::string::npos)
      << answer;
  EXPECT_NE(answer.find("Authorization"), std::string::npos) << answer;
}

// Chrome asks before letting a page on a public origin reach a private
// address. Saying yes is sound only while the token is what decides.
TEST(StatusServerTest, AnswersPrivateNetworkPreflightOnlyWithASecret) {
  const std::string preflight =
      "Access-Control-Request-Method: GET\r\n"
      "Access-Control-Request-Private-Network: true\r\n";

  auto guarded = Start("127.0.0.1", "s3cret");
  ASSERT_NE(guarded.server, nullptr);
  const auto allowed = Request(
      guarded.port, "/proxies", "127.0.0.1", "", "OPTIONS", preflight);
  EXPECT_NE(allowed.find("Access-Control-Allow-Private-Network: true"),
      std::string::npos)
      << allowed;
  guarded.server->Stop();

  auto open = Start("127.0.0.1", "");
  ASSERT_NE(open.server, nullptr);
  const auto refused =
      Request(open.port, "/proxies", "127.0.0.1", "", "OPTIONS", preflight);
  EXPECT_EQ(refused.find("Access-Control-Allow-Private-Network"),
      std::string::npos)
      << refused;
}
