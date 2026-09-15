/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>

#include "fptn-client/status/server_registry.h"

namespace fptn::client::status {

// A local HTTP endpoint exposing the server pool and its latency.
//
// Before it the client had no machine-readable output at all: only log lines
// and the process exit code. A transparent proxy running the client as its
// helper could show neither the pool nor the latency - it had nowhere to read
// them from.
//
// The response shape follows the Clash API (sing-box, mihomo): dashboards and
// router-side tooling already parse that JSON, so nothing new has to be
// learned.
class StatusServer final {
 public:
  struct Options {
    std::string listen_address = "127.0.0.1";
    std::uint16_t listen_port = 0;
    // An empty secret means "no check", the same as sing-box does, but the
    // default listen address is the loopback so this cannot become a hole.
    std::string secret;
  };

  // On-demand probe: returns the latency in ms, 0 on failure.
  // NOLINTNEXTLINE(readability/casting) - a function type, not a C cast
  using DelayProbeSignature = std::uint32_t(const ServerInfo&, int);
  using DelayProbe = std::function<DelayProbeSignature>;
  // Switch to another server. true if the request was accepted.
  using SwitchServer = std::function<bool(const ServerInfo& server)>;
  // Tunnel and service state - everything only the client itself knows.
  using StatusProvider = std::function<nlohmann::json()>;

  StatusServer(Options options, std::shared_ptr<ServerRegistry> registry);
  ~StatusServer();

  StatusServer(const StatusServer&) = delete;
  StatusServer& operator=(const StatusServer&) = delete;

  void SetDelayProbe(DelayProbe probe);
  void SetSwitchServer(SwitchServer handler);
  void SetStatusProvider(StatusProvider provider);

  bool Start();
  void Stop();
  [[nodiscard]] bool IsRunning() const { return running_; }

 private:
  boost::asio::awaitable<void> AcceptLoop();
  boost::asio::awaitable<void> HandleConnection(
      boost::asio::ip::tcp::socket socket);

  struct Reply {
    unsigned status = 200;
    nlohmann::json body;
  };
  [[nodiscard]] Reply Route(const std::string& method,
      const std::string& target,
      const std::string& body) const;
  [[nodiscard]] Reply HandleDelay(
      const std::string& name, const std::string& query) const;
  [[nodiscard]] Reply HandleSwitch(
      const std::string& name, const std::string& body) const;
  [[nodiscard]] bool Authorized(const std::string& header) const;
  [[nodiscard]] bool HostAllowed(const std::string& host) const;

  const Options options_;
  const std::shared_ptr<ServerRegistry> registry_;

  // The callbacks are installed after Start(): the endpoint comes up before a
  // server is chosen, and the tunnel-facing ones only exist later. Requests
  // are already being served from the accept thread by then, so reads and
  // writes go through the mutex.
  mutable std::mutex callbacks_mutex_;
  DelayProbe delay_probe_;
  SwitchServer switch_server_;
  StatusProvider status_provider_;

  // More than one thread runs the context: an on-demand probe blocks the
  // thread it lands on for seconds, and the rest of the API has to keep
  // answering meanwhile - a supervising daemon reads an unresponsive endpoint
  // as a failed section.
  static constexpr int kThreads = 2;

  // Guards Start() and Stop() against each other and against themselves:
  // the destructor and an explicit Stop() can race, and a half-finished stop
  // would leave threads inside a context that is about to be destroyed.
  std::mutex lifecycle_mutex_;

  // Declared before the acceptor and the threads so that it outlives them:
  // suspended coroutine frames are destroyed with the context.
  boost::asio::io_context ioc_{kThreads};
  std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
  std::vector<std::thread> threads_;
  std::atomic<bool> running_{false};
};

}  // namespace fptn::client::status
