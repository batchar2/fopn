/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>


namespace fptn::socks {

class PolicyRoute {
 public:
  struct Config {
    std::string tun_interface_name;
    std::string tun_address_ipv4;
    std::string tun_address_ipv6;
    std::uint32_t table_id = 100;
    std::uint32_t rule_priority = 10000;
  };

  explicit PolicyRoute(Config config);
  ~PolicyRoute();

  PolicyRoute(const PolicyRoute&) = delete;
  PolicyRoute& operator=(const PolicyRoute&) = delete;

  // Idempotent: removes leftovers from a previous run before adding.
  bool Apply();
  void Clean();

 private:
  Config config_;
  bool applied_ = false;
};

class TunnelResolver {
 public:
  struct Config {
    std::string dns_server_ipv4;
    std::string bind_address_ipv4;
    int timeout_ms = 4000;
    // The query travels inside the tunnel, so a cache miss costs a full round
    // trip to the resolver. An answer lives for its own TTL, clamped to these
    // bounds.
    std::chrono::seconds min_ttl{10};
    std::chrono::seconds max_ttl{600};
    std::size_t max_cache_entries = 512;
    // A datagram is lost silently, so one loss is covered by a retry.
    int attempts = 2;
  };

  explicit TunnelResolver(Config config);

  // An empty result means the name could not be resolved.
  // A is tried first, AAAA on failure.
  boost::asio::awaitable<std::vector<boost::asio::ip::address>> Resolve(
      std::string host);

 private:
  struct Answer {
    std::vector<boost::asio::ip::address> addresses;
    std::chrono::seconds ttl{0};
    // An empty answer and a silent resolver are different things: the first
    // is cached, the second makes us try again.
    bool answered = false;
    bool truncated = false;
  };

  struct CacheEntry {
    std::vector<boost::asio::ip::address> addresses;
    std::chrono::steady_clock::time_point expires_at;
  };

  // The transport does not matter: an already received message is parsed.
  static Answer ParseResponse(const std::uint8_t* data, std::size_t size,
      std::uint16_t query_id, const std::string& host);

  boost::asio::awaitable<Answer> Query(
      const std::string& host, std::uint16_t qtype);
  boost::asio::awaitable<Answer> QueryOverUdp(
      const std::string& host, std::uint16_t qtype);
  boost::asio::awaitable<Answer> QueryOverTcp(
      const std::string& host, std::uint16_t qtype);

  bool LookupCache(
      const std::string& host, std::vector<boost::asio::ip::address>* out);
  void StoreCache(const std::string& host,
      const std::vector<boost::asio::ip::address>& addresses,
      std::chrono::seconds ttl);
  // The same outage repeats on every connection; it reaches the log once per
  // state change.
  void ReportReachable(bool reachable, const std::string& host);

  Config config_;
  // The resolver lives only on the server io_context thread, so no locking.
  std::unordered_map<std::string, CacheEntry> cache_;
  bool dns_unreachable_ = false;
};

// SOCKS5 entry point for coexistence with a transparent proxy in front of the
// client. CONNECT and UDP ASSOCIATE, so QUIC and plain UDP traverse it too;
// see udp_associate.h for how datagrams are relayed.
class Socks5Server {
 public:
  struct Config {
    std::string listen_address = "127.0.0.1";
    std::uint16_t listen_port = 1080;
    std::string tun_interface_name;
    std::string tun_address_ipv4;
    std::string tun_address_ipv6;
    std::string dns_server_ipv4;
    int connect_timeout_ms = 10000;
    // A session costs two descriptors, and a router has few: past the cap the
    // server refuses the client instead of hitting EMFILE.
    std::size_t max_sessions = 512;
    // An idle session holds both descriptors for the life of the process
    // unless it is closed.
    std::chrono::seconds idle_timeout{300};
    // How long a client may take to finish the handshake. Configurable so a
    // test does not have to wait out the production value.
    std::chrono::seconds handshake_timeout{15};
  };

  explicit Socks5Server(Config config);
  ~Socks5Server();

  Socks5Server(const Socks5Server&) = delete;
  Socks5Server& operator=(const Socks5Server&) = delete;

  // Opening the port is separate from serving it: ZeroBlock waits only
  // seconds for the helper to become ready, while a login race across dozens
  // of servers takes up to a minute. Listen() brings the listening socket up
  // at once so connections queue in the kernel backlog, and Serve() starts
  // handling them when the tunnel is ready and the addresses are known.
  bool Listen();
  void SetTunnel(const std::string& tun_address_ipv4,
      const std::string& tun_address_ipv6,
      const std::string& dns_server_ipv4);
  bool Serve();
  // Listen() + Serve() in one call, for when there is nothing to wait for.
  bool Start();
  void Stop();
  bool IsRunning() const noexcept { return running_.load(); }
  // The counters were already kept to refuse on overflow, but never exposed.
  std::size_t ActiveSessions() const noexcept {
    return active_sessions_.load();
  }
  std::uint64_t TotalSessions() const noexcept {
    return session_counter_.load();
  }
  std::size_t MaxSessions() const noexcept { return config_.max_sessions; }

 private:
  boost::asio::awaitable<void> AcceptLoop();
  boost::asio::awaitable<void> HandleSession(
      boost::asio::ip::tcp::socket client);
  // Every read pushes the idle timer back; when it does fire, WatchIdle
  // closes both sides and the relay ends on its own.
  boost::asio::awaitable<void> Relay(boost::asio::ip::tcp::socket& from,
      boost::asio::ip::tcp::socket& to,
      boost::asio::steady_timer& idle);
  boost::asio::awaitable<void> WatchIdle(boost::asio::steady_timer& idle,
      boost::asio::ip::tcp::socket& client,
      boost::asio::ip::tcp::socket& remote);
  boost::asio::awaitable<void> HandleUdpAssociate(
      boost::asio::ip::tcp::socket& client, std::uint64_t session_id);
  boost::asio::awaitable<void> WaitForClose(
      boost::asio::ip::tcp::socket& client);

  Config config_;
  boost::asio::io_context ioc_;
  std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
  std::unique_ptr<TunnelResolver> resolver_;
  std::thread thread_;
  std::atomic<bool> running_{false};
  std::atomic<std::uint64_t> session_counter_{0};
  std::atomic<std::size_t> active_sessions_{0};
};

using Socks5ServerPtr = std::unique_ptr<Socks5Server>;

}  // namespace fptn::socks
