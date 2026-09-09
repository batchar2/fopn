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
    // Запрос уходит внутрь тоннеля, поэтому промах кэша стоит целого круга до
    // резолвера. Ответ живёт по своему TTL, зажатому в эти границы.
    std::chrono::seconds min_ttl{10};
    std::chrono::seconds max_ttl{600};
    std::size_t max_cache_entries = 512;
    // Датаграмма теряется тихо, поэтому одну потерю переживаем повтором.
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
    // Пустой ответ и молчание резолвера - разные вещи: первый кэшируем,
    // второй заставляет пробовать снова.
    bool answered = false;
    bool truncated = false;
  };

  struct CacheEntry {
    std::vector<boost::asio::ip::address> addresses;
    std::chrono::steady_clock::time_point expires_at;
  };

  // Транспорт значения не имеет: разбирается уже принятое сообщение.
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
  // Один и тот же обрыв связи повторяется на каждом соединении; в лог он
  // попадает по разу на переход состояния.
  void ReportReachable(bool reachable, const std::string& host);

  Config config_;
  // Резолвер живёт только в потоке io_context сервера, поэтому без блокировок.
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
    // Дескрипторов на сессию уходит два, и на роутере их немного: за потолком
    // сервер отказывает клиенту, а не упирается в EMFILE.
    std::size_t max_sessions = 512;
    // Простаивающая сессия держит оба дескриптора до конца жизни процесса,
    // если её не закрыть.
    std::chrono::seconds idle_timeout{300};
  };

  explicit Socks5Server(Config config);
  ~Socks5Server();

  Socks5Server(const Socks5Server&) = delete;
  Socks5Server& operator=(const Socks5Server&) = delete;

  // Порт открывается отдельно от обслуживания: ZeroBlock ждёт готовности
  // помощника считаные секунды, а логин-гонка по нескольким десяткам серверов
  // занимает до минуты. Listen() поднимает слушающий сокет сразу, соединения
  // копятся в backlog ядра, а Serve() начинает их разбирать, когда туннель
  // готов и адреса известны.
  bool Listen();
  void SetTunnel(const std::string& tun_address_ipv4,
      const std::string& tun_address_ipv6,
      const std::string& dns_server_ipv4);
  bool Serve();
  // Listen() + Serve() одним вызовом, для случая, когда ждать нечего.
  bool Start();
  void Stop();
  bool IsRunning() const noexcept { return running_.load(); }

 private:
  boost::asio::awaitable<void> AcceptLoop();
  boost::asio::awaitable<void> HandleSession(
      boost::asio::ip::tcp::socket client);
  // Каждое чтение отодвигает таймер простоя; когда он всё-таки срабатывает,
  // WatchIdle закрывает обе стороны и релей завершается сам.
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
