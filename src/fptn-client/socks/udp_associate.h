/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

#include "fptn-client/socks/socks5_server.h"

namespace fptn::socks {

// UDP ASSOCIATE (RFC 1928, sections 4 and 7). One association per control
// connection; datagrams are relayed through kernel sockets bound to the TUN
// address. FRAG != 0 is rejected.
class UdpAssociate {
 public:
  struct Config {
    std::string listen_address;
    std::string tun_address_ipv4;
    std::string tun_address_ipv6;
    std::chrono::seconds session_timeout{60};
    // Сокет на каждую цель: без потолка одна ассоциация с активным QUIC
    // способна съесть все дескрипторы процесса.
    std::size_t max_sessions = 128;
  };

  UdpAssociate(boost::asio::any_io_executor executor,
      Config config,
      TunnelResolver* resolver,
      std::uint64_t session_id);
  ~UdpAssociate();

  UdpAssociate(const UdpAssociate&) = delete;
  UdpAssociate& operator=(const UdpAssociate&) = delete;

  // On success BoundEndpoint() holds what to report as BND.ADDR/BND.PORT.
  bool Open(boost::system::error_code& ec);

  const boost::asio::ip::udp::endpoint& BoundEndpoint() const noexcept {
    return bound_;
  }

  // Returns when the relay socket fails - that is how the caller learns the
  // association ended.
  boost::asio::awaitable<void> Run();

  void Close();

 private:
  // Own socket per target, bound to the TUN address so the source port stays
  // stable for NAT on the far side.
  struct Session {
    boost::asio::ip::udp::socket socket;
    boost::asio::ip::udp::endpoint client;
    std::chrono::steady_clock::time_point last_used;
    bool receiving = false;
  };

  using Key = std::pair<boost::asio::ip::udp::endpoint,
      boost::asio::ip::udp::endpoint>;

  boost::asio::awaitable<void> HandleDatagram(
      const boost::asio::ip::udp::endpoint& from,
      const std::uint8_t* data,
      std::size_t size);

  boost::asio::awaitable<void> ReceiveLoop(Key key);

  Session* FindOrCreate(const Key& key,
      const boost::asio::ip::udp::endpoint& client,
      boost::system::error_code& ec);

  void SweepIdle();

  boost::asio::any_io_executor executor_;
  Config config_;
  TunnelResolver* resolver_;
  std::uint64_t session_id_;

  boost::asio::ip::udp::socket relay_;
  boost::asio::ip::udp::endpoint bound_;
  // Learned from the first datagram: clients announce zeroes in practice.
  boost::asio::ip::udp::endpoint client_;
  std::map<Key, std::unique_ptr<Session>> sessions_;
  bool closed_ = false;
};

}  // namespace fptn::socks
