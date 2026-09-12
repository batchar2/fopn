/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/https/censorship_strategy.h"
#include "fptn-protocol-lib/protocol/serializer_policy.h"

namespace fptn::protocol::https {

using IPv4Address = fptn::common::network::IPv4Address;
using IPv6Address = fptn::common::network::IPv6Address;

using OnIPRecvPacketCallback = std::function<void(
  fptn::common::network::IPPacketPtr packet)>;

using OnIPRecvBatchPacketCallback = std::function<void(
  fptn::common::network::BatchIPPacketPtr packets)>;

using OnConnectedCallback = std::function<void()>;

using OnSocketOpenedCallback = std::function<void(int socket_fd)>;

struct ConnectionConfig {
  struct Common {
    IPv4Address server_ip;
    std::uint16_t server_port = 443;

    std::string sni;
    std::string md5_fingerprint;
    std::string client_version;
    CensorshipStrategy censorship_strategy = CensorshipStrategy::kSni;

    // Auto resolves to the bandwidth-efficient Protobuf framing while keeping
    // YAFF available for deployments that explicitly prefer it.
    fptn::protocol::SerializerPolicy serializer_policy =
        fptn::protocol::SerializerPolicy::kAuto;

    // Shared across all websocket connections of a connection pool so the
    // server can multiplex them into one logical client (empty = the server
    // assigns a unique session, i.e. a standalone long-term connection).
    std::string session_id;

    // Pool scheduling advertised to the server (0 = unset). send_duration_ms is
    // how long this connection stays sending upstream before it becomes a
    // downstream receiver; ttl_ms is its total lifetime, after which the server
    // closes it.
    std::uint64_t send_duration_ms = 0;
    std::uint64_t ttl_ms = 0;

    IPv4Address tun_interface_address_ipv4;
    IPv6Address tun_interface_address_ipv6;

    std::size_t connection_timeout_ms = 10000;
    std::size_t max_reconnections = 5;

    // Hard memory budget for packets waiting to be written to the tunnel.
    std::size_t max_outbound_queue_bytes = 4U * 1024U * 1024U;

    OnConnectedCallback on_connected_callback = nullptr;
    OnIPRecvPacketCallback recv_ip_packet_callback = nullptr;
    OnIPRecvBatchPacketCallback recv_ip_packet_batch_callback = nullptr;
    OnSocketOpenedCallback on_socket_opened_callback = nullptr;
  } common;

  struct Pool {
    std::size_t size = 3;
  } pool;

  bool Validate() const {
    if (common.server_ip.IsEmpty() || pool.size == 0) {
      return false;
    }
    return true;
  }
};

}  // namespace fptn::protocol::https
