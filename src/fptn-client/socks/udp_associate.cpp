/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-client/socks/udp_associate.h"

#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/socket_options.h"

namespace fptn::socks {

namespace {

constexpr std::uint8_t kAtypIPv4 = 0x01;
constexpr std::uint8_t kAtypDomain = 0x03;
constexpr std::uint8_t kAtypIPv6 = 0x04;

// A datagram can be a full 64 KiB; anything larger is not a UDP payload.
constexpr std::size_t kBufferSize = 65535;
// Header is RSV(2) + FRAG(1) + ATYP(1) + shortest address + port.
constexpr std::size_t kMinHeaderSize = 4 + 4 + 2;

struct ParsedDatagram {
  boost::asio::ip::address address;
  std::string host;  // set instead of address for ATYP=domain
  std::uint16_t port = 0;
  const std::uint8_t* payload = nullptr;
  std::size_t payload_size = 0;
};

// Parses the SOCKS5 UDP request header (RFC 1928 section 7). Returns false on a
// malformed or fragmented datagram, which the caller drops silently - there is
// no error channel for UDP in the protocol.
bool ParseDatagram(
    const std::uint8_t* data, std::size_t size, ParsedDatagram& out) {
  if (size < kMinHeaderSize || data[0] != 0 || data[1] != 0) {
    return false;
  }
  if (data[2] != 0) {
    return false;  // fragmented, see the class comment
  }
  std::size_t offset = 4;
  switch (data[3]) {
    case kAtypIPv4: {
      if (size < offset + 4 + 2) {
        return false;
      }
      boost::asio::ip::address_v4::bytes_type bytes{};
      std::memcpy(bytes.data(), data + offset, bytes.size());
      out.address = boost::asio::ip::address_v4(bytes);
      offset += 4;
      break;
    }
    case kAtypIPv6: {
      if (size < offset + 16 + 2) {
        return false;
      }
      boost::asio::ip::address_v6::bytes_type bytes{};
      std::memcpy(bytes.data(), data + offset, bytes.size());
      out.address = boost::asio::ip::address_v6(bytes);
      offset += 16;
      break;
    }
    case kAtypDomain: {
      const std::size_t length = data[offset];
      if (length == 0 || size < offset + 1 + length + 2) {
        return false;
      }
      out.host.assign(reinterpret_cast<const char*>(data + offset + 1), length);
      offset += 1 + length;
      break;
    }
    default:
      return false;
  }
  out.port = static_cast<std::uint16_t>((data[offset] << 8) | data[offset + 1]);
  offset += 2;
  out.payload = data + offset;
  out.payload_size = size - offset;
  return true;
}

// Wraps a reply in the same header shape, addressed from where it came.
std::vector<std::uint8_t> WrapDatagram(
    const boost::asio::ip::udp::endpoint& from,
    const std::uint8_t* payload,
    std::size_t size) {
  std::vector<std::uint8_t> out;
  out.reserve(size + 22);
  out.insert(out.end(), {0x00, 0x00, 0x00});
  if (from.address().is_v4()) {
    const auto bytes = from.address().to_v4().to_bytes();
    out.push_back(kAtypIPv4);
    out.insert(out.end(), bytes.begin(), bytes.end());
  } else {
    const auto bytes = from.address().to_v6().to_bytes();
    out.push_back(kAtypIPv6);
    out.insert(out.end(), bytes.begin(), bytes.end());
  }
  out.push_back(static_cast<std::uint8_t>(from.port() >> 8));
  out.push_back(static_cast<std::uint8_t>(from.port() & 0xFF));
  out.insert(out.end(), payload, payload + size);
  return out;
}

}  // namespace

UdpAssociate::UdpAssociate(boost::asio::any_io_executor executor,
    Config config,
    TunnelResolver* resolver,
    std::uint64_t session_id)
    : executor_(std::move(executor)),
      config_(std::move(config)),
      resolver_(resolver),
      session_id_(session_id),
      relay_(executor_) {}

UdpAssociate::~UdpAssociate() { Close(); }

bool UdpAssociate::Open(boost::system::error_code& ec) {
  const auto address =
      boost::asio::ip::make_address(config_.listen_address, ec);
  if (ec) {
    return false;
  }
  relay_.open(address.is_v4() ? boost::asio::ip::udp::v4()
                              : boost::asio::ip::udp::v6(),
      ec);
  if (ec) {
    return false;
  }
  // Port 0: the kernel picks one and the client is told which in BND.PORT.
  relay_.bind(boost::asio::ip::udp::endpoint(address, 0), ec);
  if (ec) {
    return false;
  }
  bound_ = relay_.local_endpoint(ec);
  if (ec) {
    return false;
  }
  SPDLOG_DEBUG("SOCKS5[{}]: UDP relay listening on {}:{}", session_id_,
      bound_.address().to_string(), bound_.port());
  return true;
}

void UdpAssociate::Close() {
  if (closed_) {
    return;
  }
  closed_ = true;
  boost::system::error_code ec;
  relay_.close(ec);
  for (auto& [key, session] : sessions_) {
    session->socket.close(ec);
  }
  sessions_.clear();
}

boost::asio::awaitable<void> UdpAssociate::Run() {
  std::vector<std::uint8_t> buffer(kBufferSize);
  boost::system::error_code ec;
  for (;;) {
    boost::asio::ip::udp::endpoint from;
    const std::size_t size = co_await relay_.async_receive_from(
        boost::asio::buffer(buffer), from,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      break;
    }
    SweepIdle();
    co_await HandleDatagram(from, buffer.data(), size);
  }
}

boost::asio::awaitable<void> UdpAssociate::HandleDatagram(
    const boost::asio::ip::udp::endpoint& from,
    const std::uint8_t* data,
    std::size_t size) {
  // Only the client that opened the association may use it. The first datagram
  // decides who that is; the relay socket is bound to the loopback listen
  // address, so nothing outside the router can reach it in the meantime.
  if (client_.port() == 0) {
    client_ = from;
  } else if (from != client_) {
    SPDLOG_DEBUG("SOCKS5[{}]: dropping UDP from unexpected {}:{}", session_id_,
        from.address().to_string(), from.port());
    co_return;
  }

  ParsedDatagram parsed;
  if (!ParseDatagram(data, size, parsed)) {
    SPDLOG_DEBUG("SOCKS5[{}]: malformed or fragmented UDP datagram dropped",
        session_id_);
    co_return;
  }

  if (!parsed.host.empty()) {
    // Same reason as the TCP path: the system resolver hands out FakeIP.
    const auto resolved = co_await resolver_->Resolve(parsed.host);
    if (resolved.empty()) {
      SPDLOG_DEBUG("SOCKS5[{}]: cannot resolve '{}' for UDP", session_id_,
          parsed.host);
      co_return;
    }
    parsed.address = resolved.front();
  }

  const boost::asio::ip::udp::endpoint target(parsed.address, parsed.port);
  const Key key{from, target};
  boost::system::error_code ec;
  Session* session = FindOrCreate(key, from, ec);
  if (session == nullptr) {
    SPDLOG_DEBUG("SOCKS5[{}]: UDP socket for {}:{} failed: {}", session_id_,
        target.address().to_string(), target.port(), ec.message());
    co_return;
  }

  co_await session->socket.async_send_to(
      boost::asio::buffer(parsed.payload, parsed.payload_size), target,
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec) {
    SPDLOG_DEBUG("SOCKS5[{}]: UDP send to {}:{} failed: {}", session_id_,
        target.address().to_string(), target.port(), ec.message());
  }
}

UdpAssociate::Session* UdpAssociate::FindOrCreate(const Key& key,
    const boost::asio::ip::udp::endpoint& client,
    boost::system::error_code& ec) {
  const auto known = sessions_.find(key);
  if (known == sessions_.end() && sessions_.size() >= config_.max_sessions) {
    // Сначала убираем то, что уже простаивает: обычно этого хватает, и отказ
    // достаётся только по-настоящему активному всплеску.
    SweepIdle();
    if (sessions_.size() >= config_.max_sessions) {
      SPDLOG_WARN("UDP[{}]: session limit {} reached, dropping datagram",
          session_id_, config_.max_sessions);
      ec = boost::asio::error::no_descriptors;
      return nullptr;
    }
  }

  if (const auto it = sessions_.find(key); it != sessions_.end()) {
    it->second->last_used = std::chrono::steady_clock::now();
    return it->second.get();
  }

  const auto& target = key.second;
  auto session = std::make_unique<Session>(
      Session{boost::asio::ip::udp::socket(executor_), client,
          std::chrono::steady_clock::now(), false});
  session->socket.open(target.protocol(), ec);
  if (ec) {
    return nullptr;
  }
  fptn::protocol::https::ApplyRoutingMark(session->socket.native_handle());

  const std::string& bind_ip = target.address().is_v4()
                                   ? config_.tun_address_ipv4
                                   : config_.tun_address_ipv6;
  if (!bind_ip.empty()) {
    boost::system::error_code addr_ec;
    const auto bind_addr = boost::asio::ip::make_address(bind_ip, addr_ec);
    if (!addr_ec) {
      session->socket.bind(
          boost::asio::ip::udp::endpoint(bind_addr, 0), ec);
      if (ec) {
        return nullptr;
      }
    }
  }

  auto* raw = session.get();
  sessions_.emplace(key, std::move(session));
  raw->receiving = true;
  boost::asio::co_spawn(
      executor_,
      [this, key]() -> boost::asio::awaitable<void> {
        co_await ReceiveLoop(key);
      },
      boost::asio::detached);
  return raw;
}

boost::asio::awaitable<void> UdpAssociate::ReceiveLoop(Key key) {
  std::vector<std::uint8_t> buffer(kBufferSize);
  for (;;) {
    const auto it = sessions_.find(key);
    if (it == sessions_.end() || closed_) {
      break;
    }
    Session* session = it->second.get();

    boost::system::error_code ec;
    boost::asio::ip::udp::endpoint from;
    const std::size_t size = co_await session->socket.async_receive_from(
        boost::asio::buffer(buffer), from,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      break;
    }
    // The map may have been swept while awaiting; re-check before touching it.
    const auto still = sessions_.find(key);
    if (still == sessions_.end() || closed_) {
      break;
    }
    still->second->last_used = std::chrono::steady_clock::now();

    const auto wrapped = WrapDatagram(from, buffer.data(), size);
    co_await relay_.async_send_to(boost::asio::buffer(wrapped),
        still->second->client,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      break;
    }
  }
}

void UdpAssociate::SweepIdle() {
  const auto now = std::chrono::steady_clock::now();
  for (auto it = sessions_.begin(); it != sessions_.end();) {
    if (now - it->second->last_used > config_.session_timeout) {
      boost::system::error_code ec;
      it->second->socket.close(ec);
      it = sessions_.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace fptn::socks
