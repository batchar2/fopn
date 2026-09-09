/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#if _WIN32
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#endif

#ifdef FPTN_WITH_LIBIDN2
#include <idn2.h>
#endif

#ifdef USING_MIMALLOC
#include <mimalloc.h>
#endif

#include <spdlog/spdlog.h>

#include "common/client_id.h"
#include "common/network/ip_address.h"
#include "common/network/ip_utils.h"
#include "common/utils/utils.h"

namespace fptn::common::network {

#ifdef USING_MIMALLOC
using IPPacketData = std::vector<std::uint8_t, mi_stl_allocator<std::uint8_t>>;
#else
using IPPacketData = std::vector<std::uint8_t>;
#endif

#define FPTN_PACKET_UNDEFINED_CLIENT_ID MAX_CLIENT_ID

namespace detail {

inline constexpr std::size_t kMinIPv4 = 20;
inline constexpr std::size_t kMinIPv6 = 40;
inline constexpr std::size_t kUdpHdr = 8;
inline constexpr std::size_t kDnsHdr = 12;

inline int Ipv4Ihl(const std::uint8_t* p) noexcept {
  return (p[0] & 0x0Fu) * 4;
}

inline std::uint8_t Ipv4Proto(const std::uint8_t* p) noexcept { return p[9]; }

inline std::uint8_t& Ipv4Ttl(std::uint8_t* p) noexcept { return p[8]; }

inline std::uint8_t Ipv6Next(const std::uint8_t* p) noexcept { return p[6]; }

inline const std::uint8_t* DnsPayloadPtr(
    const std::uint8_t* udp, const std::uint8_t* end) noexcept {
  if (udp + kUdpHdr > end) {
    return nullptr;
  }
  if (ReadU16Be(udp) != 53 && ReadU16Be(udp + 2) != 53) {
    return nullptr;
  }
  const std::uint8_t* dns = udp + kUdpHdr;
  return (dns + kDnsHdr <= end) ? dns : nullptr;
}

// Parses a DNS name at *cur with pointer-compression support (RFC 1035).
// Advances *cur past the uncompressed portion.
inline std::string ParseDnsName(const std::uint8_t* base,
    const std::uint8_t* end,
    const std::uint8_t*& cur) noexcept {
  std::string name;
  bool jumped = false;
  const std::uint8_t* ptr = cur;
  for (int i = 0; i < 128 && ptr < end; ++i) {
    const std::uint8_t len = *ptr;
    if (len == 0u) {
      if (!jumped) cur = ptr + 1;
      break;
    }
    if ((len & 0xC0u) == 0xC0u) {
      if (end - ptr < 2) {
        break;
      }
      if (!jumped) {
        cur = ptr + 2;
      }
      jumped = true;
      const std::size_t offset =
          (static_cast<std::size_t>(len & 0x3Fu) << 8) | ptr[1];
      if (offset >= static_cast<std::size_t>(end - base)) {
        break;
      }
      ptr = base + offset;
      continue;
    }
    ++ptr;
    if (static_cast<std::size_t>(end - ptr) < len) {
      break;
    }
    if (!name.empty()) {
      name += '.';
    }
    name.append(reinterpret_cast<const char*>(ptr), len);
    ptr += len;
  }
  return name;
}

template <typename Byte>
inline bool SkipDnsName(Byte*& cur, const std::uint8_t* end) noexcept {
  for (int i = 0; i < 256 && cur < end; ++i) {
    const std::uint8_t len = *cur;
    if (len == 0u) {
      ++cur;
      return true;
    }
    const bool compressed = (len & 0xC0u) == 0xC0u;
    const std::size_t step = compressed ? 2u : 1u + len;
    if (static_cast<std::size_t>(end - cur) < step) {
      return false;
    }
    cur += step;
    if (compressed) {
      return true;
    }
  }
  return false;
}

inline const std::uint8_t* DnsAnswerStart(const std::uint8_t* dns,
    const std::uint8_t* end,
    int* out_ancount) noexcept {
  if (dns + kDnsHdr > end) {
    return nullptr;
  }
  if ((dns[2] & 0x80u) == 0u) {
    return nullptr;
  }
  const int qdcount = static_cast<int>(ReadU16Be(dns + 4));
  *out_ancount = static_cast<int>(ReadU16Be(dns + 6));
  if (*out_ancount == 0) {
    return nullptr;
  }

  const std::uint8_t* cur = dns + kDnsHdr;
  for (int q = 0; q < qdcount && cur < end; ++q) {
    if (!SkipDnsName(cur, end) || end - cur < 4) {
      return nullptr;
    }
    cur += 4;  // QTYPE + QCLASS
  }
  return (cur < end) ? cur : nullptr;
}

#ifdef FPTN_WITH_LIBIDN2
inline bool IsPunycode(const std::string& s) noexcept {
  return s.find("xn--") != std::string::npos;
}
inline std::string ToUnicode(const std::string& domain) noexcept {
  char* r = nullptr;
  if (idn2_to_unicode_8z8z(domain.c_str(), &r, 0) == IDN2_OK && r) {
    std::string out = r;
    free(r);
    return out;
  }
  if (r) free(r);
  return domain;
}
#endif

}  // namespace detail

class IPPacket {
 public:
  static std::unique_ptr<IPPacket> Parse(IPPacketData buffer,
      fptn::ClientID client_id = FPTN_PACKET_UNDEFINED_CLIENT_ID) {
    const std::size_t sz = buffer.size();
    if (sz < detail::kMinIPv4) {
      return nullptr;
    }
    const std::uint8_t ver = buffer[0] >> 4;
    if (ver == 4 || (ver == 6 && sz >= detail::kMinIPv6)) {
      return std::make_unique<IPPacket>(std::move(buffer), client_id);
    }
    return nullptr;
  }

  static std::unique_ptr<IPPacket> Parse(
      const std::uint8_t* buf, std::size_t sz) {
    if (!buf || sz == 0) {
      return nullptr;
    }
    IPPacketData packet(buf, buf + sz);
    return Parse(std::move(packet));
  }

  IPPacket(IPPacketData data, fptn::ClientID client_id)
      : data_(std::move(data)), client_id_(client_id) {}

  virtual ~IPPacket() = default;

  void ComputeCalculateFields() noexcept {
    if (data_.size() < detail::kMinIPv4) {
      return;
    }
    RecalculateChecksums(data_.data(), data_.size());
  }

  fptn::ClientID ClientId() const noexcept { return client_id_; }
  void SetClientId(fptn::ClientID id) noexcept { client_id_ = id; }

  virtual bool IsIPv4() const noexcept {
    return !data_.empty() && (data_[0] >> 4) == 4;
  }
  virtual bool IsIPv6() const noexcept {
    return !data_.empty() && (data_[0] >> 4) == 6;
  }

  std::size_t Size() const noexcept { return data_.size(); }
  const IPPacketData& Data() const noexcept { return data_; }
  // const IPPacket* GetRawPacket() const noexcept { return this; }

  IPv4Address GetSrcIPv4Address() const noexcept {
    if (!IsIPv4() || data_.size() < detail::kMinIPv4) {
      return {};
    }
    const std::uint32_t addr = ntohl(Ipv4GetSrc(data_.data()));
    return IPv4Address(addr);
  }

  IPv4Address GetDstIPv4Address() const noexcept {
    if (!IsIPv4() || data_.size() < detail::kMinIPv4) {
      return {};
    }
    const std::uint32_t addr = ntohl(Ipv4GetDst(data_.data()));
    return IPv4Address(addr);
  }

  IPv6Address GetSrcIPv6Address() const noexcept {
    if (!IsIPv6() || data_.size() < detail::kMinIPv6) {
      return {};
    }
    IPv6Address::Bytes addr{};
    Ipv6GetSrc(data_.data(), addr.data());
    return IPv6Address(addr);
  }

  IPv6Address GetDstIPv6Address() const noexcept {
    if (!IsIPv6() || data_.size() < detail::kMinIPv6) {
      return {};
    }
    IPv6Address::Bytes addr{};
    Ipv6GetDst(data_.data(), addr.data());
    return IPv6Address(addr);
  }

  void SetDstIPv4Address(const IPv4Address& dst) noexcept {
    if (!IsIPv4() || data_.size() < detail::kMinIPv4) {
      return;
    }
    std::uint8_t* p = data_.data();

    if (detail::Ipv4Ttl(p) == 0) {
      return;
    }

    const std::uint32_t addr = htonl(dst.ToInt());
    Ipv4SetDst(p, addr);
    RecalculateChecksums(p, data_.size());
  }

  void SetSrcIPv4Address(const IPv4Address& src) noexcept {
    if (!IsIPv4() || data_.size() < detail::kMinIPv4) {
      return;
    }
    std::uint8_t* p = data_.data();
    if (detail::Ipv4Ttl(p) == 0) {
      return;
    }
    const std::uint32_t addr = htonl(src.ToInt());
    Ipv4SetSrc(p, addr);
    RecalculateChecksums(p, data_.size());
  }

  void SetDstIPv6Address(const IPv6Address& dst) noexcept {
    if (!IsIPv6() || data_.size() < detail::kMinIPv6) {
      return;
    }
    if (!dst.IsValid()) {
      return;
    }
    const IPv6Address::Bytes addr = dst.ToBytes();
    Ipv6SetDst(data_.data(), addr.data());
    RecalculateChecksums(data_.data(), data_.size());
  }

  void SetSrcIPv6Address(const IPv6Address& src) noexcept {
    if (!IsIPv6() || data_.size() < detail::kMinIPv6) {
      return;
    }
    if (!src.IsValid()) {
      return;
    }
    const IPv6Address::Bytes addr = src.ToBytes();
    Ipv6SetSrc(data_.data(), addr.data());
    RecalculateChecksums(data_.data(), data_.size());
  }

  bool IsICMPv4() const noexcept {
    return IsIPv4() && data_.size() >= detail::kMinIPv4 &&
           detail::Ipv4Proto(data_.data()) == 1u;
  }
  bool IsICMPv6() const noexcept {
    return IsIPv6() && data_.size() >= detail::kMinIPv6 &&
           detail::Ipv6Next(data_.data()) == 58u;
  }

  bool IsTCP() const noexcept {
    if (IsIPv4()) {
      return data_.size() >= detail::kMinIPv4 &&
             detail::Ipv4Proto(data_.data()) == 6u;
    }
    if (IsIPv6()) {
      return data_.size() >= detail::kMinIPv6 &&
             detail::Ipv6Next(data_.data()) == 6u;
    }
    return false;
  }

  std::uint16_t GetTcpSrcPort() const noexcept {
    const std::uint8_t* p = data_.data();
    const std::size_t ip_hdr = IsIPv4() ? detail::Ipv4Ihl(p) : detail::kMinIPv6;
    if (data_.size() < ip_hdr + 2) {
      return 0;
    }
    return ReadU16Be(p + ip_hdr);
  }

  std::uint16_t GetTcpDstPort() const noexcept {
    const std::uint8_t* p = data_.data();
    const std::size_t ip_hdr = IsIPv4() ? detail::Ipv4Ihl(p) : detail::kMinIPv6;
    if (data_.size() < ip_hdr + 4) {
      return 0;
    }
    return ReadU16Be(p + ip_hdr + 2);
  }

  bool IsUDP() const noexcept {
    if (IsIPv4()) {
      return data_.size() >= detail::kMinIPv4 &&
             detail::Ipv4Proto(data_.data()) == 17u;
    }
    if (IsIPv6()) {
      return data_.size() >= detail::kMinIPv6 &&
             detail::Ipv6Next(data_.data()) == 17u;
    }
    return false;
  }

  std::uint16_t GetUdpSrcPort() const noexcept {
    const std::uint8_t* p = data_.data();
    const std::size_t ip_hdr = IsIPv4() ? detail::Ipv4Ihl(p) : detail::kMinIPv6;
    if (data_.size() < ip_hdr + 2) {
      return 0;
    }
    return ReadU16Be(p + ip_hdr);
  }

  std::uint16_t GetUdpDstPort() const noexcept {
    const std::uint8_t* p = data_.data();
    const std::size_t ip_hdr = IsIPv4() ? detail::Ipv4Ihl(p) : detail::kMinIPv6;
    if (data_.size() < ip_hdr + 4) {
      return 0;
    }
    return ReadU16Be(p + ip_hdr + 2);
  }

  std::pair<const std::uint8_t*, std::size_t> GetTcpPayload() const noexcept {
    const std::uint8_t* p = data_.data();
    const std::uint8_t proto =
        IsIPv4() ? detail::Ipv4Proto(p) : detail::Ipv6Next(p);
    if (proto != 6u) {
      return {nullptr, 0};
    }
    const std::size_t ip_hdr = IsIPv4() ? detail::Ipv4Ihl(p) : detail::kMinIPv6;
    if (data_.size() < ip_hdr + 20) {
      return {nullptr, 0};
    }
    const std::uint8_t* tcp = p + ip_hdr;
    const std::size_t tcp_hdr = (tcp[12] >> 4) * 4;
    if (data_.size() < ip_hdr + tcp_hdr) {
      return {nullptr, 0};
    }
    return {tcp + tcp_hdr, data_.size() - ip_hdr - tcp_hdr};
  }

  std::pair<const std::uint8_t*, std::size_t> GetUdpPayload() const noexcept {
    const std::uint8_t* p = data_.data();
    const std::uint8_t proto =
        IsIPv4() ? detail::Ipv4Proto(p) : detail::Ipv6Next(p);
    if (proto != 17u) {
      return {nullptr, 0};
    }
    const std::size_t ip_hdr = IsIPv4() ? detail::Ipv4Ihl(p) : detail::kMinIPv6;
    if (data_.size() < ip_hdr + detail::kUdpHdr) {
      return {nullptr, 0};
    }
    return {
        p + ip_hdr + detail::kUdpHdr, data_.size() - ip_hdr - detail::kUdpHdr};
  }

  bool IsDns() const noexcept { return DnsPtr() != nullptr; }

  // QUIC long header carrying an Initial packet (RFC 9000 17.2.2). The rest
  // of a QUIC flow is indistinguishable from any other UDP datagram.
  bool IsQuicInitial() const noexcept {
    constexpr std::uint32_t kVersion1 = 0x00000001u;
    constexpr std::uint32_t kVersion2 = 0x6B3343CFu;
    constexpr std::size_t kMinLongHeader = 7;

    const auto [payload, size] = GetUdpPayload();
    if (!payload || size < kMinLongHeader || (payload[0] & 0xC0u) != 0xC0u) {
      return false;
    }
    const std::uint32_t version = ReadU32Be(payload + 1);
    const std::uint8_t type = (payload[0] & 0x30u) >> 4;
    return (version == kVersion1 && type == 0u) ||
           (version == kVersion2 && type == 1u);
  }

  std::optional<std::string> GetDnsDomain() const noexcept {
    const std::uint8_t* dns = DnsPtr();
    if (!dns) {
      return std::nullopt;
    }
    if (ReadU16Be(dns + 4) == 0) {
      return std::nullopt;  // qdcount == 0
    }
    const std::uint8_t* cur = dns + detail::kDnsHdr;
    std::string name = ToLowerAscii(
        detail::ParseDnsName(dns, data_.data() + data_.size(), cur));
    if (name.empty()) {
      return std::nullopt;
    }
#ifdef FPTN_WITH_LIBIDN2
    if (detail::IsPunycode(name)) return detail::ToUnicode(name);
#endif
    return name;
  }

  bool IsDnsMxQuery() const noexcept {
    constexpr std::uint16_t kMxRecordType = 15;

    const std::uint8_t* dns = DnsPtr();
    if (!dns) {
      return false;
    }
    if ((dns[2] & 0x80u) != 0u || ReadU16Be(dns + 4) == 0) {
      return false;
    }
    const std::uint8_t* end = data_.data() + data_.size();
    const std::uint8_t* cur = dns + detail::kDnsHdr;
    detail::ParseDnsName(dns, end, cur);
    if (cur < dns || end - cur < 2) {
      return false;
    }
    return ReadU16Be(cur) == kMxRecordType;
  }

  std::vector<IPv4Address> GetDnsIPv4Addresses() const noexcept {
    const std::uint8_t* dns = DnsPtr();
    if (!dns) {
      return {};
    }
    const std::uint8_t* end = data_.data() + data_.size();
    int ancount = 0;
    const std::uint8_t* cur = detail::DnsAnswerStart(dns, end, &ancount);
    if (!cur) {
      return {};
    }

    std::vector<IPv4Address> out;
    for (int a = 0; a < ancount && cur < end; ++a) {
      if (!detail::SkipDnsName(cur, end) || end - cur < 10) {
        break;
      }

      const std::uint16_t rtype = ReadU16Be(cur);
      cur += 8;  // TYPE + CLASS + TTL
      const std::uint16_t rdlen = ReadU16Be(cur);
      cur += 2;

      if (static_cast<std::size_t>(end - cur) < rdlen) {
        break;
      }
      if (rtype == 1u && rdlen == 4u) {  // A record
        char buf[INET_ADDRSTRLEN] = {};
        const std::uint32_t net =
            htonl((static_cast<std::uint32_t>(cur[0]) << 24) |
                  (static_cast<std::uint32_t>(cur[1]) << 16) |
                  (static_cast<std::uint32_t>(cur[2]) << 8) |
                  static_cast<std::uint32_t>(cur[3]));
        if (::inet_ntop(AF_INET, &net, buf, sizeof(buf))) {
          out.emplace_back(buf);
        }
      }
      cur += rdlen;
    }
    return out;
  }

  std::vector<IPv6Address> GetDnsIPv6Addresses() const noexcept {
    const std::uint8_t* dns = DnsPtr();
    if (!dns) {
      return {};
    }
    const std::uint8_t* end = data_.data() + data_.size();
    int ancount = 0;
    const std::uint8_t* cur = detail::DnsAnswerStart(dns, end, &ancount);
    if (!cur) {
      return {};
    }

    std::vector<IPv6Address> out;
    for (int a = 0; a < ancount && cur < end; ++a) {
      if (!detail::SkipDnsName(cur, end) || end - cur < 10) {
        break;
      }
      const std::uint16_t rtype = ReadU16Be(cur);
      cur += 8;  // TYPE + CLASS + TTL
      const std::uint16_t rdlen = ReadU16Be(cur);
      cur += 2;
      if (static_cast<std::size_t>(end - cur) < rdlen) {
        break;
      }
      if (rtype == 28u && rdlen == 16u) {  // AAAA record
        char buf[INET6_ADDRSTRLEN] = {};
        if (::inet_ntop(AF_INET6, cur, buf, sizeof(buf))) {
          out.emplace_back(buf);
        }
      }
      cur += rdlen;
    }
    return out;
  }

  // Rewrites every A/AAAA answer in a DNS response to loopback
  // (127.0.0.1 / ::1) in place and fixes up the checksums. Record lengths are
  // unchanged, so no header offsets are touched. Returns true if at least one
  // record was rewritten.
  bool RewriteDnsAnswersToLoopback() noexcept {
    const std::uint8_t* dns = DnsPtr();
    if (!dns) {
      return false;
    }
    const std::uint8_t* end = data_.data() + data_.size();
    int ancount = 0;
    std::uint8_t* cur =
        const_cast<std::uint8_t*>(detail::DnsAnswerStart(dns, end, &ancount));
    if (!cur) {
      return false;
    }

    bool rewritten = false;
    for (int a = 0; a < ancount && cur < end; ++a) {
      if (!detail::SkipDnsName(cur, end) || end - cur < 10) {
        break;
      }
      const std::uint16_t rtype = ReadU16Be(cur);
      cur += 8;  // TYPE + CLASS + TTL
      const std::uint16_t rdlen = ReadU16Be(cur);
      cur += 2;
      if (static_cast<std::size_t>(end - cur) < rdlen) {
        break;
      }
      if (rtype == 1u && rdlen == 4u) {  // A record -> 127.0.0.1
        cur[0] = 127;
        cur[1] = 0;
        cur[2] = 0;
        cur[3] = 1;
        rewritten = true;
      } else if (rtype == 28u && rdlen == 16u) {  // AAAA record -> ::1
        for (int i = 0; i < 15; ++i) {
          cur[i] = 0;
        }
        cur[15] = 1;
        rewritten = true;
      }
      cur += rdlen;
    }
    if (rewritten) {
      RecalculateChecksums(data_.data(), data_.size());
    }
    return rewritten;
  }

  // Turns this DNS query into a response null-routed to loopback: A/AAAA get
  // 127.0.0.1 / ::1, any other query type gets NXDOMAIN.
  std::unique_ptr<IPPacket> MakeDnsNullRouteResponse() const {
    constexpr std::uint16_t kQTypeA = 0x0001;
    constexpr std::uint16_t kQTypeAAAA = 0x001C;

    const std::uint8_t* dns = DnsPtr();
    if (!dns) {
      return nullptr;
    }
    const std::size_t ip_hdr_len =
        IsIPv4() ? static_cast<std::size_t>(detail::Ipv4Ihl(data_.data()))
                 : detail::kMinIPv6;
    const std::size_t udp_off = ip_hdr_len;
    const std::size_t dns_off = udp_off + detail::kUdpHdr;

    const std::uint8_t* end = data_.data() + data_.size();
    const std::uint8_t* cur = dns + detail::kDnsHdr;
    detail::ParseDnsName(dns, end, cur);
    const auto name_end = static_cast<std::size_t>(cur - data_.data());
    if (name_end + 4 > data_.size()) {
      return nullptr;
    }
    const std::uint16_t qtype = ReadU16Be(data_.data() + name_end);
    const std::size_t question_end = name_end + 4;

    std::size_t rdlen = 0;
    if (qtype == kQTypeA) {
      rdlen = 4;
    } else if (qtype == kQTypeAAAA) {
      rdlen = 16;
    }
    const bool null_route = rdlen != 0;

    IPPacketData resp;
    if (null_route) {
      const std::size_t answer_len = 12 + rdlen;
      resp.assign(data_.begin(), data_.begin() + question_end);
      resp.resize(question_end + answer_len);

      std::size_t off = question_end;
      resp[off++] = 0xC0;
      resp[off++] = static_cast<std::uint8_t>(detail::kDnsHdr);
      WriteU16Be(resp.data() + off, qtype);
      off += 2;
      WriteU16Be(resp.data() + off, 0x0001);
      off += 2;
      WriteU16Be(resp.data() + off, 0);
      off += 2;
      WriteU16Be(resp.data() + off, 600);
      off += 2;
      WriteU16Be(resp.data() + off, static_cast<std::uint16_t>(rdlen));

      resp[dns_off + 2] =
          static_cast<std::uint8_t>((resp[dns_off + 2] & 0x01) | 0x80);
      resp[dns_off + 3] = 0x80;
      WriteU16Be(resp.data() + dns_off + 6, 1);
      WriteU16Be(resp.data() + dns_off + 8, 0);
      WriteU16Be(resp.data() + dns_off + 10, 0);
    } else {
      resp.assign(data_.begin(), data_.end());
      resp[dns_off + 2] =
          static_cast<std::uint8_t>((resp[dns_off + 2] & 0x01) | 0x80);
      resp[dns_off + 3] = 0x83;
    }

    const std::size_t new_len = resp.size();

    if (IsIPv4()) {
      for (int i = 0; i < 4; ++i) {
        std::swap(resp[12 + i], resp[16 + i]);
      }
      detail::Ipv4Ttl(resp.data()) = 64;
      WriteU16Be(resp.data() + 2, static_cast<std::uint16_t>(new_len));
    } else {
      for (int i = 0; i < 16; ++i) {
        std::swap(resp[8 + i], resp[24 + i]);
      }
      resp[7] = 64;
      WriteU16Be(
          resp.data() + 4, static_cast<std::uint16_t>(new_len - ip_hdr_len));
    }

    std::swap(resp[udp_off], resp[udp_off + 2]);
    std::swap(resp[udp_off + 1], resp[udp_off + 3]);
    WriteU16Be(resp.data() + udp_off + 4,
        static_cast<std::uint16_t>(new_len - udp_off));

    auto packet = Parse(std::move(resp), client_id_);
    if (!packet) {
      return nullptr;
    }
    if (null_route) {
      packet->RewriteDnsAnswersToLoopback();
    } else {
      packet->ComputeCalculateFields();
    }
    return packet;
  }

  std::unique_ptr<IPPacket> MakeTcpReset() const {
    if (!IsIPv4() || !IsTCP()) {
      return nullptr;
    }
    const std::uint8_t* p = data_.data();
    const std::size_t ip_hdr = detail::Ipv4Ihl(p);
    if (data_.size() < ip_hdr + 20) {
      return nullptr;
    }
    const std::uint8_t* tcp = p + ip_hdr;
    const std::size_t tcp_hdr = (tcp[12] >> 4) * 4;
    if (data_.size() < ip_hdr + tcp_hdr) {
      return nullptr;
    }
    const std::uint32_t seq = ReadU32Be(tcp + 4);
    const std::uint32_t ack = ReadU32Be(tcp + 8);
    const std::uint32_t payload_len =
        static_cast<std::uint32_t>(data_.size() - ip_hdr - tcp_hdr);

    constexpr std::size_t kTcpHdr = 20;
    IPPacketData resp(detail::kMinIPv4 + kTcpHdr, 0);

    resp[0] = 0x45;
    detail::Ipv4Ttl(resp.data()) = 64;
    resp[9] = 6;
    WriteU16Be(resp.data() + 2, static_cast<std::uint16_t>(resp.size()));
    Ipv4SetSrc(resp.data(), Ipv4GetDst(p));
    Ipv4SetDst(resp.data(), Ipv4GetSrc(p));

    std::uint8_t* rt = resp.data() + detail::kMinIPv4;
    WriteU16Be(rt, ReadU16Be(tcp + 2));
    WriteU16Be(rt + 2, ReadU16Be(tcp));
    const std::uint32_t rst_seq = ack;
    const std::uint32_t rst_ack = seq + payload_len;
    rt[4] = static_cast<std::uint8_t>(rst_seq >> 24);
    rt[5] = static_cast<std::uint8_t>(rst_seq >> 16);
    rt[6] = static_cast<std::uint8_t>(rst_seq >> 8);
    rt[7] = static_cast<std::uint8_t>(rst_seq);
    rt[8] = static_cast<std::uint8_t>(rst_ack >> 24);
    rt[9] = static_cast<std::uint8_t>(rst_ack >> 16);
    rt[10] = static_cast<std::uint8_t>(rst_ack >> 8);
    rt[11] = static_cast<std::uint8_t>(rst_ack);
    rt[12] = static_cast<std::uint8_t>((kTcpHdr / 4) << 4);
    rt[13] = 0x14;
    WriteU16Be(rt + 14, 0);

    auto packet = Parse(std::move(resp), client_id_);
    if (!packet) {
      return nullptr;
    }
    packet->ComputeCalculateFields();
    return packet;
  }

 protected:
  IPPacket() : client_id_(FPTN_PACKET_UNDEFINED_CLIENT_ID) {}  // for tests

  const std::uint8_t* DnsPtr() const noexcept {
    const std::uint8_t* p = data_.data();
    const std::uint8_t* end = p + data_.size();
    if (IsIPv4() && data_.size() >= detail::kMinIPv4 &&
        detail::Ipv4Proto(p) == 17u) {
      return detail::DnsPayloadPtr(p + detail::Ipv4Ihl(p), end);
    }
    if (IsIPv6() && data_.size() >= detail::kMinIPv6 &&
        detail::Ipv6Next(p) == 17u) {
      return detail::DnsPayloadPtr(p + detail::kMinIPv6, end);
    }
    return nullptr;
  }

 private:
  IPPacketData data_;
  fptn::ClientID client_id_;
};

using IPPacketPtr = std::unique_ptr<IPPacket>;

#ifdef USING_MIMALLOC
using BatchIPPacketPtr =
    std::vector<IPPacketPtr, mi_stl_allocator<IPPacketPtr>>;  // NOLINT
#else
using BatchIPPacketPtr = std::vector<IPPacketPtr>;
#endif

}  // namespace fptn::common::network
