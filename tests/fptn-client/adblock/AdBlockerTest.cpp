/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <algorithm>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/network/ip_packet.h"

#include "plugins/adblock/adblock.h"

namespace fptn::plugin {
extern const unsigned char kBlocklistGz[] = {0};
extern const unsigned int kBlocklistGzLen = 0;
}  // namespace fptn::plugin

namespace {

using fptn::common::network::IPPacket;
using fptn::common::network::IPPacketData;
using fptn::common::network::ReadU16Be;
using fptn::plugin::AdBlock;

constexpr std::uint8_t kUdp = 17;
constexpr std::uint16_t kTypeA = 1;
constexpr std::uint16_t kTypeAAAA = 28;
constexpr std::uint16_t kTypeMx = 15;

std::vector<std::uint8_t> EncodeQName(const std::string& domain) {
  std::vector<std::uint8_t> out;
  std::size_t start = 0;
  while (start <= domain.size()) {
    std::size_t dot = domain.find('.', start);
    if (dot == std::string::npos) {
      dot = domain.size();
    }
    const std::size_t len = dot - start;
    out.push_back(static_cast<std::uint8_t>(len));
    for (std::size_t i = start; i < dot; ++i) {
      out.push_back(static_cast<std::uint8_t>(domain[i]));
    }
    if (dot == domain.size()) {
      break;
    }
    start = dot + 1;
  }
  out.push_back(0);
  return out;
}

IPPacketData MakeDnsQuery(
    const std::string& domain, std::uint16_t qtype, bool ipv6 = false) {
  std::vector<std::uint8_t> dns = {
      0x12,
      0x34,
      0x01,
      0x00,
      0x00,
      0x01,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
  };
  const std::vector<std::uint8_t> qname = EncodeQName(domain);
  dns.insert(dns.end(), qname.begin(), qname.end());
  dns.push_back(static_cast<std::uint8_t>(qtype >> 8));
  dns.push_back(static_cast<std::uint8_t>(qtype & 0xFF));
  dns.push_back(0x00);
  dns.push_back(0x01);

  const std::size_t ip_hdr = ipv6 ? 40 : 20;
  const std::size_t udp_len = 8 + dns.size();
  IPPacketData p(ip_hdr + udp_len, 0);

  if (ipv6) {
    p[0] = 0x60;
    p[6] = kUdp;
    p[4] = static_cast<std::uint8_t>(udp_len >> 8);
    p[5] = static_cast<std::uint8_t>(udp_len & 0xFF);
    p[8] = 0x20;
    p[24] = 0x20;
    p[39] = 0x02;
  } else {
    p[0] = 0x45;
    p[9] = kUdp;
    const std::size_t total = ip_hdr + udp_len;
    p[2] = static_cast<std::uint8_t>(total >> 8);
    p[3] = static_cast<std::uint8_t>(total & 0xFF);
    p[12] = 10;
    p[15] = 1;
    p[16] = 8;
    p[17] = 8;
    p[18] = 8;
    p[19] = 8;
  }

  const std::size_t udp = ip_hdr;
  p[udp] = 0x30;
  p[udp + 1] = 0x39;
  p[udp + 3] = 53;
  p[udp + 4] = static_cast<std::uint8_t>(udp_len >> 8);
  p[udp + 5] = static_cast<std::uint8_t>(udp_len & 0xFF);

  const std::size_t dns_off = ip_hdr + 8;
  for (std::size_t i = 0; i < dns.size(); ++i) {
    p[dns_off + i] = dns[i];
  }
  return p;
}

AdBlock MakeBlocker() {
  return AdBlock(
      std::unordered_set<std::string>{"doubleclick.net", "ads.example.com"});
}

std::uint8_t Rcode(const IPPacket& packet, bool ipv6 = false) {
  const std::size_t dns_off = (ipv6 ? 40 : 20) + 8;
  return packet.Data()[dns_off + 3] & 0x0F;
}

std::uint16_t OnesComplementSum(
    const std::uint8_t* data, std::size_t len, std::uint32_t sum = 0) {
  for (std::size_t i = 0; i + 1 < len; i += 2) {
    sum += (static_cast<std::uint32_t>(data[i]) << 8) | data[i + 1];
  }
  if (len % 2 != 0) {
    sum += static_cast<std::uint32_t>(data[len - 1]) << 8;
  }
  while ((sum >> 16) != 0) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return static_cast<std::uint16_t>(sum);
}

bool Ipv4HeaderChecksumValid(const IPPacketData& p) {
  return OnesComplementSum(p.data(), 20) == 0xFFFF;
}

bool UdpChecksumValid(const IPPacketData& p) {
  const bool ipv6 = (p[0] >> 4) == 6;
  const std::size_t ip_hdr = ipv6 ? 40 : 20;
  const std::size_t udp_len = p.size() - ip_hdr;

  // pseudo-header: addresses + protocol + UDP length
  const std::size_t addr_off = ipv6 ? 8 : 12;
  const std::size_t addr_len = ipv6 ? 32 : 8;
  std::uint32_t sum = 0;
  for (std::size_t i = 0; i < addr_len; i += 2) {
    sum += (static_cast<std::uint32_t>(p[addr_off + i]) << 8) |
           p[addr_off + i + 1];
  }
  sum += kUdp;
  sum += static_cast<std::uint32_t>(udp_len);

  return OnesComplementSum(p.data() + ip_hdr, udp_len, sum) == 0xFFFF;
}

std::size_t QuestionEnd(const std::string& domain, bool ipv6 = false) {
  const std::size_t dns_off = (ipv6 ? 40 : 20) + 8;
  return dns_off + 12 + EncodeQName(domain).size() + 4;
}

}  // namespace

TEST(AdBlockerTest, BlocksExactDomainWithLoopbackA) {
  const AdBlock blocker = MakeBlocker();
  auto query = IPPacket::Parse(MakeDnsQuery("doubleclick.net", kTypeA));
  ASSERT_NE(query, nullptr);

  auto resp = blocker.ProcessOutgoingDns(*query);
  ASSERT_NE(resp, nullptr);

  const auto addrs = resp->GetDnsIPv4Addresses();
  ASSERT_EQ(addrs.size(), 1U);
  EXPECT_EQ(addrs[0].ToString(), "127.0.0.1");
  EXPECT_EQ(resp->GetDstIPv4Address().ToString(), "10.0.0.1");
}

TEST(AdBlockerTest, BlocksSubdomainOfBlockedParent) {
  const AdBlock blocker = MakeBlocker();
  auto query = IPPacket::Parse(MakeDnsQuery("a.b.ads.example.com", kTypeA));
  ASSERT_NE(query, nullptr);

  auto resp = blocker.ProcessOutgoingDns(*query);
  ASSERT_NE(resp, nullptr);
  const auto addrs = resp->GetDnsIPv4Addresses();
  ASSERT_EQ(addrs.size(), 1U);
  EXPECT_EQ(addrs[0].ToString(), "127.0.0.1");
}

TEST(AdBlockerTest, PassesThroughAllowedDomain) {
  const AdBlock blocker = MakeBlocker();
  auto query = IPPacket::Parse(MakeDnsQuery("example.org", kTypeA));
  ASSERT_NE(query, nullptr);
  EXPECT_EQ(blocker.ProcessOutgoingDns(*query), nullptr);
}

TEST(AdBlockerTest, BlocksAaaaWithLoopbackV6) {
  const AdBlock blocker = MakeBlocker();
  auto query = IPPacket::Parse(MakeDnsQuery("doubleclick.net", kTypeAAAA));
  ASSERT_NE(query, nullptr);

  auto resp = blocker.ProcessOutgoingDns(*query);
  ASSERT_NE(resp, nullptr);
  const auto addrs = resp->GetDnsIPv6Addresses();
  ASSERT_EQ(addrs.size(), 1U);
  EXPECT_EQ(addrs[0].ToString(), "::1");
}

TEST(AdBlockerTest, BlocksNonAddressQueryWithNxdomain) {
  const AdBlock blocker = MakeBlocker();
  auto query = IPPacket::Parse(MakeDnsQuery("doubleclick.net", kTypeMx));
  ASSERT_NE(query, nullptr);

  auto resp = blocker.ProcessOutgoingDns(*query);
  ASSERT_NE(resp, nullptr);
  EXPECT_EQ(Rcode(*resp), 3U);
}

TEST(AdBlockerTest, BlocksIpv6Query) {
  const AdBlock blocker = MakeBlocker();
  auto query = IPPacket::Parse(MakeDnsQuery("doubleclick.net", kTypeA, true));
  ASSERT_NE(query, nullptr);

  auto resp = blocker.ProcessOutgoingDns(*query);
  ASSERT_NE(resp, nullptr);
  EXPECT_TRUE(resp->IsIPv6());
  const auto addrs = resp->GetDnsIPv4Addresses();
  ASSERT_EQ(addrs.size(), 1U);
  EXPECT_EQ(addrs[0].ToString(), "127.0.0.1");
}

TEST(AdBlockerTest, BuildsValidIPv4ResponseHeaders) {
  const AdBlock blocker = MakeBlocker();
  const IPPacketData query_data = MakeDnsQuery("doubleclick.net", kTypeA);
  auto query = IPPacket::Parse(query_data);
  ASSERT_NE(query, nullptr);

  auto resp = blocker.ProcessOutgoingDns(*query);
  ASSERT_NE(resp, nullptr);
  const IPPacketData& p = resp->Data();

  ASSERT_TRUE(resp->IsIPv4());
  EXPECT_EQ(p[9], kUdp);
  EXPECT_EQ(p[8], 64) << "TTL";
  EXPECT_EQ(ReadU16Be(p.data() + 2), p.size()) << "IP total length";
  EXPECT_TRUE(Ipv4HeaderChecksumValid(p)) << "IPv4 header checksum";

  EXPECT_EQ(resp->GetSrcIPv4Address().ToString(), "8.8.8.8")
      << "the answer comes from the resolver the client asked";
  EXPECT_EQ(resp->GetDstIPv4Address().ToString(), "10.0.0.1");

  EXPECT_EQ(ReadU16Be(p.data() + 20), 53U) << "UDP source port";
  EXPECT_EQ(ReadU16Be(p.data() + 22), 12345U) << "UDP destination port";
  EXPECT_EQ(ReadU16Be(p.data() + 24), p.size() - 20) << "UDP length";
  EXPECT_TRUE(UdpChecksumValid(p)) << "UDP checksum";
}

TEST(AdBlockerTest, BuildsWellFormedDnsAnswer) {
  const AdBlock blocker = MakeBlocker();
  const IPPacketData query_data = MakeDnsQuery("doubleclick.net", kTypeA);
  auto query = IPPacket::Parse(query_data);
  ASSERT_NE(query, nullptr);

  auto resp = blocker.ProcessOutgoingDns(*query);
  ASSERT_NE(resp, nullptr);
  const IPPacketData& p = resp->Data();

  constexpr std::size_t kDnsOff = 28;
  EXPECT_EQ(ReadU16Be(p.data() + kDnsOff), 0x1234U) << "transaction id";
  EXPECT_EQ(p[kDnsOff + 2] & 0x80, 0x80) << "QR";
  EXPECT_EQ(p[kDnsOff + 3] & 0x80, 0x80) << "RA";
  EXPECT_EQ(p[kDnsOff + 3] & 0x0F, 0) << "RCODE=0";
  EXPECT_EQ(ReadU16Be(p.data() + kDnsOff + 4), 1U) << "QDCOUNT";
  EXPECT_EQ(ReadU16Be(p.data() + kDnsOff + 6), 1U) << "ANCOUNT";
  EXPECT_EQ(ReadU16Be(p.data() + kDnsOff + 8), 0U) << "NSCOUNT";
  EXPECT_EQ(ReadU16Be(p.data() + kDnsOff + 10), 0U) << "ARCOUNT";

  const std::size_t question_end = QuestionEnd("doubleclick.net");
  EXPECT_TRUE(std::equal(query_data.begin() + kDnsOff + 12,
      query_data.begin() + question_end, p.begin() + kDnsOff + 12))
      << "the question section is echoed back unchanged";

  ASSERT_EQ(p.size(), question_end + 16) << "one A record is appended";
  const std::uint8_t* answer = p.data() + question_end;
  EXPECT_EQ(ReadU16Be(answer), 0xC00CU) << "NAME points to the question";
  EXPECT_EQ(ReadU16Be(answer + 2), kTypeA);
  EXPECT_EQ(ReadU16Be(answer + 4), 1U) << "class IN";
  EXPECT_EQ(ReadU16Be(answer + 6), 0U);
  EXPECT_EQ(ReadU16Be(answer + 8), 600U) << "TTL";
  EXPECT_EQ(ReadU16Be(answer + 10), 4U) << "RDLENGTH";
  EXPECT_EQ(answer[12], 127);
  EXPECT_EQ(answer[13], 0);
  EXPECT_EQ(answer[14], 0);
  EXPECT_EQ(answer[15], 1);
}

TEST(AdBlockerTest, BuildsValidIPv6ResponseHeaders) {
  const AdBlock blocker = MakeBlocker();
  auto query = IPPacket::Parse(MakeDnsQuery("doubleclick.net", kTypeA, true));
  ASSERT_NE(query, nullptr);

  auto resp = blocker.ProcessOutgoingDns(*query);
  ASSERT_NE(resp, nullptr);
  const IPPacketData& p = resp->Data();

  ASSERT_TRUE(resp->IsIPv6());
  EXPECT_EQ(p[6], kUdp) << "next header";
  EXPECT_EQ(p[7], 64) << "hop limit";
  EXPECT_EQ(ReadU16Be(p.data() + 4), p.size() - 40) << "payload length";
  EXPECT_EQ(resp->GetSrcIPv6Address().ToString(), "2000::2");
  EXPECT_EQ(resp->GetDstIPv6Address().ToString(), "2000::");
  EXPECT_EQ(ReadU16Be(p.data() + 40), 53U) << "UDP source port";
  EXPECT_EQ(ReadU16Be(p.data() + 44), p.size() - 40) << "UDP length";
  EXPECT_NE(ReadU16Be(p.data() + 46), 0U) << "UDP checksum is mandatory";
  EXPECT_TRUE(UdpChecksumValid(p)) << "UDP checksum";
}

TEST(AdBlockerTest, NxdomainResponseKeepsQuestionIntact) {
  const AdBlock blocker = MakeBlocker();
  const IPPacketData query_data = MakeDnsQuery("doubleclick.net", kTypeMx);
  auto query = IPPacket::Parse(query_data);
  ASSERT_NE(query, nullptr);

  auto resp = blocker.ProcessOutgoingDns(*query);
  ASSERT_NE(resp, nullptr);
  const IPPacketData& p = resp->Data();

  constexpr std::size_t kDnsOff = 28;
  ASSERT_EQ(p.size(), query_data.size()) << "no answer is appended";
  EXPECT_EQ(p[kDnsOff + 2] & 0x80, 0x80) << "QR";
  EXPECT_EQ(Rcode(*resp), 3U);
  EXPECT_EQ(ReadU16Be(p.data() + kDnsOff + 6), 0U) << "ANCOUNT";
  EXPECT_TRUE(std::equal(query_data.begin() + kDnsOff + 12, query_data.end(),
      p.begin() + kDnsOff + 12))
      << "the question section is echoed back unchanged";
  EXPECT_TRUE(Ipv4HeaderChecksumValid(p));
  EXPECT_TRUE(UdpChecksumValid(p));
}

TEST(AdBlockerTest, IgnoresNonDnsPacket) {
  const AdBlock blocker = MakeBlocker();
  IPPacketData packet = MakeDnsQuery("doubleclick.net", kTypeA);
  packet[22] = 0x01;
  packet[23] = 0x00;
  auto query = IPPacket::Parse(std::move(packet));
  ASSERT_NE(query, nullptr);
  EXPECT_EQ(blocker.ProcessOutgoingDns(*query), nullptr);
}

TEST(AdBlockerTest, EmptyBlocklistBlocksNothing) {
  const AdBlock blocker{std::unordered_set<std::string>{}};
  auto query = IPPacket::Parse(MakeDnsQuery("doubleclick.net", kTypeA));
  ASSERT_NE(query, nullptr);
  EXPECT_EQ(blocker.ProcessOutgoingDns(*query), nullptr);
}

namespace {

using fptn::common::network::IPPacketPtr;
using fptn::plugin::Direction;

constexpr std::uint8_t kTcpProto = 6;

void PushU16(std::vector<std::uint8_t>& out, std::size_t value) {
  out.push_back(static_cast<std::uint8_t>(value >> 8));
  out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

std::vector<std::uint8_t> MakeClientHello(const std::string& sni) {
  std::vector<std::uint8_t> body = {0x01, 0x00, 0x00, 0x00, 0x03, 0x03};
  body.insert(body.end(), 32, 0x11);
  body.push_back(0x00);
  PushU16(body, 2);
  body.push_back(0x13);
  body.push_back(0x01);
  body.push_back(0x01);
  body.push_back(0x00);

  std::vector<std::uint8_t> extensions;
  PushU16(extensions, 0x0000);
  PushU16(extensions, sni.size() + 5);
  PushU16(extensions, sni.size() + 3);
  extensions.push_back(0x00);
  PushU16(extensions, sni.size());
  extensions.insert(extensions.end(), sni.begin(), sni.end());
  PushU16(body, extensions.size());
  body.insert(body.end(), extensions.begin(), extensions.end());

  const std::size_t handshake_len = body.size() - 4;
  body[1] = static_cast<std::uint8_t>(handshake_len >> 16);
  body[2] = static_cast<std::uint8_t>(handshake_len >> 8);
  body[3] = static_cast<std::uint8_t>(handshake_len & 0xFF);

  std::vector<std::uint8_t> record = {0x16, 0x03, 0x01};
  PushU16(record, body.size());
  record.insert(record.end(), body.begin(), body.end());
  return record;
}

IPPacketPtr MakeHandshake(const std::string& sni) {
  constexpr std::size_t kIpHdr = 20;
  constexpr std::size_t kTcpHdr = 20;
  const std::vector<std::uint8_t> hello = MakeClientHello(sni);
  IPPacketData p(kIpHdr + kTcpHdr + hello.size(), 0);
  p[0] = 0x45;
  p[2] = static_cast<std::uint8_t>(p.size() >> 8);
  p[3] = static_cast<std::uint8_t>(p.size() & 0xFF);
  p[9] = kTcpProto;
  p[12] = 10;
  p[15] = 1;
  p[16] = 1;
  p[17] = 2;
  p[18] = 3;
  p[19] = 4;
  p[kIpHdr] = 0xC0;
  p[kIpHdr + 2] = 0x01;
  p[kIpHdr + 3] = 0xBB;
  p[kIpHdr + 12] = 0x50;
  for (std::size_t i = 0; i < hello.size(); ++i) {
    p[kIpHdr + kTcpHdr + i] = hello[i];
  }
  return IPPacket::Parse(std::move(p));
}

}  // namespace

TEST(AdBlockerTest, DropsBlockedSniWithoutReply) {
  AdBlock blocker = MakeBlocker();

  auto result = blocker.HandlePacket(
      MakeHandshake("cdn.ads.example.com"), Direction::kOutgoing);
  EXPECT_EQ(result.packet, nullptr) << "blocked TLS packet is dropped";
  EXPECT_EQ(result.reply, nullptr) << "no RST is sent, just a silent drop";
  EXPECT_TRUE(result.triggered);
}

TEST(AdBlockerTest, PassesAllowedSni) {
  AdBlock blocker = MakeBlocker();

  auto result =
      blocker.HandlePacket(MakeHandshake("example.org"), Direction::kOutgoing);
  ASSERT_NE(result.packet, nullptr);
  EXPECT_EQ(result.reply, nullptr);
  EXPECT_FALSE(result.triggered);
}

TEST(AdBlockerTest, DropsBlockedDnsQueryReturningResponse) {
  AdBlock blocker = MakeBlocker();

  auto result = blocker.HandlePacket(
      IPPacket::Parse(MakeDnsQuery("doubleclick.net", kTypeA)),
      Direction::kOutgoing);
  EXPECT_EQ(result.packet, nullptr) << "the query is not forwarded";
  ASSERT_NE(result.reply, nullptr) << "a null-route DNS answer is returned";
  EXPECT_TRUE(result.triggered);
  const auto addrs = result.reply->GetDnsIPv4Addresses();
  ASSERT_EQ(addrs.size(), 1U);
  EXPECT_EQ(addrs[0].ToString(), "127.0.0.1");
}

TEST(AdBlockerTest, IgnoresIncomingDirection) {
  AdBlock blocker = MakeBlocker();

  auto result = blocker.HandlePacket(
      MakeHandshake("cdn.ads.example.com"), Direction::kIncoming);
  ASSERT_NE(result.packet, nullptr) << "adblock only acts on outgoing traffic";
  EXPECT_FALSE(result.triggered);
}
