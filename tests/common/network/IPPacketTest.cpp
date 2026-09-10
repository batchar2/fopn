/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <utility>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/protocol/protobuf/protobuf_serializer.h"
#include "fptn-protocol-lib/protocol/yaff/yaff_serializer.h"

namespace {

using fptn::common::network::IPPacket;
using fptn::common::network::IPPacketData;

constexpr std::uint8_t kTcp = 6;
constexpr std::uint8_t kUdp = 17;
constexpr std::uint8_t kIcmpv4 = 1;
constexpr std::uint8_t kIcmpv6 = 58;

// IPv4 packet, IHL=5 (20-byte header). For TCP/UDP the first four L4 bytes
// carry src/dst ports.
IPPacketData MakeIPv4(
    std::uint8_t proto, std::uint16_t src_port, std::uint16_t dst_port) {
  IPPacketData p(40, 0);
  p[0] = 0x45;  // version 4, IHL 5
  p[9] = proto;
  p[20] = static_cast<std::uint8_t>(src_port >> 8);
  p[21] = static_cast<std::uint8_t>(src_port & 0xFF);
  p[22] = static_cast<std::uint8_t>(dst_port >> 8);
  p[23] = static_cast<std::uint8_t>(dst_port & 0xFF);
  return p;
}

// IPv6 packet, no extension headers (L4 header at offset 40).
IPPacketData MakeIPv6(
    std::uint8_t next_header, std::uint16_t src_port, std::uint16_t dst_port) {
  IPPacketData p(60, 0);
  p[0] = 0x60;  // version 6
  p[6] = next_header;
  p[40] = static_cast<std::uint8_t>(src_port >> 8);
  p[41] = static_cast<std::uint8_t>(src_port & 0xFF);
  p[42] = static_cast<std::uint8_t>(dst_port >> 8);
  p[43] = static_cast<std::uint8_t>(dst_port & 0xFF);
  return p;
}

}  // namespace

TEST(IPPacketTest, IPv4Tcp) {
  const auto packet = IPPacket::Parse(MakeIPv4(kTcp, 0x1234, 0x5678));
  ASSERT_NE(packet, nullptr);
  EXPECT_TRUE(packet->IsIPv4());
  EXPECT_TRUE(packet->IsTCP());
  EXPECT_EQ(packet->GetTcpSrcPort(), 0x1234);
  EXPECT_EQ(packet->GetTcpDstPort(), 0x5678);
}

TEST(IPPacketTest, IPv4Udp) {
  const auto packet = IPPacket::Parse(MakeIPv4(kUdp, 0x1111, 0x2222));
  ASSERT_NE(packet, nullptr);
  EXPECT_FALSE(packet->IsTCP());
  EXPECT_TRUE(packet->IsUDP());
  EXPECT_EQ(packet->GetUdpSrcPort(), 0x1111);
  EXPECT_EQ(packet->GetUdpDstPort(), 0x2222);
}

TEST(IPPacketTest, IPv4Icmp) {
  const auto packet = IPPacket::Parse(MakeIPv4(kIcmpv4, 0, 0));
  ASSERT_NE(packet, nullptr);
  EXPECT_FALSE(packet->IsTCP());
  EXPECT_FALSE(packet->IsUDP());
}

TEST(IPPacketTest, IPv4TcpWithOptions) {
  // IHL=6 → 24-byte IP header, L4 header starts at offset 24.
  IPPacketData p(44, 0);
  p[0] = 0x46;  // version 4, IHL 6
  p[9] = kTcp;
  p[24] = 0x11;
  p[25] = 0x22;
  p[26] = 0x33;
  p[27] = 0x44;
  const auto packet = IPPacket::Parse(std::move(p));
  ASSERT_NE(packet, nullptr);
  EXPECT_TRUE(packet->IsTCP());
  EXPECT_EQ(packet->GetTcpSrcPort(), 0x1122);
  EXPECT_EQ(packet->GetTcpDstPort(), 0x3344);
}

TEST(IPPacketTest, IPv4TruncatedTcpReturnsZeroPort) {
  IPPacketData p(20, 0);  // IP header only, no TCP header
  p[0] = 0x45;
  p[9] = kTcp;
  const auto packet = IPPacket::Parse(std::move(p));
  ASSERT_NE(packet, nullptr);
  EXPECT_TRUE(packet->IsTCP());
  EXPECT_EQ(packet->GetTcpSrcPort(), 0);
  EXPECT_EQ(packet->GetTcpDstPort(), 0);
}

TEST(IPPacketTest, IPv6Tcp) {
  const auto packet = IPPacket::Parse(MakeIPv6(kTcp, 0xABCD, 0xEF01));
  ASSERT_NE(packet, nullptr);
  EXPECT_TRUE(packet->IsIPv6());
  EXPECT_TRUE(packet->IsTCP());
  EXPECT_EQ(packet->GetTcpSrcPort(), 0xABCD);
  EXPECT_EQ(packet->GetTcpDstPort(), 0xEF01);
}

TEST(IPPacketTest, IPv6Udp) {
  const auto packet = IPPacket::Parse(MakeIPv6(kUdp, 0x3333, 0x4444));
  ASSERT_NE(packet, nullptr);
  EXPECT_FALSE(packet->IsTCP());
  EXPECT_TRUE(packet->IsUDP());
  EXPECT_EQ(packet->GetUdpSrcPort(), 0x3333);
  EXPECT_EQ(packet->GetUdpDstPort(), 0x4444);
}

TEST(IPPacketTest, IPv6Icmp) {
  const auto packet = IPPacket::Parse(MakeIPv6(kIcmpv6, 0, 0));
  ASSERT_NE(packet, nullptr);
  EXPECT_FALSE(packet->IsTCP());
  EXPECT_FALSE(packet->IsUDP());
}

namespace {

using fptn::common::network::BatchIPPacketPtr;
using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;

IPPacketData MakeIPv4WithAddrs() {
  IPPacketData p = MakeIPv4(kTcp, 1, 2);
  p[8] = 64;  // ttl, the setters refuse to touch a packet with ttl 0
  p[12] = 10;
  p[13] = 0;
  p[14] = 0;
  p[15] = 1;
  p[16] = 192;
  p[17] = 168;
  p[18] = 5;
  p[19] = 7;
  return p;
}

IPPacketData MakeIPv6WithAddrs() {
  IPPacketData p = MakeIPv6(kTcp, 1, 2);
  p[8] = 0xfd;
  p[23] = 0x02;  // src fd00::2
  p[24] = 0xfd;
  p[39] = 0x01;  // dst fd00::1
  return p;
}

BatchIPPacketPtr MakeFullBatch(std::size_t count, std::size_t mtu) {
  BatchIPPacketPtr batch;
  batch.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    // Distinct contents: identical payloads are deduplicated by the
    // serializer and would understate the real frame size.
    IPPacketData raw(mtu, static_cast<std::uint8_t>(i));
    raw[0] = 0x45;
    raw[9] = kTcp;
    for (std::size_t j = 20; j < raw.size(); j += 7) {
      raw[j] = static_cast<std::uint8_t>((i * 31) + j);
    }
    batch.push_back(IPPacket::Parse(std::move(raw)));
  }
  return batch;
}

}  // namespace

TEST(IPPacketTest, IPv4AddressesReadFromHeader) {
  const auto packet = IPPacket::Parse(MakeIPv4WithAddrs());
  ASSERT_NE(packet, nullptr);
  EXPECT_EQ(packet->GetSrcIPv4Address().ToString(), "10.0.0.1");
  EXPECT_EQ(packet->GetDstIPv4Address().ToString(), "192.168.5.7");
  EXPECT_EQ(packet->GetDstIPv4Address().ToInt(), 3232236807U);
}

// The NAT table is keyed on ToInt(); a key taken from a packet header must
// equal the key taken from the configured address.
TEST(IPPacketTest, IPv4KeyMatchesAddressBuiltFromString) {
  const auto packet = IPPacket::Parse(MakeIPv4WithAddrs());
  ASSERT_NE(packet, nullptr);
  const IPv4Address expected(std::string("192.168.5.7"));
  EXPECT_EQ(packet->GetDstIPv4Address().ToInt(), expected.ToInt());
  EXPECT_TRUE(packet->GetDstIPv4Address() == expected);
  EXPECT_TRUE(
      packet->GetDstIPv4Address() != IPv4Address(std::string("192.168.5.8")));
}

TEST(IPPacketTest, IPv6AddressesReadFromHeader) {
  const auto packet = IPPacket::Parse(MakeIPv6WithAddrs());
  ASSERT_NE(packet, nullptr);
  EXPECT_EQ(packet->GetSrcIPv6Address().ToString(), "fd00::2");
  EXPECT_EQ(packet->GetDstIPv6Address().ToString(), "fd00::1");
}

// Same invariant for IPv6, whose table is keyed on the raw bytes.
TEST(IPPacketTest, IPv6KeyMatchesAddressBuiltFromString) {
  const auto packet = IPPacket::Parse(MakeIPv6WithAddrs());
  ASSERT_NE(packet, nullptr);
  const IPv6Address expected(std::string("fd00::1"));
  EXPECT_EQ(packet->GetDstIPv6Address().ToBytes(), expected.ToBytes());
  EXPECT_TRUE(packet->GetDstIPv6Address() == expected);
}

TEST(IPPacketTest, IPv4AddressSetterRoundTrip) {
  auto packet = IPPacket::Parse(MakeIPv4WithAddrs());
  ASSERT_NE(packet, nullptr);
  packet->SetDstIPv4Address(IPv4Address(std::string("172.16.9.3")));
  packet->SetSrcIPv4Address(IPv4Address(std::string("172.16.9.4")));
  EXPECT_EQ(packet->GetDstIPv4Address().ToString(), "172.16.9.3");
  EXPECT_EQ(packet->GetSrcIPv4Address().ToString(), "172.16.9.4");
}

TEST(IPPacketTest, IPv6AddressSetterRoundTrip) {
  auto packet = IPPacket::Parse(MakeIPv6WithAddrs());
  ASSERT_NE(packet, nullptr);
  packet->SetDstIPv6Address(IPv6Address(std::string("2001:db8::dead:beef")));
  packet->SetSrcIPv6Address(IPv6Address(std::string("2001:db8::1")));
  EXPECT_EQ(packet->GetDstIPv6Address().ToString(), "2001:db8::dead:beef");
  EXPECT_EQ(packet->GetSrcIPv6Address().ToString(), "2001:db8::1");
}

TEST(IPPacketTest, IPv6SetterIgnoresInvalidAddress) {
  auto packet = IPPacket::Parse(MakeIPv6WithAddrs());
  ASSERT_NE(packet, nullptr);
  packet->SetDstIPv6Address(IPv6Address());
  EXPECT_EQ(packet->GetDstIPv6Address().ToString(), "fd00::1");
}

// A frame above the peer's read_message_max drops the tunnel.
TEST(IPPacketTest, SerializedBatchFitsPeerMessageLimit) {
  constexpr std::size_t kPeerMessageLimit = 256 * 1024;
  constexpr std::size_t kSenderBatchCap = 128;  // Session::RunSender

  for (const std::size_t mtu : {std::size_t{1420}, std::size_t{1500}}) {
    auto protobuf_frame = fptn::protocol::protobuf::SerializeBatchIPPacket(
        MakeFullBatch(kSenderBatchCap, mtu));
    ASSERT_TRUE(protobuf_frame.has_value()) << "mtu=" << mtu;
    EXPECT_LT(protobuf_frame->size(), kPeerMessageLimit) << "mtu=" << mtu;

    auto yaff_frame = fptn::protocol::yaff::SerializeBatchIPPacket(
        MakeFullBatch(kSenderBatchCap, mtu));
    ASSERT_TRUE(yaff_frame.has_value()) << "mtu=" << mtu;
    EXPECT_LT(yaff_frame->size(), kPeerMessageLimit) << "mtu=" << mtu;

    std::cout << "mtu=" << mtu << " cap=" << kSenderBatchCap
              << " -> protobuf=" << protobuf_frame->size()
              << " yaff=" << yaff_frame->size() << " (limit "
              << kPeerMessageLimit << ")\n";
  }
}

TEST(IPPacketTest, SerializedBatchSizeByCap) {
  constexpr std::size_t kPeerMessageLimit = 256 * 1024;
  for (const std::size_t cap : {std::size_t{128}, std::size_t{160},
           std::size_t{180}, std::size_t{200}, std::size_t{256}}) {
    auto protobuf_frame = fptn::protocol::protobuf::SerializeBatchIPPacket(
        MakeFullBatch(cap, 1420));
    auto yaff_frame =
        fptn::protocol::yaff::SerializeBatchIPPacket(MakeFullBatch(cap, 1420));
    ASSERT_TRUE(protobuf_frame.has_value());
    ASSERT_TRUE(yaff_frame.has_value());
    const std::size_t worst =
        std::max(protobuf_frame->size(), yaff_frame->size());
    std::cout << "cap=" << cap
              << " mtu=1420 -> protobuf=" << protobuf_frame->size()
              << " yaff=" << yaff_frame->size() << " (" << std::fixed
              << std::setprecision(1)
              << (100.0 * static_cast<double>(worst) /
                     static_cast<double>(kPeerMessageLimit))
              << "%)" << (worst >= kPeerMessageLimit ? "  OVER" : "") << "\n";
  }
}

// Full-MTU packets are never padded, so this uses ACK-sized ones.
TEST(IPPacketTest, PaddingAppliedOnlyToSmallBatches) {
  constexpr std::size_t kAckSize = 40;
  constexpr std::size_t kMinPaddingBytes = 64;

  const auto per_packet = [](std::size_t count, bool yaff) {
    auto frame = yaff ? fptn::protocol::yaff::SerializeBatchIPPacket(
                            MakeFullBatch(count, kAckSize))
                      : fptn::protocol::protobuf::SerializeBatchIPPacket(
                            MakeFullBatch(count, kAckSize));
    return frame.has_value() ? frame->size() / count : 0;
  };

  for (const bool yaff : {false, true}) {
    const std::size_t padded = per_packet(2, yaff);
    const std::size_t plain = per_packet(64, yaff);
    std::cout << (yaff ? "yaff" : "protobuf") << " ack: batch=2 -> " << padded
              << " B/pkt, batch=64 -> " << plain << " B/pkt\n";

    EXPECT_GT(padded, plain + (kMinPaddingBytes / 2));
    EXPECT_LT(plain, kAckSize + kMinPaddingBytes);
  }
}

namespace {

std::uint32_t ReadBe32(const std::uint8_t* p) {
  return (static_cast<std::uint32_t>(p[0]) << 24) |
         (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) |
         static_cast<std::uint32_t>(p[3]);
}

IPPacketData MakeTcpDataSegment(std::uint32_t seq, std::uint32_t ack,
    std::uint16_t src_port, std::uint16_t dst_port, std::size_t payload) {
  IPPacketData p(40 + payload, 0);
  p[0] = 0x45;
  p[8] = 64;
  p[9] = kTcp;
  p[2] = static_cast<std::uint8_t>((p.size() >> 8) & 0xFF);
  p[3] = static_cast<std::uint8_t>(p.size() & 0xFF);
  p[12] = 10;
  p[13] = 0;
  p[14] = 0;
  p[15] = 1;
  p[16] = 93;
  p[17] = 184;
  p[18] = 216;
  p[19] = 34;
  std::size_t t = 20;
  p[t] = static_cast<std::uint8_t>(src_port >> 8);
  p[t + 1] = static_cast<std::uint8_t>(src_port & 0xFF);
  p[t + 2] = static_cast<std::uint8_t>(dst_port >> 8);
  p[t + 3] = static_cast<std::uint8_t>(dst_port & 0xFF);
  p[t + 4] = static_cast<std::uint8_t>(seq >> 24);
  p[t + 5] = static_cast<std::uint8_t>(seq >> 16);
  p[t + 6] = static_cast<std::uint8_t>(seq >> 8);
  p[t + 7] = static_cast<std::uint8_t>(seq);
  p[t + 8] = static_cast<std::uint8_t>(ack >> 24);
  p[t + 9] = static_cast<std::uint8_t>(ack >> 16);
  p[t + 10] = static_cast<std::uint8_t>(ack >> 8);
  p[t + 11] = static_cast<std::uint8_t>(ack);
  p[t + 12] = static_cast<std::uint8_t>(5 << 4);
  p[t + 13] = 0x18;
  return p;
}

}  // namespace

TEST(IPPacketTest, MakeTcpResetSwapsEndpointsAndSetsFields) {
  const std::uint32_t seq = 0x11223344;
  const std::uint32_t ack = 0xAABBCCDD;
  const std::size_t payload = 100;
  const auto hello =
      IPPacket::Parse(MakeTcpDataSegment(seq, ack, 0xC001, 0x01BB, payload));
  ASSERT_NE(hello, nullptr);

  const auto rst = hello->MakeTcpReset();
  ASSERT_NE(rst, nullptr);
  EXPECT_TRUE(rst->IsIPv4());
  EXPECT_TRUE(rst->IsTCP());
  EXPECT_EQ(rst->GetSrcIPv4Address().ToString(), "93.184.216.34");
  EXPECT_EQ(rst->GetDstIPv4Address().ToString(), "10.0.0.1");
  EXPECT_EQ(rst->GetTcpSrcPort(), 0x01BB);
  EXPECT_EQ(rst->GetTcpDstPort(), 0xC001);

  const auto& d = rst->Data();
  ASSERT_EQ(d.size(), 40U);
  EXPECT_EQ(d[20 + 13], 0x14);
  EXPECT_EQ(ReadBe32(d.data() + 20 + 4), ack);
  EXPECT_EQ(ReadBe32(d.data() + 20 + 8), seq + payload);
}

TEST(IPPacketTest, MakeTcpResetReturnsNullForUdp) {
  const auto packet = IPPacket::Parse(MakeIPv4(kUdp, 0x1111, 0x2222));
  ASSERT_NE(packet, nullptr);
  EXPECT_EQ(packet->MakeTcpReset(), nullptr);
}

TEST(IPPacketTest, MakeTcpResetReturnsNullForIPv6) {
  const auto packet = IPPacket::Parse(MakeIPv6(kTcp, 0xABCD, 0xEF01));
  ASSERT_NE(packet, nullptr);
  EXPECT_EQ(packet->MakeTcpReset(), nullptr);
}
