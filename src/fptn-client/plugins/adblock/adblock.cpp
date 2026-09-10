/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "plugins/adblock/adblock.h"

#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)
#include <zlib.h>           // NOLINT(build/include_order)

#include "common/network/ip_utils.h"
#include "common/utils/utils.h"

namespace fptn::plugin {

extern const unsigned char kBlocklistGz[];
extern const unsigned int kBlocklistGzLen;

namespace {

std::string Gunzip(const unsigned char* data, unsigned int size) {
  constexpr std::size_t kChunkSize = 64 * 1024;
  std::vector<char> buffer(kChunkSize);

  ::z_stream strm{};
  strm.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(data));
  strm.avail_in = size;
  if (::inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
    return {};
  }

  std::string out;
  int ret = 0;
  do {
    strm.next_out = reinterpret_cast<Bytef*>(buffer.data());
    strm.avail_out = static_cast<unsigned int>(buffer.size());
    ret = ::inflate(&strm, Z_NO_FLUSH);
    if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
      ::inflateEnd(&strm);
      return {};
    }
    out.append(buffer.data(), buffer.size() - strm.avail_out);
  } while (ret != Z_STREAM_END);

  ::inflateEnd(&strm);
  return out;
}

std::string ParseBlocklistLine(std::string line) {
  if (!line.empty() && line.back() == '\r') {
    line.pop_back();
  }
  if (line.empty() || line[0] == '#' || line[0] == '!') {
    return {};
  }
  const std::size_t comment = line.find('#');
  if (comment != std::string::npos) {
    line.erase(comment);
  }
  line = fptn::common::utils::ToLowerCase(fptn::common::utils::Trim(line));
  if (line.empty()) {
    return {};
  }

  const std::size_t sep = line.find_first_of(" \t");
  std::string domain = (sep == std::string::npos) ? line : line.substr(sep + 1);
  domain = fptn::common::utils::Trim(domain);
  const std::size_t dot = domain.find('.');
  if (dot == std::string::npos || domain == "0.0.0.0") {
    return {};
  }
  if (domain.ends_with(".local") || domain.ends_with(".localdomain") ||
      domain.ends_with(".localhost")) {
    return {};
  }
  return domain;
}

std::unordered_set<std::string> LoadEmbeddedBlocklist() {
  std::unordered_set<std::string> domains;
  const std::string list = Gunzip(kBlocklistGz, kBlocklistGzLen);
  if (list.empty()) {
    SPDLOG_WARN(
        "Ad-block list could not be decompressed; ad blocking inactive");
    return domains;
  }

  std::size_t start = 0;
  while (start < list.size()) {
    std::size_t nl = list.find('\n', start);
    if (nl == std::string::npos) {
      nl = list.size();
    }
    std::string domain = ParseBlocklistLine(list.substr(start, nl - start));
    if (!domain.empty()) {
      domains.insert(std::move(domain));
    }
    start = nl + 1;
  }
  SPDLOG_INFO("Ad-block list loaded [domains={}]", domains.size());
  return domains;
}

}  // namespace

AdBlock::AdBlock() : AdBlock(LoadEmbeddedBlocklist()) {}

AdBlock::AdBlock(std::unordered_set<std::string> blocked_domains)
    : blocked_domains_(std::move(blocked_domains)) {}

bool AdBlock::IsBlocked(const std::string& domain) const {
  std::string d = domain;
  std::size_t dot = d.find('.');
  while (dot != std::string::npos) {
    if (blocked_domains_.contains(d)) {
      return true;
    }
    d = d.substr(dot + 1);
    dot = d.find('.');
  }
  return false;
}

fptn::common::network::IPPacketPtr AdBlock::ProcessOutgoingDns(
    const fptn::common::network::IPPacket& packet) const {
  if (!packet.IsDns()) {
    return nullptr;
  }
  const auto domain = packet.GetDnsDomain();
  if (!domain || !IsBlocked(*domain)) {
    return nullptr;
  }

  SPDLOG_INFO("Blocked DNS query [domain={}]", *domain);
  return packet.MakeDnsNullRouteResponse();
}

Result AdBlock::HandlePacket(
    fptn::common::network::IPPacketPtr packet, Direction direction) {
  if (direction == Direction::kOutgoing) {
    if (packet->IsDns()) {
      if (auto response = ProcessOutgoingDns(*packet)) {
        return {
            .packet = nullptr,
            .reply = std::move(response),
            .triggered = true,
        };
      }
    } else if (packet->IsTCP() && packet->IsIPv4()) {
      const auto [payload, size] = packet->GetTcpPayload();
      if (fptn::common::network::IsTlsClientHello(payload, size)) {
        const auto sni_opt = fptn::common::network::GetTlsSNI(payload, size);
        if (sni_opt.has_value() && IsBlocked(sni_opt.value())) {
          SPDLOG_INFO("Blocked TLS SNI {}", sni_opt.value());
          return {
              .packet = nullptr,
              .reply = nullptr,
              .triggered = true,
          };
        }
      }
    }
  }
  return {
      .packet = std::move(packet),
      .reply = nullptr,
      .triggered = false,
  };
}

}  // namespace fptn::plugin
