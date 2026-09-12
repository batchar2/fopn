/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "fptn-client/utils/speed_estimator/server_info.h"
#include "fptn-protocol-lib/https/censorship_strategy.h"
#include "fptn-protocol-lib/https/obfuscator/methods/obfuscator_interface.h"

namespace fptn::utils::speed_estimator {

struct LoginResult {
  ServerInfo server;
  std::string access_token;
};

// The outcome of a single probe: how long it took and why it failed. The
// measurements used to live inside the race and were discarded, so not a
// single number reached the outside - neither the server list nor its
// latency could be shown.
using ProbeCallback = std::function<void(const ServerInfo& server,
    std::uint32_t delay_ms,
    const std::string& error)>;

// How many servers are probed at once. Every server used to get its own
// thread, which is noticeable on a router with a large pool.
constexpr std::size_t kMaxProbeConcurrency = 8;

// Downloads a 100 KB test file: the number says something about throughput,
// not only about the round trip. Kept for the places that want that.
std::uint64_t GetDownloadTimeMs(const ServerInfo& server,
    const std::string& sni,
    int timeout,
    const std::string& md5_fingerprint,
    fptn::protocol::https::CensorshipStrategy censorship_strategy);

// A latency probe: the same TLS connection, but the request behind it asks
// for the DNS record - a few dozen bytes - instead of 100 KB. This is what
// sing-box measures with generate_204, and what a pool sweep needs: sweeping
// thirty-five servers every few minutes at 100 KB each moves megabytes for a
// number that the handshake alone already gives.
std::uint64_t GetLatencyMs(const ServerInfo& server,
    const std::string& sni,
    int timeout,
    const std::string& md5_fingerprint,
    fptn::protocol::https::CensorshipStrategy censorship_strategy);

std::optional<LoginResult> FindServerByLogin(const std::string& sni,
    const std::vector<ServerInfo>& servers,
    fptn::protocol::https::CensorshipStrategy censorship_strategy,
    int timeout_sec = 15,
    ProbeCallback on_probe = {});

};  // namespace fptn::utils::speed_estimator
