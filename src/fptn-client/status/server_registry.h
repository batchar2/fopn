/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "fptn-client/utils/speed_estimator/server_info.h"

namespace fptn::client::status {

using fptn::utils::speed_estimator::ServerInfo;

// How many recent measurements are kept per server. A single number is not
// enough: a probe lies now and then (the network blinked, the node was busy),
// and a decision made on one measurement moves the pool off a healthy server.
// A window allows reporting an average and a failure count instead.
constexpr std::size_t kMeasurementWindow = 10;

// How long a measurement stays meaningful. Without this the window is only
// bounded by its size, so with --probe-interval off (the default) a server
// keeps reporting the single reading taken at startup as if it were fresh -
// including "alive" for a node that died hours ago.
constexpr std::chrono::seconds kMeasurementTtl{15 * 60};

struct Measurement {
  std::uint64_t at_ms = 0;      // when it was taken, unix ms (for display)
  // Freshness is judged on the monotonic clock: a router starts with a wrong
  // wall clock and NTP moves it by a jump, which would otherwise expire every
  // measurement at once - or keep them fresh forever if the jump went back.
  std::chrono::steady_clock::time_point taken_at{};
  std::uint32_t delay_ms = 0;   // 0 means failure, as in the Clash API
  std::string error;            // why, when delay_ms == 0
};

struct ServerStats {
  std::uint32_t average_ms = 0;
  std::uint32_t min_ms = 0;
  std::uint32_t max_ms = 0;
  std::size_t total = 0;
  std::size_t failed = 0;
  bool alive = false;
};

// The server pool together with its measurements. The pool used to live in a
// local inside main() and died right after a server was picked, while the
// measured latency was discarded - not a single number reached the outside.
class ServerRegistry final {
 public:
  ServerRegistry() = default;
  ServerRegistry(const ServerRegistry&) = delete;
  ServerRegistry& operator=(const ServerRegistry&) = delete;

  // Sets the pool contents. Measurements for servers that stay on the list
  // are preserved - rebuilding the pool must not wipe the history.
  void Reset(const std::vector<ServerInfo>& servers);

  // The result of one probe. delay_ms == 0 counts as a failure.
  void RecordProbe(const ServerInfo& server,
      std::uint32_t delay_ms,
      const std::string& error = {});

  void SetActive(const ServerInfo& server);
  void ClearActive();

  [[nodiscard]] std::vector<ServerInfo> Servers() const;
  [[nodiscard]] std::optional<ServerInfo> FindByKey(const std::string& key)
      const;
  [[nodiscard]] std::optional<ServerInfo> FindByName(const std::string& name)
      const;
  [[nodiscard]] ServerStats Stats(const ServerInfo& server) const;

  // The Clash API compatible view: dashboards (yacd, metacubexd) and the
  // transparent proxies that talk to sing-box already read it.
  [[nodiscard]] nlohmann::json ToClashProxies() const;

  // The detailed native view: measurement window, errors, pool contents.
  [[nodiscard]] nlohmann::json ToJson() const;

  // The server key in the API is host:port, unique within the pool. Names
  // need not be unique: different tokens bring identical ones.
  [[nodiscard]] static std::string KeyOf(const ServerInfo& server);
  [[nodiscard]] static std::string DisplayName(const ServerInfo& server);

 private:
  struct Entry {
    ServerInfo info;
    std::deque<Measurement> window;
    std::uint64_t last_try_ms = 0;
    std::uint64_t last_ok_ms = 0;
    std::string last_error;
  };

  [[nodiscard]] static ServerStats Summarize(const Entry& entry);
  [[nodiscard]] nlohmann::json EntryToJson(const Entry& entry) const;

  mutable std::mutex mutex_;
  std::unordered_map<std::string, Entry> entries_;
  // token order, so the output stays stable between requests
  std::vector<std::string> order_;
  std::string active_key_;
};

}  // namespace fptn::client::status
