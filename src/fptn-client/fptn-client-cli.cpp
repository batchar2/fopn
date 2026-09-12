/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <iostream>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/resource.h>  // NOLINT(build/include_order)
#include <unistd.h>        // NOLINT(build/include_order)
#endif

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <fstream>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <argparse/argparse.hpp>
#include <fmt/format.h>  // NOLINT(build/include_order)
#include <fmt/ranges.h>  // NOLINT(build/include_order)
#include <nlohmann/json.hpp>  // NOLINT(build/include_order)

#include "common/logger/logger.h"
#include "common/network/ip_address.h"
#include "common/network/net_interface.h"
#include "common/utils/utils.h"

#include "config/config_file.h"
#include "fptn-protocol-lib/https/obfuscator/methods/detector.h"
#include "fptn-protocol-lib/time/time_provider.h"
#ifndef FPTN_OPENWRT
#include "plugins/adblock/adblock.h"
#endif
#include "plugins/blacklist/domain_blacklist.h"
#include "routing/route_manager.h"
// cppcheck-suppress missingInclude
#include "split_tunnel_domains.generated.h"  // NOLINT
#include "utils/signal/main_loop.h"
#include "vpn/vpn_manager.h"

#include "fptn-client/status/server_registry.h"
#include "fptn-client/status/status_server.h"
#include "fptn-client/socks/socks5_server.h"
#include "fptn-protocol-lib/https/socket_options.h"

namespace {

using fptn::utils::speed_estimator::ServerInfo;

#if defined(__linux__) || defined(__APPLE__)
// Every proxied session holds two descriptors, and the soft limit of 1024
// that daemons start with on a router runs out within a couple of hours of
// office traffic: accept starts returning EMFILE and the proxy stops taking
// connections while the process itself stays alive.
// Returns the limit the process ended up with: the SOCKS session cap is
// derived from it.
std::size_t RaiseFileDescriptorLimit() {
  struct rlimit limit {};
  if (getrlimit(RLIMIT_NOFILE, &limit) != 0) {
    return 0;
  }
  const rlim_t previous = limit.rlim_cur;
  if (limit.rlim_cur >= limit.rlim_max) {
    SPDLOG_INFO("File descriptor limit: {} (already at maximum)", previous);
    return static_cast<std::size_t>(limit.rlim_cur);
  }
  limit.rlim_cur = limit.rlim_max;
  if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
    SPDLOG_WARN("Failed to raise the file descriptor limit from {}", previous);
    return static_cast<std::size_t>(previous);
  }
  SPDLOG_INFO("File descriptor limit raised: {} -> {}", previous,
      limit.rlim_cur);
  return static_cast<std::size_t>(limit.rlim_cur);
}
#else
std::size_t RaiseFileDescriptorLimit() { return 0; }
#endif

// A session takes two descriptors, plus headroom for the tunnel, the logs
// and service sockets. A fixed number would lie here: a router may have a
// limit of 1024 or 4096, and the cap has to follow it rather than be a
// constant.
std::size_t DefaultMaxSocksSessions(std::size_t fd_limit) {
  constexpr std::size_t kReserved = 256;
  constexpr std::size_t kConservative = 128;
  constexpr std::size_t kCeiling = 4096;
  constexpr std::size_t kMinimum = 64;
  // An unknown limit (getrlimit failed, or the platform has none) must not
  // hand out the largest cap - that is exactly the case where the process
  // knows least. An unlimited one must not remove the ceiling either: with
  // RLIM_INFINITY the arithmetic below would allow billions of sessions.
  if (fd_limit == 0 || fd_limit == std::numeric_limits<std::size_t>::max()) {
    return kConservative;
  }
  if (fd_limit <= kReserved) {
    return std::max(kMinimum, fd_limit / 4);
  }
  return std::clamp((fd_limit - kReserved) / 2, kMinimum, kCeiling);
}

// Servers of every token in one pool, each carrying the credentials of the
// token it came from.
// A config file carries what does not fit on the command line: long keys and
// arrays of them. Values expand into the very same flags, so parsing, types
// and defaults stay shared. Flags given on the command line come afterwards
// and override the file.
std::vector<std::string> ExpandConfigFile(int argc, char* argv[]) {
  // Keys are written with dashes and with underscores alike; to the parser
  // they are the same flag.
  const auto normalize = [](std::string name) {
    if (name.starts_with("--")) {
      std::replace(name.begin(), name.end(), '_', '-');
    }
    return name;
  };

  std::vector<std::string> expanded;
  std::vector<std::string> rest;
  std::set<std::string> from_command_line;
  std::string config_path;

  expanded.emplace_back(argv[0]);
  for (int i = 1; i < argc; ++i) {
    const std::string arg = normalize(argv[i]);
    if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
      config_path = argv[++i];
      continue;
    }
    // argparse also accepts --config=/path, and so must this: otherwise the
    // file is quietly ignored and the client dies on a missing token.
    if (arg.starts_with("--config=")) {
      config_path = arg.substr(std::string_view("--config=").size());
      continue;
    }
    if (arg.starts_with("-c=")) {
      config_path = arg.substr(std::string_view("-c=").size());
      continue;
    }
    if (arg.starts_with("--")) {
      // Both spellings register the flag: --sni value and --sni=value must
      // suppress the same key from the file, or argparse sees it twice.
      const auto eq = arg.find('=');
      from_command_line.insert(
          eq == std::string::npos ? arg : arg.substr(0, eq));
    }
    rest.push_back(arg);
  }
  if (config_path.empty()) {
    for (auto& arg : rest) {
      expanded.push_back(std::move(arg));
    }
    return expanded;
  }

  std::ifstream file(config_path);
  if (!file.is_open()) {
    throw std::runtime_error("Cannot open config file: " + config_path);
  }
  nlohmann::json doc;
  file >> doc;
  if (!doc.is_object()) {
    throw std::runtime_error("Config file must contain a JSON object");
  }

  // Switch arguments take no value: in JSON they are booleans, but on the
  // command line they expand into a bare flag - otherwise the value lands
  // among the positional arguments and parsing fails.
  static constexpr std::string_view kFlagOnly[] = {"--disable-routing"};
  const auto is_flag_only = [](const std::string& flag) {
    return std::ranges::find(kFlagOnly, flag) != std::end(kFlagOnly);
  };
  const auto is_truthy = [](const nlohmann::json& value) {
    if (value.is_boolean()) {
      return value.get<bool>();
    }
    if (value.is_number()) {
      return value.get<double>() != 0;
    }
    if (value.is_string()) {
      const std::string text =
          fptn::common::utils::ToLowerCase(value.get<std::string>());
      return text == "true" || text == "1" || text == "yes" || text == "on";
    }
    return false;
  };

  const auto to_flag = [&normalize](const std::string& key) {
    return normalize("--" + key);
  };
  const auto append_value = [&expanded](
                                const std::string& flag,
                                const nlohmann::json& value) {
    expanded.push_back(flag);
    if (value.is_string()) {
      expanded.push_back(value.get<std::string>());
    } else if (value.is_boolean()) {
      expanded.emplace_back(value.get<bool>() ? "true" : "false");
    } else {
      expanded.push_back(value.dump());
    }
  };

  for (const auto& [key, value] : doc.items()) {
    const std::string flag = to_flag(key);
    if (value.is_null()) {
      continue;
    }
    // The same flag on the command line wins over the file. It is skipped
    // here rather than left to ordering: a repeated argument breaks parsing.
    if (from_command_line.contains(flag)) {
      continue;
    }
    if (is_flag_only(flag)) {
      if (is_truthy(value)) {
        expanded.push_back(flag);
      }
      continue;
    }
    if (value.is_array()) {
      // An array is a repeated flag: this is how several tokens are given.
      for (const auto& item : value) {
        append_value(flag, item);
      }
    } else {
      append_value(flag, value);
    }
  }

  for (auto& arg : rest) {
    expanded.push_back(std::move(arg));
  }
  return expanded;
}

std::vector<ServerInfo> CollectServers(const std::vector<std::string>& tokens,
    const std::string& sni,
    fptn::protocol::https::CensorshipStrategy censorship_strategy) {
  std::vector<ServerInfo> servers;

  for (const auto& token : tokens) {
    fptn::config::ConfigFile config(token, sni, censorship_strategy);
    config.Parse();
    for (auto server : config.GetServers()) {
      server.username = config.GetUsername();
      server.password = config.GetPassword();
      server.service_name = config.GetServiceName();
      servers.push_back(std::move(server));
    }
  }

  return servers;
}

// A name may be qualified with its service ("MyService/Server-1") when the
// same name occurs in more than one token.
std::optional<ServerInfo> FindPreferredServer(
    const std::vector<ServerInfo>& servers, const std::string& wanted) {
  const auto normalize = [](const std::string& value) {
    return fptn::common::utils::Trim(fptn::common::utils::ToLowerCase(value));
  };
  const std::string needle = normalize(wanted);
  if (needle.empty()) {
    return std::nullopt;
  }

  const auto it = std::ranges::find_if(servers, [&](const ServerInfo& server) {
    return normalize(server.name) == needle ||
           normalize(server.service_name + "/" + server.name) == needle;
  });
  if (it == servers.end()) {
    return std::nullopt;
  }
  return *it;
}

// Name for the log, qualified when the service is known.
std::string DescribeServer(const ServerInfo& server) {
  if (server.service_name.empty()) {
    return server.name;
  }
  return fmt::format("{}/{}", server.service_name, server.name);
}

// Both the bare name and "service/name" are matched, so a whole service can
// be excluded at once.
std::vector<ServerInfo> ExcludeServers(
    const std::vector<ServerInfo>& servers, const std::string& pattern) {
  if (pattern.empty()) {
    return servers;
  }

  const std::regex re(pattern, std::regex::ECMAScript | std::regex::icase);
  std::vector<ServerInfo> kept;
  for (const auto& server : servers) {
    if (std::regex_search(server.name, re) ||
        std::regex_search(DescribeServer(server), re)) {
      SPDLOG_INFO("Excluded server: {}", DescribeServer(server));
      continue;
    }
    kept.push_back(server);
  }
  return kept;
}

// The latency limit applied unless --max-ping says otherwise. It is a ceiling,
// not a target: the probe opens a TLS connection and downloads 100 KB, so even
// a healthy distant server reads as hundreds of milliseconds, and a busy one
// as a second or two. Five seconds is the point past which the tunnel is
// unusable rather than merely slow - low enough to leave a dying server,
// high enough not to chase normal jitter. 0 turns the check off.
constexpr int kDefaultMaxPingMs = 5000;

// How long a single probe is given to answer. Past this the server counts as
// dead for that round, so it also sets how long a sweep can stall on a node
// that accepts the connection and then says nothing.
constexpr int kProbeTimeoutSec = 5;

// How often the whole pool is re-measured, and how much better another server
// must be before the tunnel moves to it. sing-box sweeps every three minutes
// and switches on 50 ms, because switching an outbound there costs nothing.
// Here it costs a second of silence and a fresh login against a server that
// counts sessions per user, so the threshold is an order larger: the point is
// to leave a server that has gone bad, not to chase the fastest one.
constexpr std::chrono::seconds kDefaultProbeInterval{180};
constexpr int kDefaultSwitchToleranceMs = 500;

// A floor under how often the tunnel may move on latency alone. Without it a
// pool with two servers a few hundred milliseconds apart would swap on every
// sweep, and each swap is a second without traffic.
constexpr std::chrono::minutes kMinAutoSwitchGap{10};

// The login race returns whichever server answers first, which says nothing
// about its speed: with a limit set the winner is measured, dropped if it is
// over, and the race repeated. Three rounds, then the best of a bad lot.
std::optional<fptn::utils::speed_estimator::LoginResult> SelectServer(
    std::vector<ServerInfo> servers,
    const std::string& sni,
    fptn::protocol::https::CensorshipStrategy censorship_strategy,
    int max_ping_ms,
    const std::shared_ptr<fptn::client::status::ServerRegistry>& registry) {
  std::optional<fptn::utils::speed_estimator::LoginResult> last;

  for (int round = 0; round < 3 && !servers.empty(); ++round) {
    auto result = fptn::utils::speed_estimator::FindServerByLogin(sni, servers,
        censorship_strategy, 10,
        [registry](const ServerInfo& server, std::uint32_t delay_ms,
            const std::string& error) {
          if (registry) {
            registry->RecordProbe(server, delay_ms, error);
          }
        });
    if (!result) {
      return last;
    }
    if (max_ping_ms <= 0) {
      return result;
    }

    const auto ms = fptn::utils::speed_estimator::GetLatencyMs(
        result->server, sni, 5, result->server.md5_fingerprint,
        censorship_strategy);
    if (ms <= static_cast<std::uint64_t>(max_ping_ms)) {
      return result;
    }

    if (ms == UINT64_MAX) {
      SPDLOG_WARN("{} did not answer the latency check - trying another",
          DescribeServer(result->server));
    } else {
      SPDLOG_WARN("{} answered in {} ms, over the {} ms limit - trying another",
          DescribeServer(result->server), ms, max_ping_ms);
    }
    last = result;
    std::erase_if(servers, [&](const ServerInfo& server) {
      return server.host == result->server.host &&
             server.port == result->server.port;
    });
  }

  return last;
}

// Three readings in a row past the limit and the watchdog asks to shut down.
// It used to send the process SIGTERM: crude in a multi-threaded program,
// cleanup was skipped, and under ZeroBlock - which starts the helper itself -
// a vanishing PID loses it for good. Now the watchdog simply stops the
// tunnel: the main loop exits on its own, SOCKS and routes are torn down
// properly, and procd brings the process back.
// The limit is on by default (kDefaultMaxPingMs), so this runs unless the
// pool holds a single server, the server is pinned by name, or --max-ping is
// set to 0.
// How many times the startup login race is retried before giving up, and how
// long to wait between attempts.
constexpr int kStartupLoginAttempts = 3;
constexpr std::chrono::seconds kStartupRetryDelay{5};

// A scheduled sweep over the whole pool. Without it the registry holds a
// single measurement - the one taken while picking a server at startup - and
// the server list shows long-stale numbers. A server that was down at launch
// and has recovered since would otherwise never become a candidate again.
class PoolMonitor final {
 public:
  PoolMonitor(std::shared_ptr<fptn::client::status::ServerRegistry> registry,
      std::string sni,
      fptn::protocol::https::CensorshipStrategy censorship_strategy,
      std::chrono::seconds interval,
      std::function<void()> on_sweep = {})
      : registry_(std::move(registry)),
        sni_(std::move(sni)),
        censorship_strategy_(censorship_strategy),
        interval_(interval),
        on_sweep_(std::move(on_sweep)) {
    thread_ = std::thread([this] { Run(); });
  }

  ~PoolMonitor() {
    {
      const std::lock_guard<std::mutex> lock(mutex_);
      running_ = false;
    }
    cv_.notify_all();
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  PoolMonitor(const PoolMonitor&) = delete;
  PoolMonitor& operator=(const PoolMonitor&) = delete;

 private:
  void Run() {
    while (Wait(interval_)) {
      Sweep();
      if (Running() && on_sweep_) {
        on_sweep_();
      }
    }
  }

  // Probed one after another, a pool of thirty-five servers with a few dead
  // ones in it takes longer to sweep than the interval between sweeps: every
  // node that does not answer costs the whole timeout. The race at startup
  // has the same shape and solves it the same way.
  void Sweep() {
    const auto servers = registry_->Servers();
    if (servers.empty()) {
      return;
    }
    std::atomic<std::size_t> next{0};
    const std::size_t workers = std::min<std::size_t>(
        fptn::utils::speed_estimator::kMaxProbeConcurrency, servers.size());

    std::vector<std::thread> pool;
    pool.reserve(workers);
    for (std::size_t worker = 0; worker < workers; ++worker) {
      pool.emplace_back([this, &servers, &next] {
        for (;;) {
          const std::size_t index = next.fetch_add(1);
          if (index >= servers.size() || !Running()) {
            return;
          }
          const auto& server = servers[index];
          const auto ms = fptn::utils::speed_estimator::GetLatencyMs(
              server, sni_, kProbeTimeoutSec, server.md5_fingerprint,
              censorship_strategy_);
          const std::uint32_t delay =
              ms == UINT64_MAX ? 0 : static_cast<std::uint32_t>(ms);
          registry_->RecordProbe(
              server, delay, delay == 0 ? "probe failed" : "");
        }
      });
    }
    for (auto& thread : pool) {
      thread.join();
    }
  }

  bool Running() {
    const std::lock_guard<std::mutex> lock(mutex_);
    return running_;
  }

  bool Wait(std::chrono::seconds period) {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait_for(lock, period, [this] { return !running_; });
    return running_;
  }

  const std::shared_ptr<fptn::client::status::ServerRegistry> registry_;
  const std::string sni_;
  const fptn::protocol::https::CensorshipStrategy censorship_strategy_;
  const std::chrono::seconds interval_;
  const std::function<void()> on_sweep_;

  std::mutex mutex_;
  std::condition_variable cv_;
  bool running_ = true;
  std::thread thread_;
};

// The fastest server that is currently answering, by the average of its
// measurement window rather than the last reading - one probe lies often
// enough that a decision made on it moves the tunnel for nothing.
std::optional<std::pair<ServerInfo, std::uint32_t>> BestServer(
    const fptn::client::status::ServerRegistry& registry) {
  std::optional<std::pair<ServerInfo, std::uint32_t>> best;
  for (const auto& server : registry.Servers()) {
    const auto stats = registry.Stats(server);
    if (!stats.alive || stats.average_ms == 0) {
      continue;
    }
    if (!best || stats.average_ms < best->second) {
      best = std::make_pair(server, stats.average_ms);
    }
  }
  return best;
}

class LatencyWatchdog final {
 public:
  LatencyWatchdog(ServerInfo server,
      std::string sni,
      fptn::protocol::https::CensorshipStrategy censorship_strategy,
      int max_ping_ms,
      std::function<void()> on_over_limit,
      std::shared_ptr<fptn::client::status::ServerRegistry> registry = {})
      : server_(std::move(server)),
        sni_(std::move(sni)),
        censorship_strategy_(censorship_strategy),
        max_ping_ms_(max_ping_ms),
        on_over_limit_(std::move(on_over_limit)),
        registry_(std::move(registry)) {
    thread_ = std::thread([this] { Run(); });
  }

  ~LatencyWatchdog() {
    {
      const std::lock_guard<std::mutex> lock(mutex_);
      running_ = false;
    }
    cv_.notify_all();
    if (thread_.joinable()) {
      thread_.join();
    }
  }

 private:
  void Run() {
    int over_limit = 0;
    while (Wait(std::chrono::seconds(60))) {
      const auto ms = fptn::utils::speed_estimator::GetLatencyMs(
          server_, sni_, 5, server_.md5_fingerprint, censorship_strategy_);
      if (registry_) {
        // UINT64_MAX means the server did not answer; in the registry a
        // failure is stored as zero, as the Clash API does.
        const std::uint32_t delay =
            ms == UINT64_MAX ? 0 : static_cast<std::uint32_t>(ms);
        registry_->RecordProbe(
            server_, delay, delay == 0 ? "latency check failed" : "");
      }
      if (ms <= static_cast<std::uint64_t>(max_ping_ms_)) {
        over_limit = 0;
        continue;
      }
      if (++over_limit < 3) {
        continue;
      }
      SPDLOG_WARN("{} is over the {} ms limit, switching server",
          DescribeServer(server_), max_ping_ms_);
      if (on_over_limit_) {
        on_over_limit_();
      }
      return;
    }
  }

  bool Wait(std::chrono::seconds period) {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait_for(lock, period, [this] { return !running_; });
    return running_;
  }

  const ServerInfo server_;
  const std::string sni_;
  const fptn::protocol::https::CensorshipStrategy censorship_strategy_;
  const int max_ping_ms_;
  const std::function<void()> on_over_limit_;
  const std::shared_ptr<fptn::client::status::ServerRegistry> registry_;

  std::mutex mutex_;
  std::condition_variable cv_;
  bool running_ = true;
  std::thread thread_;
};

// The sni-spoofing-* names are inherited from earlier versions: in practice
// they always enabled Reality mode. They are kept as aliases of the canonical
// reality-* values so that existing configs keep working.
const std::map<std::string, std::string>& BypassAliases() {
  static const std::map<std::string, std::string> kAliases = {
      {"sni-spoofing-chrome-149", "reality-chrome-149"},
      {"sni-spoofing-chrome-148", "reality-chrome-148"},
      {"sni-spoofing-chrome-147", "reality-chrome-147"},
      {"sni-spoofing-chrome-146", "reality-chrome-146"},
      {"sni-spoofing-chrome-145", "reality-chrome-145"},
      {"sni-spoofing-firefox-151", "reality-firefox-151"},
      {"sni-spoofing-firefox-150", "reality-firefox-150"},
      {"sni-spoofing-firefox-149", "reality-firefox-149"},
      {"sni-spoofing-yandex-26-4", "reality-yandex-26-4"},
      {"sni-spoofing-yandex-26-3", "reality-yandex-26-3"},
      {"sni-spoofing-yandex-25", "reality-yandex-25"},
      {"sni-spoofing-yandex-24", "reality-yandex-24"},
      {"sni-spoofing-safari-26-5", "reality-safari-26-5"},
      {"sni-spoofing-safari-26-4", "reality-safari-26-4"},
  };
  return kAliases;
}

const std::map<std::string, fptn::protocol::https::CensorshipStrategy>&
BypassStrategies() {
  using fptn::protocol::https::CensorshipStrategy;
  static const std::map<std::string, CensorshipStrategy> kStrategies = {
      {"sni", CensorshipStrategy::kSni},
      {"obfuscation", CensorshipStrategy::kTlsObfuscator},
      {"reality", CensorshipStrategy::kSniRealityMode},
      /* Chrome */
      {"reality-chrome-149", CensorshipStrategy::kSniRealityModeChrome149},
      {"reality-chrome-148", CensorshipStrategy::kSniRealityModeChrome148},
      {"reality-chrome-147", CensorshipStrategy::kSniRealityModeChrome147},
      {"reality-chrome-146", CensorshipStrategy::kSniRealityModeChrome146},
      {"reality-chrome-145", CensorshipStrategy::kSniRealityModeChrome145},
      /* Firefox */
      {"reality-firefox-151", CensorshipStrategy::kSniRealityModeFirefox151},
      {"reality-firefox-150", CensorshipStrategy::kSniRealityModeFirefox150},
      {"reality-firefox-149", CensorshipStrategy::kSniRealityModeFirefox149},
      /* Yandex */
      {"reality-yandex-26-4", CensorshipStrategy::kSniRealityModeYandex26_4},
      {"reality-yandex-26-3", CensorshipStrategy::kSniRealityModeYandex26_3},
      {"reality-yandex-25", CensorshipStrategy::kSniRealityModeYandex25},
      {"reality-yandex-24", CensorshipStrategy::kSniRealityModeYandex24},
      /* Safari */
      {"reality-safari-26-5", CensorshipStrategy::kSniRealityModeSafari26_5},
      {"reality-safari-26-4", CensorshipStrategy::kSniRealityModeSafari26_4},
  };
  return kStrategies;
}

// Everything --bypass-method accepts: canonical names plus the aliases.
const std::set<std::string>& BypassMethodNames() {
  static const std::set<std::string> kNames = [] {
    std::set<std::string> names;
    for (const auto& item : BypassStrategies()) {
      names.insert(item.first);
    }
    for (const auto& item : BypassAliases()) {
      names.insert(item.first);
    }
    return names;
  }();
  return kNames;
}

fptn::protocol::https::CensorshipStrategy ResolveBypassMethod(
    const std::string& name) {
  std::string method = name;
  const auto alias = BypassAliases().find(method);
  if (alias != BypassAliases().end()) {
    method = alias->second;
  }
  const auto found = BypassStrategies().find(method);
  if (found != BypassStrategies().end()) {
    return found->second;
  }
  return fptn::protocol::https::CensorshipStrategy::kSniRealityModeYandex26_4;
}

}  // namespace

int main(int argc, char* argv[]) {
#if defined(__linux__) || defined(__APPLE__)
  if (geteuid() != 0) {
    std::cerr << "You must be root to run this program." << std::endl;
    return EXIT_FAILURE;
  }
#endif
  try {
    const std::size_t fd_limit = RaiseFileDescriptorLimit();
    const std::set<std::string> tunnel_modes = {"exclude", "include"};

    using fptn::protocol::https::obfuscator::GetObfuscatorByName;
    using fptn::protocol::https::obfuscator::GetObfuscatorNames;

    argparse::ArgumentParser args("fptn-client", FPTN_VERSION);
    args.add_argument("-c", "--config")
        .default_value(std::string(""))
        .help("Path to a JSON config file with the same keys as the flags");
    // Required arguments
    args.add_argument("--access-token")
        .append()
        .default_value(std::vector<std::string>{})
        .help("Access token. Repeat the flag to use several keys at once");
    // Optional arguments
    args.add_argument("--out-network-interface")
        .default_value("")
        .help("Network out interface");
    args.add_argument("--gateway-ip")
        .default_value("")
        .help("Your default gateway IPv4 address");
    args.add_argument("--gateway-ipv6")
        .default_value("")
        .help("Your default gateway IPv6 address");
    args.add_argument("--mtu-size")
        .default_value(FPTN_DEFAULT_MTU_SIZE)
        .help("MTU size")
        .action([](const std::string& v) -> int {
          if (v.empty()) {
            return FPTN_DEFAULT_MTU_SIZE;
          }
          int mtu_size = 0;
          const auto [end, error] =
              std::from_chars(v.data(), v.data() + v.size(), mtu_size);
          if (error != std::errc() || end != v.data() + v.size()) {
            throw std::runtime_error(
                fmt::format("Invalid MTU size '{}'. It must be a number", v));
          }
          if (mtu_size < 576 || mtu_size > 65535) {
            throw std::runtime_error(fmt::format(
                "MTU size {} is out of range [576..65535]", mtu_size));
          }
          return mtu_size;
        });
    args.add_argument("--preferred-server")
        .default_value("")
        .help("Preferred server name (case-insensitive)");
    args.add_argument("--exclude-servers")
        .default_value(std::string(""))
        .help(
            "Regular expression: servers whose name matches it are left out "
            "of the pool, e.g. 'Russia|Vietnam'");
    args.add_argument("--max-ping")
        .default_value(kDefaultMaxPingMs)
        .help(
            "Latency limit in milliseconds (default 5000, 0 disables the "
            "check). A server over it is not picked, and the one in use is "
            "replaced once it stays over the limit")
        .action([](const std::string& v) -> int {
          if (v.empty()) {
            return 0;
          }
          int value = 0;
          const auto [end, error] =
              std::from_chars(v.data(), v.data() + v.size(), value);
          if (error != std::errc() || end != v.data() + v.size() ||
              value < 0) {
            throw std::runtime_error(
                fmt::format("Invalid --max-ping value '{}'", v));
          }
          return value;
        });
    args.add_argument("--tun-interface-name")
        .default_value("tun0")
        .help("Network interface name")
        .action([](const std::string& v) -> std::string {
          return v.empty() ? "tun0" : v;
        });
    args.add_argument("--tun-interface-ip")
        .default_value(FPTN_CLIENT_DEFAULT_ADDRESS_IP4)
        .help("Network interface IPv4 address")
        .action([](const std::string& v) -> std::string {
          return v.empty() ? FPTN_CLIENT_DEFAULT_ADDRESS_IP4 : v;
        });
    args.add_argument("--tun-interface-ipv6")
        .default_value(FPTN_CLIENT_DEFAULT_ADDRESS_IP6)
        .help("Network interface IPv6 address")
        .action([](const std::string& v) -> std::string {
          return v.empty() ? FPTN_CLIENT_DEFAULT_ADDRESS_IP6 : v;
        });
    args.add_argument("--sni")
        .default_value(FPTN_DEFAULT_SNI)
        .help(
            "Domain name for SNI in TLS handshake (used to obfuscate VPN "
            "traffic)")
        .action([](const std::string& v) -> std::string {
          return v.empty() ? FPTN_DEFAULT_SNI : v;
        });
    args.add_argument("--blacklist-domains")
        .default_value(FPTN_CLIENT_DEFAULT_BLACKLIST_DOMAINS)
        .help(
            "Completely block access to the main domain AND all its "
            "subdomains\n"
            "Format: example.com,sub.site.org\n"
            "Example: ria.ru blocks ria.ru and all *.ria.ru sites");
#ifndef FPTN_OPENWRT
    args.add_argument("--enable-ad-block")
        .help("Block ads and trackers at the DNS level")
        .default_value(true)
        .nargs(1)
        .action([](const std::string& value) {
          if (value.empty()) {
            return true;
          }
          if (fptn::common::utils::ToLowerCase(value) == "true") {
            return true;
          }
          if (fptn::common::utils::ToLowerCase(value) == "false") {
            return false;
          }
          throw std::runtime_error("Value must be true/false");
        });
#endif
    // Method to bypass censorship
    args.add_argument("--bypass-method")
        .default_value("sni-spoofing-yandex-26-4")
        .help(
            "Method to bypass censorship:\n"
            "   sni                     - plain SNI spoofing\n"
            "   obfuscation             - TLS obfuscation\n"
            "   reality                 - Reality without a browser profile\n"
            "                             (servers may refuse it - see docs)\n"
            "   reality-chrome-145..149 - Reality with a Chrome handshake\n"
            "   reality-firefox-149..151 - Reality with a Firefox handshake\n"
            "   reality-yandex-24, -25, -26-3, -26-4 - Yandex handshake\n"
            "   reality-safari-26-4, -26-5 - Safari handshake\n"
            "The sni-spoofing-* names are kept as aliases of the matching\n"
            "reality-* method and mean the same thing.\n")
        .action([](const std::string& v) -> std::string {
          if (v.empty() || v == "sni-spoofing") {
            return "sni-spoofing-yandex-26-4";
          }
          if (!BypassMethodNames().contains(v)) {
            throw std::runtime_error(
                fmt::format("Invalid bypass method '{}'. Choose from: {}", v,
                    fmt::join(BypassMethodNames(), ", ")));
          }
          return v;
        });
    args.add_argument("--connection-strategy")
        .default_value("rolling-tunnel")
        .help(
            "Connection strategy:\n"
            "  rolling-tunnel        - a single tunnel renewed every 10 mins\n"
            "  dual-rolling-tunnel   - two rolling tunnels in parallel\n"
            "  triple-rolling-tunnel - three rolling tunnels in parallel\n")
        .action([](const std::string& v) -> std::string {
          if (v.empty()) {
            return "rolling-tunnel";
          }
          if (v != "rolling-tunnel" && v != "dual-rolling-tunnel" &&
              v != "triple-rolling-tunnel") {
            throw std::runtime_error(fmt::format(
                "Invalid connection strategy '{}'. Choose from: "
                "rolling-tunnel, dual-rolling-tunnel, triple-rolling-tunnel",
                v));
          }
          return v;
        });
    // networks
    args.add_argument("--exclude-tunnel-networks")
        .default_value(FPTN_CLIENT_DEFAULT_EXCLUDE_NETWORKS)
        .help(
            "Networks that always bypass VPN tunnel\n"
            "Traffic to these networks goes directly, never through VPN\n"
            "Format: CIDR notation or IP addresses, comma-separated\n"
            "Example: 10.0.0.0/8,192.168.0.0/16");
    args.add_argument("--include-tunnel-networks")
        .default_value("")
        .help(
            "Networks that always use VPN tunnel\n"
            "Traffic to these networks always goes through VPN\n"
            "Format: CIDR notation or IP addresses, comma-separated\n"
            "Example: 172.16.0.0/12,192.168.99.0/24");
    // Split-tunneling arguments
    args.add_argument("--enable-split-tunnel")
        .help(
            "Enable split tunneling - allows different traffic routing for "
            "different sites.\n"
            "When enabled, you can configure which sites use VPN and which go"
            "directly.\n"
            "Use with --split-tunnel-mode and --split-tunnel-domains for "
            "configuration.")
        .default_value(false)
        .nargs(1)
        .action([](const std::string& value) {
          if (value.empty()) {
            return true;
          }
          if (fptn::common::utils::ToLowerCase(value) == "true") {
            return true;
          }
          if (fptn::common::utils::ToLowerCase(value) == "false") {
            return false;
          }
          throw std::runtime_error("Value must be true/false");
        });
    args.add_argument("--split-tunnel-mode")
        .default_value("exclude")
        .help(
            "Defines traffic routing strategy for split tunneling.\n"
            "Modes:\n"
            "  exclude - Bypass VPN for specified domains, route all other "
            "traffic through VPN.\n"
            "  include - Route only specified domains through VPN, bypass VPN "
            "for all other traffic.\n")
        .action([&tunnel_modes](const std::string& v) -> std::string {
          if (v.empty()) {
            return "exclude";
          }
          if (!tunnel_modes.contains(v)) {
            throw std::runtime_error(
                fmt::format("Invalid tunnel mode '{}'. Choose from: {}", v,
                    fmt::join(tunnel_modes, ", ")));
          }
          return v;
        });
    args.add_argument("--split-tunnel-domains")
        .default_value(std::string(""))
        .help(
            "List websites that should either use or bypass VPN\n"
            "\n"
            "How it works:\n"
            "  If --tunnel-mode=exclude: VPN skips these sites\n"
            "  If --tunnel-mode=include: VPN only for these sites\n"
            "Format: com,another.com,sub.domainname.com\n"
            "Empty (default) uses the built-in list");
    // parse cmd arguments
    /* --- integration with transparent proxies (ZeroBlock and friends) --- */
    args.add_argument("--disable-routing")
        .flag()
        .help(
            "Do not touch system routing tables. The TUN interface is brought "
            "up, but the default route stays untouched. Use together with "
            "--socks-listen when another daemon owns the routing");
    args.add_argument("--routing-mark")
        .default_value(std::string(""))
        .help(
            "Set SO_MARK (hex or decimal) on all outgoing sockets so that "
            "firewall rules can exclude client traffic from DPI-bypass or "
            "transparent proxying (e.g. 0x40000000)");
    args.add_argument("--socks-listen")
        .default_value(std::string(""))
        .help(
            "Run a SOCKS5 server that forwards connections through the tunnel, "
            "e.g. 127.0.0.1:1080. Implies --disable-routing");
    args.add_argument("--socks-max-sessions")
        .default_value(0)
        .scan<'i', int>()
        .help(
            "Limit of simultaneous SOCKS5 sessions. 0 (default) derives it "
            "from the file descriptor limit of the process");
    args.add_argument("--socks-route-table")
        .default_value(1080)
        .scan<'i', int>()
        .help("Routing table id used for SOCKS traffic (default: 1080)");
    args.add_argument("--status-listen")
        .default_value(std::string(""))
        .help(
            "Serve a local HTTP status API with the server pool and their "
            "latency, e.g. 127.0.0.1:9091. The JSON matches the Clash API, so "
            "existing dashboards and transparent proxies can read it as is");
    args.add_argument("--status-secret")
        .default_value(std::string(""))
        .help(
            "Token for the status API: requests must carry "
            "'Authorization: Bearer <token>'. Empty means no check");
    args.add_argument("--probe-interval")
        .default_value(static_cast<int>(kDefaultProbeInterval.count()))
        .scan<'i', int>()
        .help(
            "Re-measure every server in the pool every N seconds, so the "
            "status API shows fresh latency instead of one reading taken at "
            "startup, and a server that recovers becomes a candidate again. "
            "Default 180, 0 disables it");
    args.add_argument("--switch-tolerance")
        .default_value(kDefaultSwitchToleranceMs)
        .scan<'i', int>()
        .help(
            "How much faster another server must be, in milliseconds, before "
            "the tunnel moves to it on its own. Default 500, 0 disables "
            "moving on latency alone - a server that stops answering is still "
            "left");

    try {
      args.parse_args(ExpandConfigFile(argc, argv));
    } catch (const std::runtime_error& err) {
      std::cerr << err.what() << std::endl;
      std::cerr << args;
      return EXIT_FAILURE;
    }


    if (fptn::logger::init("fptn-client-cli")) {
      SPDLOG_INFO("Application started successfully.");
    } else {
      std::cerr << "Logger initialization failed. Exiting application."
                << std::endl;
      return EXIT_FAILURE;
    }

    fptn::time::TimeProvider::Instance();

#ifdef __linux__
    fptn::routing::HealStaleResolvConf();
#endif

    /* parse cmd args */
    const auto out_network_interface_name =
        args.get<std::string>("--out-network-interface");

    const auto param_gateway_ip = args.get<std::string>("--gateway-ip");
    const auto gateway_ip =
        fptn::common::network::IPv4Address::Create(param_gateway_ip);

    const auto mtu_size = args.get<int>("--mtu-size");

    const auto param_gateway_ipv6 = args.get<std::string>("--gateway-ipv6");
    const auto gateway_ipv6 =
        fptn::common::network::IPv6Address::Create(param_gateway_ipv6);

    const auto preferred_server = args.get<std::string>("--preferred-server");
    const auto exclude_servers = args.get<std::string>("--exclude-servers");
    const auto max_ping = args.get<int>("--max-ping");

    const auto tun_interface_name =
        args.get<std::string>("--tun-interface-name");
    const auto tun_interface_address_ipv4 =
        fptn::common::network::IPv4Address::Create(
            args.get<std::string>("--tun-interface-ip"));
    const auto tun_interface_address_ipv6 =
        fptn::common::network::IPv6Address::Create(
            args.get<std::string>("--tun-interface-ipv6"));
    const auto sni = args.get<std::string>("--sni");

    const auto socks_listen = args.get<std::string>("--socks-listen");
    const bool socks_enabled = !socks_listen.empty();
    const int socks_max_sessions_arg = args.get<int>("--socks-max-sessions");
    const std::size_t max_socks_sessions =
        socks_max_sessions_arg > 0
            ? static_cast<std::size_t>(socks_max_sessions_arg)
            : DefaultMaxSocksSessions(fd_limit);
    if (socks_enabled) {
      SPDLOG_INFO("SOCKS5 session limit: {} (fd limit {})", max_socks_sessions,
          fd_limit);
    }
    const bool disable_routing =
        args.get<bool>("--disable-routing") || socks_enabled;
    const auto socks_route_table = args.get<int>("--socks-route-table");
    const auto status_listen = args.get<std::string>("--status-listen");
    const auto status_secret = args.get<std::string>("--status-secret");
    const auto probe_interval = args.get<int>("--probe-interval");
    const auto switch_tolerance = args.get<int>("--switch-tolerance");

    std::uint32_t routing_mark = 0;
    {
      const auto raw_mark = args.get<std::string>("--routing-mark");
      if (!raw_mark.empty()) {
        try {
          // base 0 => understands both the 0x prefix and decimal notation
          routing_mark =
              static_cast<std::uint32_t>(std::stoul(raw_mark, nullptr, 0));
        } catch (const std::exception&) {
          SPDLOG_ERROR("Invalid --routing-mark value: {}", raw_mark);
          return EXIT_FAILURE;
        }
      }
    }
    if (routing_mark != 0) {
      fptn::protocol::https::SetRoutingMark(routing_mark);
    }

    std::string socks_address = "127.0.0.1";
    std::uint16_t socks_port = 1080;
    if (socks_enabled) {
      const auto colon = socks_listen.rfind(':');
      if (colon == std::string::npos) {
        SPDLOG_ERROR(
            "Invalid --socks-listen value '{}', expected <address>:<port>",
            socks_listen);
        return EXIT_FAILURE;
      }
      socks_address = socks_listen.substr(0, colon);
      try {
        socks_port = static_cast<std::uint16_t>(
            std::stoi(socks_listen.substr(colon + 1)));
      } catch (const std::exception&) {
        SPDLOG_ERROR("Invalid port in --socks-listen '{}'", socks_listen);
        return EXIT_FAILURE;
      }
    }

    /* check gateway address */
    const auto using_gateway_ip =
        gateway_ip.IsEmpty()
            ? fptn::routing::GetDefaultGatewayIPAddress(tun_interface_name)
            : fptn::common::network::IPv4Address::Create(gateway_ip);
    const auto using_gateway_ipv6 =
        gateway_ipv6.IsEmpty()
            ? fptn::routing::GetDefaultGatewayIPv6Address(tun_interface_name)
            : fptn::common::network::IPv6Address::Create(gateway_ipv6);
    if (using_gateway_ip.IsEmpty() && !disable_routing) {
      SPDLOG_ERROR(
          "Unable to find the default gateway IP address. "
          "Please check your connection and make sure no other VPN is active. "
          "If the error persists, specify the gateway address in the FPTN "
          "settings using your router's IP "
          "address with the \"--gateway-ip\" option. If the issue "
          "remains unresolved, please contact the developer via Telegram "
          "@fptn_chat.");
      return EXIT_FAILURE;
    }

    using fptn::protocol::https::CensorshipStrategy;
    const auto bypass_method = args.get<std::string>("--bypass-method");
    const CensorshipStrategy censorship_strategy =
        ResolveBypassMethod(bypass_method);

    using fptn::protocol::connection::strategies::ConnectionStrategy;
    const auto connection_strategy_name =
        args.get<std::string>("--connection-strategy");
    ConnectionStrategy connection_strategy =
        ConnectionStrategy::kSingleRollingTunnel;
    if (connection_strategy_name == "browser-mimicry") {
      connection_strategy = ConnectionStrategy::kBrowserMimicry;
    } else if (connection_strategy_name == "dual-rolling-tunnel") {
      connection_strategy = ConnectionStrategy::kDualRollingTunnel;
    } else if (connection_strategy_name == "triple-rolling-tunnel") {
      connection_strategy = ConnectionStrategy::kTripleRollingTunnel;
    }

    /* parse network lists */
    const auto exclude_networks_str =
        args.get<std::string>("--exclude-tunnel-networks");
    const auto include_networks_str =
        args.get<std::string>("--include-tunnel-networks");

    const std::vector<std::string> exclude_networks =
        fptn::common::utils::SplitCommaSeparated(exclude_networks_str);
    const std::vector<std::string> include_networks =
        fptn::common::utils::SplitCommaSeparated(include_networks_str);

    /* parse split-tunneling parameters */
#ifndef FPTN_OPENWRT
    const bool enable_ad_block = args.get<bool>("--enable-ad-block");
#endif
    const bool enable_split_tunnel = args.get<bool>("--enable-split-tunnel");
    const auto tunnel_mode = args.get<std::string>("--split-tunnel-mode");
    const auto split_domains_str =
        args.get<std::string>("--split-tunnel-domains");
    const auto blacklist_domains_str =
        args.get<std::string>("--blacklist-domains");

    std::vector<std::string> split_domains =
        fptn::common::utils::SplitCommaSeparated(split_domains_str);
    if (split_domains.empty()) {
      split_domains.assign(std::begin(fptn::defaults::kSplitTunnelDomains),
          std::end(fptn::defaults::kSplitTunnelDomains));
    }
    const std::vector<std::string> blacklist_domains =
        fptn::common::utils::SplitCommaSeparated(blacklist_domains_str);

    /* check config */
    const auto access_tokens =
        args.get<std::vector<std::string>>("--access-token");
    if (access_tokens.empty()) {
      SPDLOG_ERROR("--access-token is required");
      return EXIT_FAILURE;
    }
    // The SOCKS port is opened before a server is picked: ZeroBlock waits
    // only seconds for the helper, while the login race takes up to a minute.
    // Connections rest in the kernel backlog until the tunnel comes up.
    fptn::socks::Socks5ServerPtr socks_server;
    if (socks_enabled) {
      socks_server = std::make_unique<fptn::socks::Socks5Server>(
          fptn::socks::Socks5Server::Config{
              .listen_address = socks_address,
              .listen_port = socks_port,
              .tun_interface_name = tun_interface_name,
              .max_sessions = max_socks_sessions});
      if (!socks_server->Listen()) {
        SPDLOG_ERROR("Failed to open the SOCKS5 port");
        return EXIT_FAILURE;
      }
    }

    fptn::utils::speed_estimator::ServerInfo selected_server;
    std::string pre_obtained_token;
    bool server_pinned = false;
    // The registry outlives server selection: the pool and its measurements
    // are needed for the whole run, not just at startup.
    auto registry = std::make_shared<fptn::client::status::ServerRegistry>();

    // The status endpoint comes up before the login race, for the same reason
    // the SOCKS port does: a supervising daemon polls it within seconds, while
    // working through a large pool takes up to a minute. Until a server is
    // chosen the pool reads as empty - which is still an answer, unlike a
    // refused connection.
    std::unique_ptr<fptn::client::status::StatusServer> status_server;
    if (!status_listen.empty()) {
      const auto colon = status_listen.rfind(':');
      if (colon == std::string::npos) {
        SPDLOG_ERROR(
            "Invalid --status-listen value '{}', expected <address>:<port>",
            status_listen);
        return EXIT_FAILURE;
      }
      fptn::client::status::StatusServer::Options options;
      options.listen_address = status_listen.substr(0, colon);
      options.secret = status_secret;
      try {
        options.listen_port = static_cast<std::uint16_t>(
            std::stoi(status_listen.substr(colon + 1)));
      } catch (const std::exception&) {
        SPDLOG_ERROR("Invalid port in --status-listen '{}'", status_listen);
        return EXIT_FAILURE;
      }
      status_server = std::make_unique<fptn::client::status::StatusServer>(
          options, registry);
      status_server->SetDelayProbe([sni, censorship_strategy](
                                       const ServerInfo& server,
                                       int timeout_ms) -> std::uint32_t {
        const int timeout_sec = std::max(1, timeout_ms / 1000);
        const auto ms = fptn::utils::speed_estimator::GetLatencyMs(server,
            sni, timeout_sec, server.md5_fingerprint, censorship_strategy);
        return ms == UINT64_MAX ? 0 : static_cast<std::uint32_t>(ms);
      });
      if (!status_server->Start()) {
        SPDLOG_ERROR("Failed to start the status API");
        return EXIT_FAILURE;
      }
    }

    try {
      const auto servers = ExcludeServers(
          CollectServers(access_tokens, sni, censorship_strategy),
          exclude_servers);
      if (servers.empty()) {
        SPDLOG_ERROR("No servers left after --exclude-servers");
        return EXIT_FAILURE;
      }
      registry->Reset(servers);
      SPDLOG_INFO("Tokens: {}, servers: {}", access_tokens.size(),
          servers.size());

      bool use_login_race = preferred_server.empty();
      if (!preferred_server.empty()) {
        auto server_opt = FindPreferredServer(servers, preferred_server);
        if (server_opt.has_value()) {
          selected_server = std::move(*server_opt);
          server_pinned = true;
        } else {
          SPDLOG_WARN("Server '{}' does not exist! Check your token!",
              preferred_server);
          use_login_race = true;
        }
      }
      if (use_login_race) {
        // The whole pool being unreachable is usually a moment, not a state:
        // the uplink is still coming up, or the DNS has not settled. Leaving
        // here means the process is gone, and a supervising daemon does not
        // start it again - the router then sits without a proxy until someone
        // restarts it by hand. So the pool is retried a few times first.
        std::optional<fptn::utils::speed_estimator::LoginResult> login_result;
        for (int attempt = 1; attempt <= kStartupLoginAttempts; ++attempt) {
          login_result =
              SelectServer(servers, sni, censorship_strategy, max_ping,
                  registry);
          if (login_result) {
            break;
          }
          if (attempt < kStartupLoginAttempts) {
            SPDLOG_WARN("No server answered (attempt {}/{}), retrying in {}s",
                attempt, kStartupLoginAttempts, kStartupRetryDelay.count());
            std::this_thread::sleep_for(kStartupRetryDelay);
          }
        }
        if (!login_result) {
          SPDLOG_ERROR("All servers unavailable!");
          return EXIT_FAILURE;
        }
        selected_server = login_result->server;
        pre_obtained_token = std::move(login_result->access_token);
      }
      registry->SetActive(selected_server);
    } catch (const std::runtime_error& err) {
      SPDLOG_ERROR("Config error: {}", err.what());
      return EXIT_FAILURE;
    }
    // The route manager needs the chosen server address as well: it excludes
    // it from the tunnel, or the tunnel would run inside itself.
    const auto server_ip = fptn::routing::ResolveDomain(selected_server.host);
    if (server_ip.IsEmpty()) {
      SPDLOG_ERROR("DNS resolve error: {}", selected_server.host);
      return EXIT_FAILURE;
    }

    // Build a connection to a particular server. Factored out because the
    // same thing is needed when switching servers at runtime.
    using fptn::vpn::http::ClientPtr;
    auto make_client = [&](const ServerInfo& server, const std::string& token,
                           int login_timeout_sec = 10) -> ClientPtr {
      const auto ip = fptn::routing::ResolveDomain(server.host);
      if (ip.IsEmpty()) {
        SPDLOG_ERROR("DNS resolve error: {}", server.host);
        return nullptr;
      }
      auto client = std::make_unique<fptn::vpn::http::Client>(
          fptn::protocol::https::ConnectionConfig{
              .common ={
                      .server_ip = ip,
                      .server_port = static_cast<std::uint16_t>(server.port),
                      .sni = sni,
                      .md5_fingerprint = server.md5_fingerprint,
                      .client_version = FPTN_VERSION,
                      .censorship_strategy = censorship_strategy,
                      .tun_interface_address_ipv4 = tun_interface_address_ipv4,
                      .tun_interface_address_ipv6 = tun_interface_address_ipv6,
                  }},
          connection_strategy);
      if (!token.empty()) {
        client->SetAccessToken(token);
      }
      if (!client->Login(
              server.username, server.password, login_timeout_sec)) {
        SPDLOG_ERROR("Login to {} failed (code {}): {}",
            fptn::client::status::ServerRegistry::DisplayName(server),
            client->LatestErrorCode(), client->LatestError());
        return nullptr;
      }
      return client;
    };

    SPDLOG_INFO(
        "\n--- Starting client ---\n"
        "VERSION:            {}\n"
        "SELECTED SERVER:    {}\n"
        "SNI:                {}\n"
        "VPN SERVER NAME:    {}\n"
        "VPN SERVER IP:      {}\n"
        "VPN SERVER PORT:    {}\n"
        "BYPASS-METHOD:      {}\n"
        "GATEWAY IP:         {}\n"
        "NETWORK INTERFACE:  {}\n"
        "EXCLUDE NETWORKS:   {}\n"
        "INCLUDE NETWORKS:   {}\n"
        "SPLIT TUNNEL:       {}\n"
        "TUNNEL MODE:        {}\n"
        "TUNNEL DOMAINS:     {}\n"
        "BLACKLIST DOMAINS:  {}\n",
        // version
        FPTN_VERSION,
        // server
        DescribeServer(selected_server), sni, selected_server.name,
        selected_server.host,
        selected_server.port, bypass_method,
        // network
        using_gateway_ip.ToString(), out_network_interface_name,
        // additional settings
        exclude_networks_str, include_networks_str,
        enable_split_tunnel ? "enabled" : "disabled", tunnel_mode,
        split_domains_str, blacklist_domains_str);

    /* auth & dns */
    auto http_client = make_client(selected_server, pre_obtained_token);
    if (!http_client) {
      return EXIT_FAILURE;
    }
    const auto [dns_server_ipv4, dns_server_ipv6] = http_client->GetDns();
    if (dns_server_ipv4.IsEmpty() || dns_server_ipv6.IsEmpty()) {
      SPDLOG_ERROR("DNS server error! Check your connection!");
      return EXIT_FAILURE;
    }

    /* tun interface */
    auto virtual_network_interface =
        std::make_shared<fptn::common::network::TunInterface>(
            fptn::common::network::TunInterface::Config{
                .name = tun_interface_name,
                .mtu_size = mtu_size,
                .using_rate_calculator = true,
                .ipv4_addr = tun_interface_address_ipv4,
                .ipv4_netmask = 32,
                .ipv6_addr = tun_interface_address_ipv6,
                .ipv6_netmask = 126});

    // route manager
    // In --disable-routing mode another daemon owns the routes
    // (ZeroBlock, mwan3, ...). VpnManager honours that: with an empty
    // route_manager it brings the TUN up but never touches routing tables.
    fptn::routing::RouteManagerSPtr route_manager;
    if (!disable_routing) {
      route_manager = std::make_shared<fptn::routing::RouteManager>(
        fptn::routing::RouteManager::Config{
            .out_interface_name = out_network_interface_name,
            .tun_interface_address_ipv4 = tun_interface_address_ipv4,
            .tun_interface_address_ipv6 = tun_interface_address_ipv6,
            .vpn_server_ip = server_ip,
            .dns_server_ipv4 = dns_server_ipv4,
            .dns_server_ipv6 = dns_server_ipv6,
            .gateway_ipv4 = gateway_ip,
            .gateway_ipv6 = gateway_ipv6,
            .exclude_networks = exclude_networks,
            .include_networks = include_networks
#if _WIN32
            ,
            .enable_advanced_dns_management = false
#endif
          });
    }

    /* plugins */
    std::vector<fptn::plugin::BasePluginPtr> client_plugins;
#ifndef FPTN_OPENWRT
    if (enable_ad_block) {
      client_plugins.push_back(std::make_unique<fptn::plugin::AdBlock>());
    }
#endif
    // Plugins drive routes via route_manager - useless without it.
    if (route_manager && !blacklist_domains.empty()) {
      auto blacklist_plugin = std::make_unique<fptn::plugin::DomainBlacklist>(
          blacklist_domains, route_manager);
      client_plugins.push_back(std::move(blacklist_plugin));
    }

    if (route_manager && enable_split_tunnel) {
      const auto policy = tunnel_mode == "exclude"
                              ? fptn::routing::RoutingPolicy::kExcludeFromVpn
                              : fptn::routing::RoutingPolicy::kIncludeInVpn;
      auto split_tunnel_plugin = std::make_unique<fptn::plugin::Tunneling>(
          split_domains, route_manager, policy);
      client_plugins.push_back(std::move(split_tunnel_plugin));
    }

    /* vpn client */
    fptn::vpn::VpnManager vpn_client(
        fptn::vpn::VpnManager::Config{.http_client = std::move(http_client),
            .route_manager = route_manager,
            .virtual_net_interface = virtual_network_interface,
            .plugins = std::move(client_plugins)});

    vpn_client.Start();

    /* SOCKS5 entry point for transparent proxies */
    std::unique_ptr<fptn::socks::PolicyRoute> policy_route;
    if (socks_enabled) {
      // Dedicated routing table: the main one is left alone, the rule only
      // matches sockets bound to the tunnel address.
      policy_route = std::make_unique<fptn::socks::PolicyRoute>(
          fptn::socks::PolicyRoute::Config{
              .tun_interface_name = tun_interface_name,
              .tun_address_ipv4 = tun_interface_address_ipv4.ToString(),
              .tun_address_ipv6 = tun_interface_address_ipv6.ToString(),
              .table_id = static_cast<std::uint32_t>(socks_route_table)});
      if (!policy_route->Apply()) {
        SPDLOG_ERROR("Failed to set up policy routing for SOCKS5");
        vpn_client.Stop();
        return EXIT_FAILURE;
      }
      socks_server->SetTunnel(tun_interface_address_ipv4.ToString(),
          tun_interface_address_ipv6.ToString(), dns_server_ipv4.ToString());
      if (!socks_server->Serve()) {
        SPDLOG_ERROR("Failed to start SOCKS5 server");
        policy_route->Clean();
        vpn_client.Stop();
        return EXIT_FAILURE;
      }
    }

    // Declared before the status API: switching servers recreates the
    // watchdog, and it has to measure the new node.
    std::unique_ptr<LatencyWatchdog> watchdog;
    std::mutex switch_mutex;

    // Set the moment the user picks a server themselves. Their choice
    // outranks a measurement: undoing it on the next sweep would read as the
    // client fighting the dashboard.
    std::atomic<bool> manually_pinned{false};
    // Both written under switch_mutex.
    auto last_switch = std::chrono::steady_clock::now();

    // One implementation of "move the tunnel", used by the status API and by
    // the sweep alike. Returns false and leaves the tunnel where it was if
    // the new server does not answer or the login fails.
    const auto switch_to = [&](const ServerInfo& server) -> bool {
      const std::scoped_lock<std::mutex> lock(switch_mutex);

      // The route manager excludes the address of the server it was
      // started with, and that exclusion cannot be rewritten in place.
      // Where another daemon owns the routes there is nothing to exclude.
      if (route_manager) {
        SPDLOG_WARN(
            "Server switching needs --disable-routing: the route manager "
            "pins the current server address");
        return false;
      }

      if (fptn::client::status::ServerRegistry::KeyOf(server) ==
          fptn::client::status::ServerRegistry::KeyOf(selected_server)) {
        return true;  // already there
      }

      // A switch drops the current session before a new one exists: the
      // server counts sessions per user and would refuse a second login.
      // So make sure the new node answers at all first - otherwise a
      // working tunnel would stall for the whole run of failed attempts.
      const auto probe = fptn::utils::speed_estimator::GetLatencyMs(server,
          sni, kProbeTimeoutSec, server.md5_fingerprint, censorship_strategy);
      const std::uint32_t probe_ms =
          probe == UINT64_MAX ? 0 : static_cast<std::uint32_t>(probe);
      registry->RecordProbe(
          server, probe_ms, probe_ms == 0 ? "unreachable" : "");
      if (probe_ms == 0) {
        SPDLOG_WARN("{} did not answer, staying on the current server",
            fptn::client::status::ServerRegistry::DisplayName(server));
        return false;
      }

      if (!vpn_client.SwitchClient(
              [&]() { return make_client(server, "", 5); })) {
        SPDLOG_ERROR("Could not switch the tunnel to {}",
            fptn::client::status::ServerRegistry::DisplayName(server));
        return false;
      }

      selected_server = server;
      last_switch = std::chrono::steady_clock::now();
      registry->SetActive(server);
      SPDLOG_INFO("Switched to {}",
          fptn::client::status::ServerRegistry::DisplayName(server));

      // The watchdog watched the previous node - rebuild it for the new one.
      // Safe from the sweep thread and from the API thread; the watchdog runs
      // on its own, so joining it here is not joining ourselves.
      if (watchdog) {
        watchdog.reset();
        watchdog = std::make_unique<LatencyWatchdog>(server, sni,
            censorship_strategy, max_ping,
            [&vpn_client]() { vpn_client.Stop(); }, registry);
      }
      return true;
    };

    /* tunnel-facing callbacks: only now is there a tunnel to report on */
    if (status_server) {
      status_server->SetStatusProvider(
          [&vpn_client, &socks_server, registry, &sni, bypass_method]() {
        nlohmann::json socks = nlohmann::json{{"enabled", false}};
        if (socks_server) {
          socks = nlohmann::json{{"enabled", true},
              {"running", socks_server->IsRunning()},
              {"active_sessions", socks_server->ActiveSessions()},
              {"total_sessions", socks_server->TotalSessions()},
              {"max_sessions", socks_server->MaxSessions()}};
        }
        return nlohmann::json{{"version", FPTN_VERSION},
            {"tunnel",
                nlohmann::json{{"connected", vpn_client.IsStarted()},
                    {"reconnecting", vpn_client.IsReconnecting()},
                    {"reconnect_attempt", vpn_client.ReconnectAttempt()},
                    {"interface", vpn_client.GetInterfaceName()},
                    {"send_rate", vpn_client.GetSendRate()},
                    {"receive_rate", vpn_client.GetReceiveRate()},
                    {"to_server_sent", vpn_client.ToServerSent()},
                    {"to_server_dropped", vpn_client.ToServerDropped()},
                    {"to_tun_sent", vpn_client.ToTunSent()},
                    {"to_tun_dropped", vpn_client.ToTunDropped()},
                    {"server", registry->ToJson().value("current", "")},
                    {"sni", sni}, {"bypass_method", bypass_method}}},
            {"socks", std::move(socks)}};
      });
      status_server->SetSwitchServer([&](const ServerInfo& server) -> bool {
        // An explicit request pins the server: from here on the sweep only
        // measures, it no longer moves the tunnel.
        if (!switch_to(server)) {
          return false;
        }
        manually_pinned = true;
        return true;
      });
    }

    /* start event loop */
    // Nothing below moves the tunnel on its own in three cases: the server is
    // pinned by name (asking for one is the user's decision, and a
    // measurement does not outrank it), the route manager owns the routes so
    // an in-place switch is impossible, or the pool holds a single server and
    // there is nowhere to move.
    const bool may_auto_switch =
        !server_pinned && !route_manager && registry->Servers().size() > 1;

    std::unique_ptr<PoolMonitor> pool_monitor;
    if (probe_interval > 0) {
      pool_monitor = std::make_unique<PoolMonitor>(registry, sni,
          censorship_strategy, std::chrono::seconds(probe_interval), [&] {
            if (!may_auto_switch || manually_pinned) {
              return;
            }
            const auto best = BestServer(*registry);
            if (!best) {
              return;  // nothing answered - the current server is all there is
            }
            ServerInfo current;
            {
              const std::scoped_lock<std::mutex> lock(switch_mutex);
              current = selected_server;
            }
            using Registry = fptn::client::status::ServerRegistry;
            if (Registry::KeyOf(best->first) == Registry::KeyOf(current)) {
              return;  // already on the fastest one
            }
            const auto stats = registry->Stats(current);
            // Stopped answering, or answers past the limit: leave now,
            // without waiting out the tolerance or the gap between switches.
            const bool current_broken =
                !stats.alive ||
                (max_ping > 0 &&
                    stats.average_ms > static_cast<std::uint32_t>(max_ping));
            if (!current_broken) {
              if (switch_tolerance <= 0) {
                return;  // moving on latency alone is switched off
              }
              if (best->second + static_cast<std::uint32_t>(switch_tolerance) >=
                  stats.average_ms) {
                return;  // not enough of a gain to pay a second of silence
              }
              const std::scoped_lock<std::mutex> lock(switch_mutex);
              if (std::chrono::steady_clock::now() - last_switch <
                  kMinAutoSwitchGap) {
                return;
              }
            }
            SPDLOG_INFO("{} answers in {} ms against {} ms on {}{} - moving",
                Registry::DisplayName(best->first), best->second,
                stats.average_ms, Registry::DisplayName(current),
                current_broken ? " (over the limit or dead)" : "");
            switch_to(best->first);
          });
    }

    // The watchdog is the fallback for a pool nobody sweeps: it reacts in
    // three minutes, but all it can do is stop the tunnel and have the
    // service start the process again somewhere else. Where a sweep runs the
    // switch happens in place instead, and a second opinion on the same
    // question would only get in the way.
    if (max_ping > 0 && may_auto_switch && !pool_monitor) {
      // Same lock as the switch handler: both write this pointer, and the
      // handler runs on the status API thread.
      const std::scoped_lock<std::mutex> lock(switch_mutex);
      // selected_server is written by the switch handler under this lock too.
      watchdog = std::make_unique<LatencyWatchdog>(selected_server, sni,
          censorship_strategy, max_ping,
          [&vpn_client]() { vpn_client.Stop(); }, registry);
    }
    fptn::utils::WaitForSignal(vpn_client);
    {
      const std::scoped_lock<std::mutex> lock(switch_mutex);
      watchdog.reset();
    }
    pool_monitor.reset();


    /* clean */
    if (socks_server) {
      socks_server->Stop();
    }
    if (policy_route) {
      policy_route->Clean();
    }
    if (route_manager) {
      route_manager->Clean();
    }
    vpn_client.Stop();
    // Stopped after the route cleanup, but before the logger goes away: its
    // threads still log while they wind down.
    if (status_server) {
      status_server->Stop();
    }
    spdlog::shutdown();

    return EXIT_SUCCESS;
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("An error occurred: {}. Exiting...", ex.what());
  } catch (...) {
    SPDLOG_ERROR("An unknown error occurred. Exiting...");
  }
  return EXIT_FAILURE;
}
