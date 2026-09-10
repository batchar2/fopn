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
#include "adblock/adblock.h"
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
// Каждая проксируемая сессия держит два дескриптора, и мягкий лимит в 1024,
// с которым запускают демоны на роутере, кончается за пару часов офисной
// нагрузки: accept начинает возвращать EMFILE, и прокси перестаёт принимать
// соединения, оставаясь при этом живым процессом.
// Возвращает лимит, с которым процесс в итоге остался: от него считается
// потолок сессий SOCKS.
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

// Сессия занимает два дескриптора, плюс запас на туннель, логи и служебные
// сокеты. Фиксированное число тут врёт: на роутере лимит бывает и 1024, и
// 4096, и потолок должен считаться от него, а не стоять константой.
std::size_t DefaultMaxSocksSessions(std::size_t fd_limit) {
  constexpr std::size_t kReserved = 256;
  constexpr std::size_t kFallback = 512;
  constexpr std::size_t kMinimum = 64;
  if (fd_limit <= kReserved) {
    return kFallback;
  }
  return std::max(kMinimum, (fd_limit - kReserved) / 2);
}

// Servers of every token in one pool, each carrying the credentials of the
// token it came from.
// Конфиг-файлом кормят то, что не влезает в командную строку: длинные ключи и
// их массивы. Значения разворачиваются в те же флаги, что и раньше, поэтому
// разбор, типы и умолчания остаются общими. Флаги, заданные в командной
// строке, идут после и перекрывают файл.
std::vector<std::string> ExpandConfigFile(int argc, char* argv[]) {
  // Имена ключей пишут и через дефис, и через подчёркивание; для разбора это
  // один и тот же флаг.
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
    if (arg.starts_with("--")) {
      from_command_line.insert(arg);
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

  // Аргументы-переключатели значения не принимают: в JSON они булевы, но в
  // командной строке разворачиваются в голый флаг, иначе значение улетает в
  // позиционные и разбор падает.
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
    // Тот же флаг в командной строке главнее файла. Пропускаем его здесь, а не
    // полагаемся на порядок: повтор одного аргумента разбор не переживает.
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
      // Массив - это повторяющийся флаг: так задаются несколько токенов.
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

    const auto ms = fptn::utils::speed_estimator::GetDownloadTimeMs(
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

// Три замера подряд за пределом - и сторож просит завершиться. Раньше он слал
// процессу SIGTERM: в многопоточной программе это грубо, очистка пропускалась,
// а под ZeroBlock, который запускает помощника сам, уход PID вообще теряет его
// насовсем. Теперь сторож просто останавливает туннель - главный цикл выходит
// сам, SOCKS и маршруты убираются штатно, procd поднимает процесс заново.
// (ZeroBlock --max-ping не передаёт, поэтому там сторож не создаётся вовсе.)
// Плановый обход всего пула. Без него в реестре живёт только один замер -
// тот, что случился при выборе сервера на старте, - и список серверов
// показывает давно протухшие числа. Сервер, который лежал при запуске и с тех
// пор поднялся, иначе никогда не станет снова кандидатом.
class PoolMonitor final {
 public:
  PoolMonitor(std::shared_ptr<fptn::client::status::ServerRegistry> registry,
      std::string sni,
      fptn::protocol::https::CensorshipStrategy censorship_strategy,
      std::chrono::seconds interval)
      : registry_(std::move(registry)),
        sni_(std::move(sni)),
        censorship_strategy_(censorship_strategy),
        interval_(interval) {
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
      const auto servers = registry_->Servers();
      for (const auto& server : servers) {
        if (!Running()) {
          return;
        }
        const auto ms = fptn::utils::speed_estimator::GetDownloadTimeMs(
            server, sni_, 5, server.md5_fingerprint, censorship_strategy_);
        const std::uint32_t delay =
            ms == UINT64_MAX ? 0 : static_cast<std::uint32_t>(ms);
        registry_->RecordProbe(
            server, delay, delay == 0 ? "probe failed" : "");
      }
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

  std::mutex mutex_;
  std::condition_variable cv_;
  bool running_ = true;
  std::thread thread_;
};

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
      const auto ms = fptn::utils::speed_estimator::GetDownloadTimeMs(
          server_, sni_, 5, server_.md5_fingerprint, censorship_strategy_);
      if (registry_) {
        // UINT64_MAX означает, что сервер не ответил; в реестре неудача
        // записывается нулём, как это принято в Clash API.
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

// Имена sni-spoofing-* остались от прежних версий: на деле они всегда включали
// Reality-режим. Держим их псевдонимами канонических reality-*, чтобы не ломать
// чужие конфиги.
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

// Всё, что принимает --bypass-method: канонические имена плюс псевдонимы.
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
        .default_value(0)
        .help(
            "Latency limit in milliseconds. A server over it is not picked, "
            "and the one in use is replaced once it stays over the limit")
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
        .default_value(0)
        .scan<'i', int>()
        .help(
            "Re-measure every server in the pool every N seconds, so the "
            "status API shows fresh latency instead of one reading taken at "
            "startup. 0 (default) disables it");

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
    // Порт SOCKS открываем до выбора сервера: ZeroBlock ждёт готовности
    // помощника считаные секунды, а логин-гонка идёт до минуты. Соединения
    // полежат в backlog ядра, пока не поднимется туннель.
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
    // Реестр переживает выбор сервера: пул и замеры нужны всё время работы,
    // а не только на старте.
    auto registry = std::make_shared<fptn::client::status::ServerRegistry>();
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
        auto login_result = SelectServer(
            servers, sni, censorship_strategy, max_ping, registry);
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
    // Адрес выбранного сервера нужен ещё и менеджеру маршрутов: он исключает
    // его из туннеля, иначе получился бы туннель в туннеле.
    const auto server_ip = fptn::routing::ResolveDomain(selected_server.host);
    if (server_ip.IsEmpty()) {
      SPDLOG_ERROR("DNS resolve error: {}", selected_server.host);
      return EXIT_FAILURE;
    }

    // Собрать подключение к конкретному серверу. Вынесено отдельно, потому
    // что то же самое нужно при смене сервера на лету.
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

#ifndef FPTN_OPENWRT
    fptn::adblock::AdBlockerPtr ad_blocker;
    if (enable_ad_block) {
      ad_blocker = std::make_shared<fptn::adblock::AdBlocker>();
    }
#endif

    /* vpn client */
    fptn::vpn::VpnManager vpn_client(
        fptn::vpn::VpnManager::Config{.http_client = std::move(http_client),
            .route_manager = route_manager,
            .virtual_net_interface = virtual_network_interface,
            .plugins = std::move(client_plugins),
#ifndef FPTN_OPENWRT
            .ad_blocker = std::move(ad_blocker)
#endif
        });

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

    // Объявлен до статус-API: смена сервера пересоздаёт сторожа, а он должен
    // мерить уже новый узел.
    std::unique_ptr<LatencyWatchdog> watchdog;
    std::mutex switch_mutex;

    /* local status API */
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
      status_server->SetDelayProbe(
          [sni, censorship_strategy](const ServerInfo& server,
              int timeout_ms) -> std::uint32_t {
            const int timeout_sec = std::max(1, timeout_ms / 1000);
            const auto ms = fptn::utils::speed_estimator::GetDownloadTimeMs(
                server, sni, timeout_sec, server.md5_fingerprint,
                censorship_strategy);
            return ms == UINT64_MAX ? 0 : static_cast<std::uint32_t>(ms);
          });
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
        const std::scoped_lock<std::mutex> lock(switch_mutex);

        // Менеджер маршрутов исключает из туннеля адрес того сервера, с
        // которым его подняли, и переписать это исключение на лету нельзя.
        // Там, где маршрутами владеет другой демон, исключать нечего.
        if (route_manager) {
          SPDLOG_WARN(
              "Server switching needs --disable-routing: the route manager "
              "pins the current server address");
          return false;
        }

        if (fptn::client::status::ServerRegistry::KeyOf(server) ==
            fptn::client::status::ServerRegistry::KeyOf(selected_server)) {
          return true;  // уже на нём
        }

        // Смена гасит текущую сессию до того, как получится новая: сервер
        // считает сессии на пользователя и второй вход бы отклонил. Значит
        // сначала убеждаемся, что новый узел вообще отвечает - иначе
        // рабочий туннель встал бы на всё время неудачных попыток входа.
        const auto probe = fptn::utils::speed_estimator::GetDownloadTimeMs(
            server, sni, 5, server.md5_fingerprint, censorship_strategy);
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
        registry->SetActive(server);
        SPDLOG_INFO("Switched to {}",
            fptn::client::status::ServerRegistry::DisplayName(server));

        // Сторож следил за прежним узлом - пересобираем его под новый.
        if (max_ping > 0) {
          watchdog.reset();
          watchdog = std::make_unique<LatencyWatchdog>(server, sni,
              censorship_strategy, max_ping,
              [&vpn_client]() { vpn_client.Stop(); }, registry);
        }
        return true;
      });

      if (!status_server->Start()) {
        SPDLOG_ERROR("Failed to start the status API");
        return EXIT_FAILURE;
      }
    }

    /* start event loop */
    // Not while a server is pinned by name: a restart would pin the same one
    // again, and asking for it is the user's decision.
    std::unique_ptr<PoolMonitor> pool_monitor;
    if (probe_interval > 0) {
      pool_monitor = std::make_unique<PoolMonitor>(registry, sni,
          censorship_strategy, std::chrono::seconds(probe_interval));
    }

    if (max_ping > 0 && !server_pinned) {
      watchdog = std::make_unique<LatencyWatchdog>(selected_server, sni,
          censorship_strategy, max_ping,
          [&vpn_client]() { vpn_client.Stop(); }, registry);
    }
    fptn::utils::WaitForSignal(vpn_client);
    watchdog.reset();
    pool_monitor.reset();
    if (status_server) {
      status_server->Stop();
    }

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
    spdlog::shutdown();
    return EXIT_SUCCESS;
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("An error occurred: {}. Exiting...", ex.what());
  } catch (...) {
    SPDLOG_ERROR("An unknown error occurred. Exiting...");
  }
  return EXIT_FAILURE;
}
