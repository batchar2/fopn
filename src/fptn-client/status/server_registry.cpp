/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-client/status/server_registry.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <fmt/format.h>  // NOLINT(build/include_order)

namespace fptn::client::status {

namespace {

std::uint64_t NowMs() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

// Clash отдаёт время замера в RFC3339. Панели разбирают именно его, поэтому
// формат держим таким же, а не unix-временем.
std::string ToRfc3339(std::uint64_t ms) {
  if (ms == 0) {
    return {};
  }
  const auto seconds = static_cast<std::time_t>(ms / 1000);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &seconds);
#else
  gmtime_r(&seconds, &tm);
#endif
  std::ostringstream out;
  out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
  out << fmt::format(".{:03}Z", ms % 1000);
  return out.str();
}

std::string Trim(const std::string& value) {
  const auto begin = value.find_first_not_of(" \t\r\n");
  if (begin == std::string::npos) {
    return {};
  }
  const auto end = value.find_last_not_of(" \t\r\n");
  return value.substr(begin, end - begin + 1);
}

std::string ToLower(std::string value) {
  std::ranges::transform(value, value.begin(),
      [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

}  // namespace

std::string ServerRegistry::KeyOf(const ServerInfo& server) {
  return fmt::format("{}:{}", server.host, server.port);
}

std::string ServerRegistry::DisplayName(const ServerInfo& server) {
  if (!server.service_name.empty()) {
    return fmt::format("{}/{}", server.service_name, server.name);
  }
  return server.name;
}

void ServerRegistry::Reset(const std::vector<ServerInfo>& servers) {
  const std::scoped_lock<std::mutex> lock(mutex_);

  std::unordered_map<std::string, Entry> next;
  std::vector<std::string> next_order;
  next.reserve(servers.size());
  next_order.reserve(servers.size());

  for (const auto& server : servers) {
    auto key = KeyOf(server);
    if (next.contains(key)) {
      continue;  // один и тот же узел пришёл из двух токенов
    }
    Entry entry;
    // Замеры переживают пересборку пула: сервер тот же, мерить заново незачем.
    if (const auto old = entries_.find(key); old != entries_.end()) {
      entry = old->second;
    }
    entry.info = server;
    next_order.push_back(key);
    next.emplace(std::move(key), std::move(entry));
  }

  entries_ = std::move(next);
  order_ = std::move(next_order);
  if (!entries_.contains(active_key_)) {
    active_key_.clear();
  }
}

void ServerRegistry::RecordProbe(const ServerInfo& server,
    std::uint32_t delay_ms,
    const std::string& error) {
  const std::scoped_lock<std::mutex> lock(mutex_);

  const auto key = KeyOf(server);
  auto it = entries_.find(key);
  if (it == entries_.end()) {
    // Сервер могли исключить из пула, пока проба была в полёте.
    return;
  }

  const auto now = NowMs();
  auto& entry = it->second;
  entry.last_try_ms = now;
  if (delay_ms != 0) {
    entry.last_ok_ms = now;
    entry.last_error.clear();
  } else {
    entry.last_error = error;
  }

  entry.window.push_back(
      Measurement{.at_ms = now, .delay_ms = delay_ms, .error = error});
  while (entry.window.size() > kMeasurementWindow) {
    entry.window.pop_front();
  }
}

void ServerRegistry::SetActive(const ServerInfo& server) {
  const std::scoped_lock<std::mutex> lock(mutex_);
  active_key_ = KeyOf(server);
}

void ServerRegistry::ClearActive() {
  const std::scoped_lock<std::mutex> lock(mutex_);
  active_key_.clear();
}

std::vector<ServerInfo> ServerRegistry::Servers() const {
  const std::scoped_lock<std::mutex> lock(mutex_);
  std::vector<ServerInfo> result;
  result.reserve(order_.size());
  for (const auto& key : order_) {
    if (const auto it = entries_.find(key); it != entries_.end()) {
      result.push_back(it->second.info);
    }
  }
  return result;
}

std::optional<ServerInfo> ServerRegistry::FindByKey(
    const std::string& key) const {
  const std::scoped_lock<std::mutex> lock(mutex_);
  if (const auto it = entries_.find(key); it != entries_.end()) {
    return it->second.info;
  }
  return std::nullopt;
}

std::optional<ServerInfo> ServerRegistry::FindByName(
    const std::string& name) const {
  const std::scoped_lock<std::mutex> lock(mutex_);
  const auto wanted = ToLower(Trim(name));
  if (wanted.empty()) {
    return std::nullopt;
  }
  for (const auto& key : order_) {
    const auto it = entries_.find(key);
    if (it == entries_.end()) {
      continue;
    }
    const auto& info = it->second.info;
    if (ToLower(info.name) == wanted || ToLower(DisplayName(info)) == wanted ||
        ToLower(key) == wanted) {
      return info;
    }
  }
  return std::nullopt;
}

ServerStats ServerRegistry::Summarize(const Entry& entry) {
  ServerStats stats;
  stats.total = entry.window.size();

  std::uint64_t sum = 0;
  std::size_t counted = 0;
  for (const auto& measurement : entry.window) {
    if (measurement.delay_ms == 0) {
      ++stats.failed;
      continue;
    }
    sum += measurement.delay_ms;
    ++counted;
    if (stats.min_ms == 0 || measurement.delay_ms < stats.min_ms) {
      stats.min_ms = measurement.delay_ms;
    }
    stats.max_ms = std::max(stats.max_ms, measurement.delay_ms);
  }

  if (counted != 0) {
    stats.average_ms = static_cast<std::uint32_t>(sum / counted);
  }
  // Живым считаем сервер, у которого последняя проба удалась: одна
  // неудача в середине окна ещё не повод вычёркивать узел.
  stats.alive = !entry.window.empty() && entry.window.back().delay_ms != 0;
  return stats;
}

ServerStats ServerRegistry::Stats(const ServerInfo& server) const {
  const std::scoped_lock<std::mutex> lock(mutex_);
  if (const auto it = entries_.find(KeyOf(server)); it != entries_.end()) {
    return Summarize(it->second);
  }
  return {};
}

nlohmann::json ServerRegistry::EntryToJson(const Entry& entry) const {
  const auto stats = Summarize(entry);

  nlohmann::json history = nlohmann::json::array();
  for (const auto& measurement : entry.window) {
    nlohmann::json item{{"time", ToRfc3339(measurement.at_ms)},
        {"delay", measurement.delay_ms}};
    if (!measurement.error.empty()) {
      item["error"] = measurement.error;
    }
    history.push_back(std::move(item));
  }

  return nlohmann::json{{"name", DisplayName(entry.info)},
      {"host", entry.info.host}, {"port", entry.info.port},
      {"service", entry.info.service_name}, {"key", KeyOf(entry.info)},
      {"alive", stats.alive}, {"delay", stats.average_ms},
      {"delay_min", stats.min_ms}, {"delay_max", stats.max_ms},
      {"probes", stats.total}, {"failed", stats.failed},
      {"last_try", ToRfc3339(entry.last_try_ms)},
      {"last_seen", ToRfc3339(entry.last_ok_ms)},
      {"last_error", entry.last_error}, {"history", std::move(history)}};
}

nlohmann::json ServerRegistry::ToJson() const {
  const std::scoped_lock<std::mutex> lock(mutex_);

  nlohmann::json servers = nlohmann::json::array();
  for (const auto& key : order_) {
    const auto it = entries_.find(key);
    if (it == entries_.end()) {
      continue;
    }
    auto item = EntryToJson(it->second);
    item["in_use"] = (key == active_key_);
    servers.push_back(std::move(item));
  }

  return nlohmann::json{{"servers", std::move(servers)},
      {"current", active_key_}, {"window", kMeasurementWindow}};
}

nlohmann::json ServerRegistry::ToClashProxies() const {
  const std::scoped_lock<std::mutex> lock(mutex_);

  nlohmann::json proxies = nlohmann::json::object();
  nlohmann::json all = nlohmann::json::array();
  std::string current_name;

  for (const auto& key : order_) {
    const auto it = entries_.find(key);
    if (it == entries_.end()) {
      continue;
    }
    const auto& entry = it->second;
    const auto name = DisplayName(entry.info);
    const auto stats = Summarize(entry);

    // Clash кладёт в history не всё окно, а последний замер: панели
    // читают history[0] и ждут там свежее значение.
    nlohmann::json history = nlohmann::json::array();
    if (!entry.window.empty()) {
      const auto& last = entry.window.back();
      history.push_back(
          {{"time", ToRfc3339(last.at_ms)}, {"delay", last.delay_ms}});
    }

    proxies[name] = nlohmann::json{{"type", "FPTN"}, {"name", name},
        {"udp", true}, {"history", std::move(history)},
        {"alive", stats.alive}};
    all.push_back(name);
    if (key == active_key_) {
      current_name = name;
    }
  }

  if (current_name.empty() && !all.empty()) {
    current_name = all.front().get<std::string>();
  }

  // Группа-селектор: через неё прозрачный прокси видит текущий выбор и
  // может переключить сервер тем же PUT, что и у sing-box.
  proxies["FPTN"] = nlohmann::json{{"type", "Selector"}, {"name", "FPTN"},
      {"udp", true}, {"history", nlohmann::json::array()},
      {"now", current_name}, {"all", all}};

  return nlohmann::json{{"proxies", std::move(proxies)}};
}

}  // namespace fptn::client::status
