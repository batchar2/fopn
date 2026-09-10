/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

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

// Сколько последних замеров держим на сервер. Одного числа мало: проба
// периодически врёт (сеть моргнула, узел занят), и решение по одному
// измерению уводит пул с живого сервера. Окно позволяет отдавать среднее
// и число неудач вместо мгновенного значения.
constexpr std::size_t kMeasurementWindow = 10;

struct Measurement {
  std::uint64_t at_ms = 0;      // время замера, unix ms
  std::uint32_t delay_ms = 0;   // 0 означает неудачу - как в Clash API
  std::string error;            // причина, если delay_ms == 0
};

struct ServerStats {
  std::uint32_t average_ms = 0;
  std::uint32_t min_ms = 0;
  std::uint32_t max_ms = 0;
  std::size_t total = 0;
  std::size_t failed = 0;
  bool alive = false;
};

// Пул серверов вместе с результатами замеров. До этого пул жил локальной
// переменной в main() и умирал сразу после выбора сервера, а измеренные
// задержки выбрасывались - наружу не выходило ни одного числа.
class ServerRegistry final {
 public:
  ServerRegistry() = default;
  ServerRegistry(const ServerRegistry&) = delete;
  ServerRegistry& operator=(const ServerRegistry&) = delete;

  // Задаёт состав пула. Замеры по серверам, которые остались в списке,
  // сохраняются - пересборка пула не должна стирать историю.
  void Reset(const std::vector<ServerInfo>& servers);

  // Результат одной пробы. delay_ms == 0 считается неудачей.
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

  // Совместимый с Clash API вид: его уже умеют читать и панели (yacd,
  // metacubexd), и прозрачные прокси, которые ходят к sing-box.
  [[nodiscard]] nlohmann::json ToClashProxies() const;

  // Свой, подробный вид: окно замеров, ошибки, состав пула.
  [[nodiscard]] nlohmann::json ToJson() const;

  // Ключ сервера в API - host:port, он уникален в пуле. Имя сервера
  // уникальным не обязано быть: разные токены приносят одинаковые имена.
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
  // порядок из токенов, чтобы вывод был стабильным между запросами
  std::vector<std::string> order_;
  std::string active_key_;
};

}  // namespace fptn::client::status
