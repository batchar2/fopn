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

// Результат одной пробы: сколько заняла и почему не удалась. Раньше замеры
// жили только внутри гонки и выбрасывались - наружу не выходило ни одного
// числа, поэтому ни список серверов, ни их задержки показать было нечем.
using ProbeCallback = std::function<void(const ServerInfo& server,
    std::uint32_t delay_ms,
    const std::string& error)>;

// Сколько серверов опрашиваем одновременно. Раньше на каждый сервер
// заводился отдельный поток; на роутере с большим пулом это заметно.
constexpr std::size_t kMaxProbeConcurrency = 8;

std::uint64_t GetDownloadTimeMs(const ServerInfo& server,
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
