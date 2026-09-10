/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-client/utils/speed_estimator/speed_estimator.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <fmt/format.h>       // NOLINT(build/include_order)
#include <nlohmann/json.hpp>  // NOLINT(build/include_order)
#include <spdlog/spdlog.h>    // NOLINT(build/include_order)

#include "common/api/handle.h"

#include "fptn-protocol-lib/https/api_client/api_client.h"

using fptn::protocol::https::ApiClient;
using fptn::utils::speed_estimator::ServerInfo;

constexpr std::uint64_t kMaxTimeout = UINT64_MAX;

namespace fptn::utils::speed_estimator {

std::uint64_t GetDownloadTimeMs(const ServerInfo& server,
    const std::string& sni,
    int timeout,
    const std::string& md5_fingerprint,
    fptn::protocol::https::CensorshipStrategy censorship_strategy) {
  try {
    auto const start = std::chrono::high_resolution_clock::now();
    ApiClient cli(
        server.host, server.port, sni, md5_fingerprint, censorship_strategy);
    auto const resp = cli.Get(common::api::kApiTestFileBinUrl, timeout);
    if (resp.code == 200) {
      auto const end = std::chrono::high_resolution_clock::now();
      const std::uint64_t ms =
          std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
              .count();
      return ms;
    }
  } catch (const std::exception& ex) {
    SPDLOG_WARN("Exception in GetDownloadTimeMs: {}", ex.what());
  } catch (...) {
    SPDLOG_WARN("Unknown exception in GetDownloadTimeMs");
  }
  return kMaxTimeout;
}

std::optional<LoginResult> FindServerByLogin(const std::string& sni,
    const std::vector<ServerInfo>& servers,
    fptn::protocol::https::CensorshipStrategy censorship_strategy,
    int timeout_sec,
    ProbeCallback on_probe) {
  if (servers.empty()) {
    return std::nullopt;
  }

  // Раньше список перемешивался и опрашивалась случайная половина: быстрый
  // сервер мог просто не попасть в выборку, и клиент про него не узнавал.
  // Теперь опрашиваются все, но не больше kMaxProbeConcurrency разом.
  struct State {
    std::mutex mtx;
    std::condition_variable cv;
    std::optional<LoginResult> result;
    std::atomic<std::size_t> next{0};
    std::size_t completed = 0;
    std::size_t total = 0;
  };
  auto state = std::make_shared<State>();
  state->total = servers.size();

  auto pool = std::make_shared<std::vector<ServerInfo>>(servers);
  auto probe = std::make_shared<ProbeCallback>(std::move(on_probe));

  const std::size_t workers =
      std::min<std::size_t>(kMaxProbeConcurrency, servers.size());

  for (std::size_t worker = 0; worker < workers; ++worker) {
    // NOLINTNEXTLINE(bugprone-exception-escape)
    std::thread([state, pool, probe, sni, timeout_sec, censorship_strategy]() {
      for (;;) {
        const std::size_t index = state->next.fetch_add(1);
        if (index >= pool->size()) {
          return;
        }
        const auto& server = (*pool)[index];

        std::optional<LoginResult> local;
        std::string error;
        const auto started = std::chrono::steady_clock::now();
        try {
          const std::string body =
              fmt::format(R"({{ "username": "{}", "password": "{}" }})",
                  server.username, server.password);
          ApiClient cli(server.host, server.port, sni, server.md5_fingerprint,
              censorship_strategy);
          const auto resp = cli.Post(
              common::api::kApiLoginUrl, body, "application/json", timeout_sec);
          if (resp.code == 200) {
            const auto msg = resp.Json();
            if (msg.contains("access_token")) {
              local = LoginResult{.server = server,
                  .access_token = msg["access_token"].get<std::string>()};
            } else {
              error = "no access_token in response";
            }
          } else {
            error = fmt::format("HTTP {}", resp.code);
          }
        } catch (const std::exception& ex) {
          error = ex.what();
        } catch (...) {  // NOLINT
          error = "unknown error";
        }

        // Время логина - это и есть задержка до сервера: лёгкий запрос без
        // скачивания тестового файла, поэтому число отражает канал, а не
        // ширину полосы.
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - started)
                .count();
        if (probe && *probe) {
          const auto delay = local ? std::max<std::int64_t>(1, elapsed) : 0;
          (*probe)(server, static_cast<std::uint32_t>(delay), error);
        }

        {
          const std::scoped_lock<std::mutex> lock(state->mtx);
          if (local && !state->result.has_value()) {
            state->result = std::move(local);
          }
          ++state->completed;
        }
        state->cv.notify_one();
      }
    }).detach();
  }

  std::unique_lock<std::mutex> lock(state->mtx);
  state->cv.wait_for(lock, std::chrono::seconds(timeout_sec + 2), [&state] {
    return state->result.has_value() || state->completed == state->total;
  });

  // Оставшиеся потоки домеривают пул в фоне и дописывают результаты через
  // колбэк - выбор сервера их не ждёт.
  return state->result;
}

}  // namespace fptn::utils::speed_estimator
