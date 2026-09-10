/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include <boost/asio.hpp>

#include "fptn-client/status/server_registry.h"

namespace fptn::client::status {

// Локальный HTTP-эндпоинт со списком серверов и их задержками.
//
// До него у клиента не было ни одного машиночитаемого выхода: только строки
// в логе и код возврата процесса. Прозрачный прокси, который держит клиент
// помощником, не мог показать ни пул, ни пинги - ему просто неоткуда было их
// взять.
//
// Форма ответов повторяет Clash API (sing-box, mihomo): тот же JSON уже умеют
// читать и панели, и обвязки на роутерах, поэтому ничего нового учить не
// нужно.
class StatusServer final {
 public:
  struct Options {
    std::string listen_address = "127.0.0.1";
    std::uint16_t listen_port = 0;
    // Пустой секрет означает "без проверки". Так делает и sing-box, но по
    // умолчанию слушаем только петлю, чтобы это не превращалось в дыру.
    std::string secret;
  };

  // Замер по требованию: вернуть задержку в мс, 0 - неудача.
  // NOLINTNEXTLINE(readability/casting) - это тип функции, а не C-каст
  using DelayProbeSignature = std::uint32_t(const ServerInfo&, int);
  using DelayProbe = std::function<DelayProbeSignature>;
  // Переключение на другой сервер. true, если запрос принят.
  using SwitchServer = std::function<bool(const ServerInfo& server)>;
  // Состояние туннеля и служб - всё, что знает только сам клиент.
  using StatusProvider = std::function<nlohmann::json()>;

  StatusServer(Options options, std::shared_ptr<ServerRegistry> registry);
  ~StatusServer();

  StatusServer(const StatusServer&) = delete;
  StatusServer& operator=(const StatusServer&) = delete;

  void SetDelayProbe(DelayProbe probe);
  void SetSwitchServer(SwitchServer handler);
  void SetStatusProvider(StatusProvider provider);

  bool Start();
  void Stop();
  [[nodiscard]] bool IsRunning() const { return running_; }

 private:
  void AcceptLoop();
  void HandleConnection(boost::asio::ip::tcp::socket socket);

  struct Reply {
    unsigned status = 200;
    nlohmann::json body;
  };
  [[nodiscard]] Reply Route(const std::string& method,
      const std::string& target,
      const std::string& body) const;
  [[nodiscard]] Reply HandleDelay(
      const std::string& name, const std::string& query) const;
  [[nodiscard]] Reply HandleSwitch(
      const std::string& name, const std::string& body) const;
  [[nodiscard]] bool Authorized(const std::string& header) const;

  const Options options_;
  const std::shared_ptr<ServerRegistry> registry_;

  DelayProbe delay_probe_;
  SwitchServer switch_server_;
  StatusProvider status_provider_;

  boost::asio::io_context ioc_;
  std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
  std::thread thread_;
  std::atomic<bool> running_{false};
};

}  // namespace fptn::client::status
