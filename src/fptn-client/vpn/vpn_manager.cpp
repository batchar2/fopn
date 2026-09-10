/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "vpn/vpn_manager.h"

#include <algorithm>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace {
std::chrono::seconds ReconnectBackoff(int full_restart_count) {
  switch (full_restart_count) {
    case 1:
      return std::chrono::seconds(2);
    case 2:
      return std::chrono::seconds(5);
    case 3:
      return std::chrono::seconds(15);
    default:
      return std::chrono::seconds(30);
  }
}
}  // namespace

namespace fptn::vpn {
VpnManager::VpnManager(Config config)
    : running_(false),
      ever_connected_(false),
      gave_up_(false),
      reconnecting_(false),
      reconnect_attempt_(0),
      config_(std::move(config)) {}  // NOLINT

VpnManager::~VpnManager() { Stop(); }

bool VpnManager::IsStarted() {
  if (!running_) {
    return false;
  }

  if (gave_up_) {
    return false;
  }
  if (switching_) {
    return true;
  }
  if (ever_connected_) {
    return true;
  }

  const std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);  // mutex

  return lock.owns_lock() && config_.http_client &&
         config_.http_client->IsStarted();
}

bool VpnManager::IsReconnecting() const { return reconnecting_; }

int VpnManager::ReconnectAttempt() const { return reconnect_attempt_; }

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
int VpnManager::MaxReconnectAttempts() const { return kMaxFullRestarts_; }

bool VpnManager::Start() {
  if (running_) {
    return false;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  // cppcheck-suppress identicalConditionAfterEarlyExit
  if (running_ || !config_.http_client) {
    return false;
  }
  running_ = true;

  // NOLINTNEXTLINE(modernize-avoid-bind)
  config_.http_client->SetRecvBatchIPPacketCallback(std::bind(
      &VpnManager::HandleOnPacketsFromWebSocket, this, std::placeholders::_1));

  bool tun_opened = false;
  if (config_.virtual_net_interface) {
    config_.virtual_net_interface->SetRecvBatchIPPacketCallback(
        // NOLINTNEXTLINE(modernize-avoid-bind)
        std::bind(&VpnManager::HandleOnPacketsFromVirtualNetworkInterface, this,
            std::placeholders::_1));
    constexpr int kMaxTunOpenAttempts = 5;
    constexpr auto kTunOpenRetryDelay = std::chrono::milliseconds(100);
    for (int attempt = 1;
        running_ && !tun_opened && attempt <= kMaxTunOpenAttempts; ++attempt) {
      tun_opened = config_.virtual_net_interface->Start();
      if (!tun_opened) {
        SPDLOG_WARN(
            "Failed to open TUN device on (re)connect (attempt {}/{}), "
            "retrying in {} ms",
            attempt, kMaxTunOpenAttempts, kTunOpenRetryDelay.count());
        std::this_thread::sleep_for(kTunOpenRetryDelay);
      }
    }
  }

  if (!tun_opened) {
    SPDLOG_ERROR(
        "Could not open TUN device after IP assignment; skipping route"
        "setup and marking the connection as down so it can recover");
    return false;
  }

  if (config_.route_manager) {
    config_.route_manager->Apply(config_.virtual_net_interface->Name());
  }

  config_.http_client->Start();

  // Start worker
  thread_ = std::thread(&VpnManager::ProcessWebSocketPackets, this);

  supervisor_thread_ = std::thread(&VpnManager::Supervise, this);

  return true;
}

bool VpnManager::IsClientStarted() const {
  // Клиент можно подменить на лету, поэтому указатель читаем под мьютексом.
  const std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
  return lock.owns_lock() && config_.http_client &&
         config_.http_client->IsStarted();
}

bool VpnManager::IsClientConnected() const {
  const std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
  return lock.owns_lock() && config_.http_client &&
         config_.http_client->IsConnected();
}

bool VpnManager::SwitchClient(
    const std::function<fptn::vpn::http::ClientPtr()>& make_client) {
  if (!make_client || !running_) {
    return false;
  }

  // Флаг снимает панику главного цикла: пока идёт смена, туннель формально
  // не подключён, но это не обрыв.
  switching_ = true;

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (!running_ || !config_.http_client) {
    switching_ = false;
    return false;
  }

  SPDLOG_INFO("Switching the tunnel to another server");

  // Сессию отпускаем до логина: сервер может считать сессии на пользователя,
  // и вход со второго места он бы отклонил.
  auto previous = std::move(config_.http_client);
  previous->Stop();

  auto client = make_client();
  if (!client) {
    SPDLOG_WARN("Switch failed, staying on the current server");
    config_.http_client = std::move(previous);
    config_.http_client->Start();
    switching_ = false;
    return false;
  }

  config_.http_client = std::move(client);
  // NOLINTNEXTLINE(modernize-avoid-bind)
  config_.http_client->SetRecvBatchIPPacketCallback(std::bind(
      &VpnManager::HandleOnPacketsFromWebSocket, this, std::placeholders::_1));
  config_.http_client->Start();

  // ever_connected_ не трогаем: это признак "туннель хоть раз поднимался", и
  // смена сервера его не отменяет. Сбросить его здесь означало бы, что
  // IsStarted() на время переключения отвечает "нет" - главный цикл принимает
  // это за обрыв и завершает процесс.
  reconnecting_ = false;
  reconnect_attempt_ = 0;

  switching_ = false;
  return true;
}

bool VpnManager::Stop() {
  if (!running_) {
    return false;
  }
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    // cppcheck-suppress identicalConditionAfterEarlyExit
    if (!running_) {
      return false;
    }

    running_ = false;
  }

  {
    const std::unique_lock<std::mutex> lock(queue_mutex_);  // mutex

    ws_queue_cv_.notify_all();
  }
  {
    const std::unique_lock<std::mutex> lock(reconnect_mutex_);  // mutex

    reconnect_cv_.notify_all();
  }

  if (supervisor_thread_.joinable()) {
    supervisor_thread_.join();
  }

  SPDLOG_INFO("Stopping VPN Websocket-workers...");
  if (thread_.joinable()) {
    thread_.join();
  }

  SPDLOG_INFO("Stopping tasks");
  for (auto& task : pending_tasks_) {
    if (task.valid()) {
      task.wait();
    }
  }
  pending_tasks_.clear();

  SPDLOG_INFO("Stopping VPN client...");

  if (config_.virtual_net_interface) {
    SPDLOG_INFO("Stopping virtual network interface");
    config_.virtual_net_interface->Stop();
  }

  if (config_.http_client) {
    SPDLOG_INFO("Stopping HTTP client");
    config_.http_client->Stop();
  }

  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    config_.virtual_net_interface.reset();
    config_.http_client.reset();
  }

  return true;
}

std::size_t VpnManager::GetSendRate() {
  if (!running_) {
    return 0;
  }

  const std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);  // mutex

  if (lock.owns_lock() && running_ && config_.virtual_net_interface) {
    last_send_rate_ = config_.virtual_net_interface->GetSendRate();
  }
  return last_send_rate_;
}

std::size_t VpnManager::GetReceiveRate() {
  if (!running_) {
    return 0;
  }

  const std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);  // mutex

  if (lock.owns_lock() && running_ && config_.virtual_net_interface) {
    last_receive_rate_ = config_.virtual_net_interface->GetReceiveRate();
  }
  return last_receive_rate_;
}

std::string VpnManager::GetInterfaceName() const {
  if (config_.virtual_net_interface) {
    return config_.virtual_net_interface->Name();
  }
  return {};
}

void VpnManager::HandleOnPacketsFromVirtualNetworkInterface(
    fptn::common::network::BatchIPPacketPtr packets) {
  if (!running_) {
    return;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (running_ && config_.http_client) {
    for (auto& packet : packets) {
      if (!packet) {
        continue;
      }
#ifndef FPTN_OPENWRT
      if (config_.ad_blocker && packet->IsDns()) {
        if (auto response = config_.ad_blocker->ProcessOutgoingDns(*packet)) {
          if (config_.virtual_net_interface) {
            config_.virtual_net_interface->Send(std::move(response));
          }
          continue;
        }
      }
#endif
      if (config_.http_client->Send(std::move(packet))) {
        ++to_server_sent_;
      } else {
        ++to_server_dropped_;
      }
    }
  }
}

void VpnManager::HandleOnPacketsFromWebSocket(
    fptn::common::network::BatchIPPacketPtr packets) {
  if (!running_ || packets.empty()) {
    return;
  }

  constexpr std::size_t kMaxQueueSize = 1024 * 16;

  std::unique_lock<std::mutex> lock(queue_mutex_);

  if (ws_packet_queue_.size() >= kMaxQueueSize) {
    SPDLOG_WARN("WebSocket packet queue is full, dropping packets");
    return;
  }

  for (auto& packet : packets) {
    if (packet) {
      ws_packet_queue_.push(std::move(packet));
    }
  }
  lock.unlock();
  ws_queue_cv_.notify_one();
}

void VpnManager::ProcessWebSocketPackets() {
  while (running_) {
    fptn::common::network::BatchIPPacketPtr batch;
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);  // mutex
      ws_queue_cv_.wait(
          lock, [this]() { return !ws_packet_queue_.empty() || !running_; });
      if (!running_ && ws_packet_queue_.empty()) {
        break;
      }
      while (!ws_packet_queue_.empty()) {
        batch.push_back(std::move(ws_packet_queue_.front()));
        ws_packet_queue_.pop();
      }
    }

    if (batch.empty()) {
      continue;
    }

    fptn::common::network::BatchIPPacketPtr to_send;
    to_send.reserve(batch.size());
    for (auto& packet : batch) {
      for (const auto& plugin : config_.plugins) {
        if (packet) {
          auto [processed_packet, triggered] =
              plugin->HandlePacket(std::move(packet));
          packet = std::move(processed_packet);
          if (triggered) {
            break;
          }
        }
      }
      if (packet) {
        to_send.push_back(std::move(packet));
      }
    }

    if (!to_send.empty()) {
      const std::size_t count = to_send.size();
      const std::unique_lock<std::mutex> lock(mutex_);
      if (running_ && config_.virtual_net_interface &&
          config_.virtual_net_interface->SendBatch(std::move(to_send))) {
        to_tun_sent_ += count;
      } else {
        to_tun_dropped_ += count;
      }
    }
  }
}

void VpnManager::Supervise() {
  int full_restart_count = 0;
  while (running_) {
    {
      std::unique_lock<std::mutex> lock(reconnect_mutex_);
      reconnect_cv_.wait_for(lock, std::chrono::milliseconds(500),
          [this]() { return !running_ || !IsClientStarted(); });
    }
    if (!running_) {
      break;
    }
    if (IsClientConnected()) {
      ever_connected_ = true;
      full_restart_count = 0;
      reconnecting_ = false;
      reconnect_attempt_ = 0;
      continue;
    }
    if (ever_connected_) {
      reconnect_attempt_ = std::max(full_restart_count, 1);
      reconnecting_ = true;
    }
    if (IsClientStarted()) {
      continue;
    }

    if (full_restart_count >= kMaxFullRestarts_) {
      SPDLOG_ERROR("VPN reconnection failed after {} full restarts. Giving up.",
          kMaxFullRestarts_);
      if (config_.route_manager) {
        config_.route_manager->Clean();
      }
      reconnecting_ = false;
      gave_up_ = true;
      break;
    }
    ++full_restart_count;
    reconnect_attempt_ = full_restart_count;
    SPDLOG_WARN(
        "Full VPN restart {}/{}", full_restart_count, kMaxFullRestarts_);

    std::string tun_name;
    {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      config_.http_client->Stop();
      tun_name = config_.virtual_net_interface->Name();
    }

    // Unlocked: the route manager guards itself, and holding mutex_ across
    // seconds of netsh/powershell freezes both packet paths.
    if (config_.route_manager) {
      config_.route_manager->Clean();
    }

    {
      std::unique_lock<std::mutex> lock(reconnect_mutex_);
      reconnect_cv_.wait_for(lock, ReconnectBackoff(full_restart_count),
          [this]() { return !running_.load(); });
    }
    if (!running_) {
      break;
    }

    if (config_.route_manager) {
      config_.route_manager->Apply(tun_name);
    }

    {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      config_.http_client->Start();
    }
  }
}

}  // namespace fptn::vpn
