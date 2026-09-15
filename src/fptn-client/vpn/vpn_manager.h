/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <queue>

#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"
#include "common/network/net_interface.h"

#include "http/client.h"
#include "plugins/split/tunneling.h"

namespace fptn::vpn {

using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;

class VpnManager final {
 public:
  struct Config {
    fptn::vpn::http::ClientPtr http_client;
    fptn::routing::RouteManagerSPtr route_manager;
    fptn::common::network::TunInterfaceSPtr virtual_net_interface;
    fptn::plugin::PluginList plugins;
  };

 public:
  explicit VpnManager(Config config);
  ~VpnManager();

  bool Start();
  bool Stop();

  // Swap the server without bringing the tunnel up again: the TUN device is
  // already open and the routes are applied, only the far end changes.
  // Switching used to mean leaving the process - procd started the client
  // again, and it came back on the very same server.
  //
  // Takes a factory rather than a ready connection: the login to the new
  // server has to happen after the current session is released, otherwise a
  // server that counts sessions per user refuses it. If the factory returns
  // nothing, the previous connection is brought back up.
  bool SwitchClient(
      const std::function<fptn::vpn::http::ClientPtr()>& make_client);
  std::size_t GetSendRate();
  std::size_t GetReceiveRate();
  bool IsStarted();

  // The packet counters were always maintained, but had no getters - the
  // numbers piled up and nobody could read them.
  std::uint64_t ToServerSent() const noexcept { return to_server_sent_.load(); }
  std::uint64_t ToServerDropped() const noexcept {
    return to_server_dropped_.load();
  }
  std::uint64_t ToTunSent() const noexcept { return to_tun_sent_.load(); }
  std::uint64_t ToTunDropped() const noexcept { return to_tun_dropped_.load(); }
  bool IsReconnecting() const;
  int ReconnectAttempt() const;
  int MaxReconnectAttempts() const;
  [[nodiscard]] std::string GetInterfaceName() const;

 protected:
  [[nodiscard]] bool IsClientStarted() const;
  [[nodiscard]] bool IsClientConnected() const;
  void ProcessWebSocketPackets();
  void Supervise();

  void HandleOnPacketsFromVirtualNetworkInterface(
      fptn::common::network::BatchIPPacketPtr packets);
  void HandleOnPacketsFromWebSocket(
      fptn::common::network::BatchIPPacketPtr packets);

 private:
  mutable std::mutex mutex_;
  mutable std::mutex queue_mutex_;
  static constexpr int kMaxFullRestarts_ = 10;

  std::atomic<bool> running_;
  std::atomic<bool> ever_connected_;
  std::atomic<bool> gave_up_;
  std::atomic<bool> reconnecting_;
  // A server switch is in progress: there is no connection at this moment,
  // but it must not count as a drop - the main loop would end the process.
  std::atomic<bool> switching_{false};
  std::atomic<int> reconnect_attempt_;

  std::atomic<std::size_t> last_send_rate_{0};
  std::atomic<std::size_t> last_receive_rate_{0};

  std::atomic<std::uint64_t> to_server_sent_{0};
  std::atomic<std::uint64_t> to_server_dropped_{0};
  std::atomic<std::uint64_t> to_tun_sent_{0};
  std::atomic<std::uint64_t> to_tun_dropped_{0};

  Config config_;

  std::thread thread_;
  std::thread supervisor_thread_;
  std::mutex reconnect_mutex_;
  std::condition_variable reconnect_cv_;
  std::condition_variable ws_queue_cv_;
  std::queue<fptn::common::network::IPPacketPtr> ws_packet_queue_;

  std::vector<std::future<void>> pending_tasks_;
};

using VpnClientPtr = std::shared_ptr<fptn::vpn::VpnManager>;
}  // namespace fptn::vpn
