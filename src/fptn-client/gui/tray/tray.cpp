/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "gui/tray/tray.h"

#include <memory>
#include <numeric>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include <QDesktopServices>  // NOLINT(build/include_order)
#include <QFuture>           // NOLINT(build/include_order)
#include <QFutureWatcher>    // NOLINT(build/include_order)
#include <QIcon>             // NOLINT(build/include_order)
#include <QMessageBox>       // NOLINT(build/include_order)
#include <QStyleFactory>     // NOLINT(build/include_order)
#include <QStyleHints>       // NOLINT(build/include_order)
#include <QtConcurrent>      // NOLINT(build/include_order)

#include "common/network/ip_packet.h"
#include "common/system/command.h"

#include "fptn-protocol-lib/https/obfuscator/methods/tls/tls_obfuscator.h"
#include "fptn-protocol-lib/time/time_provider.h"
#include "gui/autoupdate/autoupdate.h"
#include "gui/server_menu_item_widget/server_menu_item_widget.h"
#include "gui/style/style.h"
#include "gui/translations/translations.h"
#include "plugins/adblock/adblock.h"
#include "plugins/blacklist/domain_blacklist.h"

#ifdef _WIN32
#include "utils/windows/vpn_conflict.h"
#endif

using fptn::gui::TrayApp;

namespace {

#ifndef __APPLE__
QPixmap LoadIcon(const QString& icon_path, int size = 12) {
  QPixmap pixmap(icon_path);
  if (pixmap.isNull()) {
    return QPixmap();
  }
  return pixmap.scaled(
      size, size, Qt::KeepAspectRatio, Qt::SmoothTransformation);
}
#endif

void ShowError(const QString& title, const QString& msg) {
  QMessageBox msg_box;
  msg_box.setWindowIcon(QIcon(":/icons/app.ico"));
  msg_box.setIcon(QMessageBox::Critical);
  msg_box.setWindowTitle(title);
#ifdef _WIN32
  msg_box.setText(msg.toUtf8());
#else
  msg_box.setText(msg);
#endif
  msg_box.exec();
}

#ifdef _WIN32
void ShowWarning(const QString& title, const QString& msg) {
  QMessageBox msg_box;
  msg_box.setWindowIcon(QIcon(":/icons/app.ico"));
  msg_box.setIcon(QMessageBox::Warning);
  msg_box.setWindowTitle(title);
  msg_box.setText(msg);
  msg_box.exec();
}
#endif

}  // namespace

TrayApp::TrayApp(const SettingsModelPtr& settings, QObject* parent)
    : settings_(settings),
      tray_icon_(new QSystemTrayIcon(this)),
      tray_menu_(new QMenu(this)),
      connect_menu_(new QMenu(QObject::tr("Connect") + "    ", tray_menu_)),
      speed_widget_(new SpeedWidget(tray_menu_)),
      update_timer_(new QTimer(this)),
      active_icon_path_(":/icons/active.ico"),
      inactive_icon_path_(":/icons/inactive.ico") {
  (void)parent;
#ifdef __linux__
  qApp->setStyleSheet(fptn::gui::GetUbuntuStyleSheet());
#elif __APPLE__
  qApp->setStyleSheet(fptn::gui::GetMacStyleSheet());
#elif _WIN32
  qApp->setStyleSheet(fptn::gui::GetWindowsStyleSheet());
#else
#error "Unsupported system!"
#endif

#if __linux__
  connect(tray_icon_, &QSystemTrayIcon::activated,
      [this](QSystemTrayIcon::ActivationReason reason) {
        if (reason == QSystemTrayIcon::Context) {
          tray_menu_->popup(tray_icon_->geometry().bottomLeft());
        } else {
          tray_menu_->close();
        }
      });
#elif _WIN32
  connect(tray_icon_, &QSystemTrayIcon::activated,
      [this](QSystemTrayIcon::ActivationReason reason) {
        if (reason == QSystemTrayIcon::Context) {
          tray_menu_->show();
          tray_menu_->exec(QCursor::pos());
        } else {
          tray_menu_->close();
        }
      });
#endif
  const QString selected_language = settings->LanguageCode();
  if (selected_language.isEmpty()) {  // save default language for first start
    const QString system_language = GetSystemLanguageCode();
    if (settings->ExistsTranslation(system_language)) {
      settings->SetLanguageCode(system_language);
    } else {
      settings->SetLanguageCode(settings->DefaultLanguageCode());
    }
  } else {
    fptn::gui::SetTranslation(selected_language);
  }

  // State
  connect(this, &TrayApp::defaultState, this, &TrayApp::handleDefaultState);
  connect(this, &TrayApp::connecting, this, &TrayApp::handleConnecting);
  connect(this, &TrayApp::connected, this, &TrayApp::handleConnected);
  connect(this, &TrayApp::disconnecting, this, &TrayApp::handleDisconnecting);
  connect(this, &TrayApp::vpnStarted, this, &TrayApp::handleVpnStarted);

  // Show connection... label
  connecting_label_action_ = new QAction(QObject::tr("Connecting..."), this);
#ifndef __APPLE__
  connecting_label_action_->setIcon(LoadIcon(":/icons/menu_connection.png"));
#endif
  connect(connecting_label_action_, &QAction::triggered, this,
      &TrayApp::handleDefaultState);

  // Show Disconnecting... label
  disconnecting_label_action_ =
      new QAction(QObject::tr("Disconnecting..."), this);

  // Show Reconnecting... label
  reconnecting_label_action_ =
      new QAction(QObject::tr("Reconnecting..."), this);
#ifndef __APPLE__
  reconnecting_label_action_->setIcon(LoadIcon(":/icons/menu_connection.png"));
#endif
  reconnecting_label_action_->setVisible(false);
  connect(reconnecting_label_action_, &QAction::triggered, this,
      &TrayApp::onDisconnectFromServer);

  // Disconect
  disconnect_action_ = new QAction(QObject::tr("Disconnect"), this);
#ifndef __APPLE__
  disconnect_action_->setIcon(LoadIcon(":/icons/menu_disconnect.png"));
#endif
  connect(disconnect_action_, &QAction::triggered, this,
      &TrayApp::onDisconnectFromServer);

  speed_widget_action_ = new QWidgetAction(this);
  speed_widget_action_->setDefaultWidget(speed_widget_);

  // Settings
  connect(settings_.get(), &SettingsModel::dataChanged, this,
      &TrayApp::UpdateTrayMenu);
  connect(update_timer_, &QTimer::timeout, this, &TrayApp::handleTimer);
  update_timer_->start(1000);

  // Connect
#ifndef __APPLE__
  connect_menu_->setIcon(LoadIcon(":/icons/menu_server_list.png"));
#endif

  // Settings
  settings_action_ = new QAction(QObject::tr("Settings"), this);
#ifndef __APPLE__
  settings_action_->setIcon(LoadIcon(":/icons/menu_settings.png"));
#endif
  connect(
      settings_action_, &QAction::triggered, this, &TrayApp::onShowSettings);

  // Autoupdate
  auto_update_action_ = new QAction(
      QObject::tr("New version available") + " " + auto_available_version_,
      this);
#ifndef __APPLE__
  auto_update_action_->setIcon(
      LoadIcon(":/icons/menu_new_version_download.png"));
#endif
  connect(auto_update_action_, &QAction::triggered, this,
      [this] { OpenWebBrowser(FPTN_GITHUB_PAGE_LINK); });
  auto_update_action_->setVisible(false);

  // Quit
  quit_action_ = new QAction(QObject::tr("Quit"), this);
#ifndef __APPLE__
  quit_action_->setIcon(LoadIcon(":/icons/menu_exit.png"));
#endif
  connect(quit_action_, &QAction::triggered, this, &QCoreApplication::quit);

  // Show menu
  // tray_menu_->addAction(connecting_action_);
  tray_menu_->addAction(disconnect_action_);
  tray_menu_->addAction(connecting_label_action_);
  tray_menu_->addAction(disconnecting_label_action_);
  tray_menu_->addAction(reconnecting_label_action_);
  tray_menu_->addAction(speed_widget_action_);
  tray_menu_->addSeparator();
  tray_menu_->addAction(settings_action_);
  tray_menu_->addSeparator();
  tray_menu_->addAction(auto_update_action_);
  tray_menu_->addSeparator();
  tray_menu_->addAction(quit_action_);

  tray_icon_->setContextMenu(tray_menu_);

  tray_icon_->show();

  // check update
  CheckForUpdatesAsync();

  try {
    settings_->Load(false);  // use this to show notification about change
                             // structure v1 and v2 config
  } catch (std::runtime_error& err) {
    ShowError(QObject::tr("Settings"), err.what());
  }
  UpdateTrayMenu();

#ifdef _WIN32
  std::string found_adapters;
  if (fptn::utils::windows::HasVpnConflicts(found_adapters)) {
    SPDLOG_WARN(
        "Detected conflicting VPN network adapters: {}", found_adapters);
    const QString message = QObject::tr(
        "A conflicting VPN connection is currently active on your system: %1\n"
        "This may cause network connectivity issues or prevent proper "
        "operation of FPTN.")
                                .arg(QString::fromStdString(found_adapters));

    ShowWarning(QObject::tr("VPN Conflict Detected"), message);
  }
#endif
  // start pinging
  settings_->StartPingMonitoring();

  // Show pings
  ping_update_timer_ = new QTimer(this);
  connect(ping_update_timer_, &QTimer::timeout, [this]() { UpdatePings(); });
  ping_update_timer_->start(1000);
}

void TrayApp::CheckForUpdatesAsync() {
  (void)QtConcurrent::run([this]() {
    try {
      SPDLOG_DEBUG("Checking for updates in background thread");

      const auto update_result = fptn::gui::autoupdate::Check();
      const bool is_available = update_result.first;
      const std::string version_name = update_result.second;

      SPDLOG_INFO("Update check completed: available={}, version={}",
          is_available, version_name);
      if (is_available && !version_name.empty()) {
        QMetaObject::invokeMethod(
            this,
            // NOLINTNEXTLINE(bugprone-exception-escape)
            [this, version_name]() noexcept {
              try {
                auto_available_version_ = QString::fromStdString(version_name);
                auto_update_action_->setText(
                    QObject::tr("New version available") + " " +
                    auto_available_version_);
                auto_update_action_->setVisible(true);
                RetranslateUi();
              } catch (...) {
                SPDLOG_WARN("Failed to update UI with new version info");
              }
            },
            Qt::QueuedConnection);
      } else {
        SPDLOG_DEBUG("No updates available or version name is empty");
      }
    } catch (const std::exception& e) {
      SPDLOG_WARN("Failed to check for updates: {}", e.what());
    } catch (...) {
      SPDLOG_WARN("Unknown error during update check");
    }
  });
}

void TrayApp::UpdateTrayMenu() {
  if (limited_zone_connect_menu_) {
    limited_zone_connect_menu_->clear();
  }
  if (connect_menu_) {
    connect_menu_->clear();
  }
  if (tray_menu_ && connect_menu_) {
    tray_menu_->removeAction(connect_menu_->menuAction());
    smart_connect_action_ = nullptr;
    empty_configuration_action_ = nullptr;

    limited_zone_connect_menu_ = nullptr;
  }

  if (reconnecting_label_action_) {
    reconnecting_label_action_->setVisible(false);
  }

  switch (connection_state_) {
    case ConnectionState::None: {
      tray_icon_->setIcon(QIcon(inactive_icon_path_));
      const auto& services = settings_->Services();

      // calculate services
      const std::size_t servers_number =
          std::accumulate(services.begin(), services.end(), std::size_t{0},
              [](std::size_t sum, const auto& service) {
                return sum + service.servers.size();
              });

      if (0 != servers_number) {
        smart_connect_action_ =
            new QAction(QObject::tr("Smart Connect"), connect_menu_);
#ifndef __APPLE__
        smart_connect_action_->setIcon(QIcon(":/icons/ping_green_circle.png"));
#endif
        connect(smart_connect_action_, &QAction::triggered, [this]() {
          smart_connect_ = true;
          onConnectToServer();
        });

        connect_menu_->addAction(smart_connect_action_);
        connect_menu_->addSeparator();
        // servers
        for (const auto& service : services) {
          // usual servers
          for (const auto& server : service.servers) {
            auto* action = new ServerMenuItemWidget(
                server.name, server.ping_ms, connect_menu_);
            // auto* widget_action = new QWidgetAction(connect_menu_);
            // widget_action->setDefaultWidget(widget);
            connect_menu_->addAction(action);

            // FIXME
            connect(action, &QAction::triggered, [this, server, service]() {
              smart_connect_ = false;
              fptn::utils::speed_estimator::ServerInfo cfg_server;
              {
                cfg_server.name = server.name.toStdString();
                cfg_server.host = server.host.toStdString();
                cfg_server.port = server.port;
                cfg_server.is_using = server.is_using;
                cfg_server.service_name = service.service_name.toStdString();
                cfg_server.username = service.username.toStdString();
                cfg_server.password = service.password.toStdString();
                cfg_server.md5_fingerprint =
                    server.md5_fingerprint.toStdString();
              }
              selected_server_ = cfg_server;
              onConnectToServer();
            });
          }
          // Censored zone servers
          for (const auto& server : service.censored_zone_servers) {
            if (!limited_zone_connect_menu_) {
              limited_zone_connect_menu_ = new QMenu(
                  QObject::tr("Limited access servers") + "  ", connect_menu_);
#ifndef __APPLE__
              limited_zone_connect_menu_->setIcon(
                  LoadIcon(":/icons/menu_server_list.png"));
#endif
              connect_menu_->addMenu(limited_zone_connect_menu_);
            }
            auto* server_connect =
                new QAction(server.name, limited_zone_connect_menu_);
            limited_zone_connect_menu_->addAction(server_connect);

            // FIXME
            connect(
                server_connect, &QAction::triggered, [this, server, service]() {
                  smart_connect_ = false;
                  fptn::utils::speed_estimator::ServerInfo cfg_server;
                  {
                    cfg_server.name = server.name.toStdString();
                    cfg_server.host = server.host.toStdString();
                    cfg_server.port = server.port;
                    cfg_server.is_using = server.is_using;
                    cfg_server.service_name =
                        service.service_name.toStdString();
                    cfg_server.username = service.username.toStdString();
                    cfg_server.password = service.password.toStdString();
                    cfg_server.md5_fingerprint =
                        server.md5_fingerprint.toStdString();
                    cfg_server.censored_zone = true;
                  }
                  selected_server_ = cfg_server;
                  onConnectToServer();
                });
          }
        }
      } else {
        empty_configuration_action_ =
            new QAction(QObject::tr("No servers"), connect_menu_);
        connect_menu_->addAction(empty_configuration_action_);
        empty_configuration_action_->setEnabled(false);
      }
      tray_menu_->insertMenu(settings_action_, connect_menu_);
      if (connect_menu_) {
        connect_menu_->setVisible(false);
      }
      if (disconnect_action_) {
        disconnect_action_->setVisible(false);
      }
      if (speed_widget_action_) {
        speed_widget_action_->setVisible(false);
      }
      if (settings_action_) {
        settings_action_->setEnabled(true);
      }
      if (speed_widget_) {
        speed_widget_->setVisible(false);
      }
      if (connecting_label_action_) {
        connecting_label_action_->setVisible(false);
      }
      if (disconnecting_label_action_) {
        disconnecting_label_action_->setVisible(false);
      }
      if (quit_action_) {
        quit_action_->setEnabled(true);
      }
      break;
    }
    case ConnectionState::Connecting: {
      tray_icon_->setIcon(QIcon(inactive_icon_path_));
      if (connecting_label_action_) {
        connecting_label_action_->setVisible(true);
      }
      if (disconnecting_label_action_) {
        disconnecting_label_action_->setVisible(false);
      }
      if (speed_widget_action_) {
        speed_widget_action_->setVisible(false);
      }
      if (settings_action_) {
        settings_action_->setEnabled(false);
      }
      if (disconnect_action_) {
        disconnect_action_->setVisible(false);
      }
      if (quit_action_) {
        quit_action_->setEnabled(false);
      }
      break;
    }
    case ConnectionState::Connected: {
      tray_icon_->setIcon(QIcon(active_icon_path_));
      if (disconnect_action_) {
        disconnect_action_->setText(QString(QObject::tr("Disconnect") + ": %1")
                .arg(QString::fromStdString(selected_server_.name)));
        disconnect_action_->setVisible(true);
      }
      if (speed_widget_) {
        speed_widget_->setVisible(true);
      }
      if (settings_action_) {
        settings_action_->setEnabled(false);
      }
      if (speed_widget_action_) {
        speed_widget_action_->setVisible(true);
      }
      if (connecting_label_action_) {
        connecting_label_action_->setVisible(false);
      }
      if (disconnecting_label_action_) {
        disconnecting_label_action_->setVisible(false);
      }
      if (quit_action_) {
        quit_action_->setEnabled(true);
      }
      break;
    }
    case ConnectionState::Disconnecting: {
      tray_icon_->setIcon(QIcon(inactive_icon_path_));
      if (disconnect_action_) {
        disconnect_action_->setVisible(false);
      }
      if (speed_widget_action_) {
        speed_widget_action_->setVisible(false);
      }
      if (settings_action_) {
        settings_action_->setEnabled(false);
      }
      if (connecting_label_action_) {
        connecting_label_action_->setVisible(false);
      }
      if (disconnecting_label_action_) {
        disconnecting_label_action_->setVisible(true);
      }
      if (quit_action_) {
        quit_action_->setEnabled(false);
      }
      break;
    }
  }

  // Apply the language translation based on the user's settings
  const QString selected_language = settings_->LanguageCode();
  if (!selected_language.isEmpty()) {
    fptn::gui::SetTranslation(selected_language);
  }
  RetranslateUi();
}

void TrayApp::onConnectToServer() {
  SPDLOG_INFO("Signal: connecting to server");
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    connection_state_ = ConnectionState::Connecting;
    UpdateTrayMenu();
  }
  emit connecting();
}

void TrayApp::onDisconnectFromServer() {
  SPDLOG_INFO("Signal: disconnected from server");
  fptn::vpn::VpnClientPtr vpn_client;
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    connection_state_ = ConnectionState::None;
    vpn_client = std::move(vpn_client_);

    settings_->StartPingMonitoring();

    UpdateTrayMenu();
  }
  if (vpn_client) {
    vpn_client->Stop();
  }
}

void TrayApp::onShowSettings() {
  auto dialog = std::make_unique<SettingsWidget>(settings_);
  QMetaObject::invokeMethod(
      dialog.get(),
      [widget = dialog.get()]() {
        widget->setWindowState(
            (widget->windowState() & ~Qt::WindowMinimized) | Qt::WindowActive);
        widget->raise();
        widget->activateWindow();
      },
      Qt::QueuedConnection);
  dialog->exec();
}

void TrayApp::handleDefaultState() {
  SPDLOG_INFO("Signal: entering default state");
  fptn::vpn::VpnClientPtr vpn_client;
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    cancel_connecting_ = true;
    settings_->StartPingMonitoring();

    connection_state_ = ConnectionState::None;
    vpn_client = std::move(vpn_client_);
  }
  if (vpn_client) {
    vpn_client->Stop();
  }
  UpdateTrayMenu();
}

void TrayApp::handleConnecting() {
  SPDLOG_INFO("Signal: connecting to server");

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  settings_->StopPingMonitoring();

  connection_state_ = ConnectionState::Connecting;
  UpdateTrayMenu();

  if (!connecting_in_progress_) {  // only once!
    cancel_connecting_ = false;
    connecting_in_progress_ = true;

    QFuture<std::tuple<bool, QString>> future = QtConcurrent::run([this]() {
      QString err_msg;
      const auto status = startVpn(err_msg);
      return std::make_tuple(status, std::move(err_msg));
    });

    auto* watcher = new QFutureWatcher<std::tuple<bool, QString>>(this);
    connect(watcher, &QFutureWatcher<std::tuple<bool, QString>>::finished, this,
        [this, watcher]() {
          const std::tuple<bool, QString> result = watcher->result();
          watcher->deleteLater();

          if (!cancel_connecting_) {
            const bool status = std::get<0>(result);
            const QString err_msg = std::get<1>(result);
            emit this->vpnStarted(status, err_msg);
          }
          connecting_in_progress_ = false;
        });
    watcher->setFuture(future);
  }
}

void TrayApp::handleConnected() {
  SPDLOG_INFO("Signal: connected to server");
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    connection_state_ = ConnectionState::Connected;
  }
  UpdateTrayMenu();
}

void TrayApp::handleDisconnecting() {
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    settings_->StartPingMonitoring();

    connection_state_ = ConnectionState::None;
    UpdateTrayMenu();
  }
  stopVpn();
  emit defaultState();
}

void TrayApp::handleTimer() {
  static bool reconnection_in_progress = false;
  static auto last_reconnection_time = std::chrono::steady_clock::now();

  // check connection state
  bool is_disconnected = false;
  {
    const std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);  // mutex

    if (lock.owns_lock() && connection_state_ == ConnectionState::Connected &&
        vpn_client_) {
      if (!vpn_client_->IsStarted()) {
        // check reconnection
        auto now = std::chrono::steady_clock::now();
        auto time_since_last = std::chrono::duration_cast<std::chrono::seconds>(
            now - last_reconnection_time);

        if (!reconnection_in_progress &&
            time_since_last > std::chrono::seconds(3)) {
          reconnection_in_progress = true;
          last_reconnection_time = now;
          is_disconnected = true;
        }
      } else if (vpn_client_->IsReconnecting()) {
        if (reconnecting_label_action_) {
          const int n = vpn_client_->ReconnectAttempt();
          QString text = QObject::tr("Reconnecting...");
          if (n > 0) {
            text += QString(" (%1/%2)")
                        .arg(n)
                        .arg(vpn_client_->MaxReconnectAttempts());
          }
          reconnecting_label_action_->setText(text);
          reconnecting_label_action_->setVisible(true);
        }
        if (disconnect_action_) {
          disconnect_action_->setVisible(false);
        }
      } else {
        // Re-arm the check: the tunnel is healthy again, so the next
        // unexpected close has to be reported too.
        reconnection_in_progress = false;
        if (reconnecting_label_action_) {
          reconnecting_label_action_->setVisible(false);
        }
        if (disconnect_action_) {
          disconnect_action_->setVisible(true);
        }
        if (speed_widget_) {
          speed_widget_->UpdateSpeed(
              vpn_client_->GetReceiveRate(), vpn_client_->GetSendRate());
        }
      }
    }
  }

  if (is_disconnected) {
    // show error
    ShowError(QObject::tr("FPTN Connection Error"),
        QObject::tr("The VPN connection was unexpectedly closed."));
    SPDLOG_INFO("FPTN Connection Error");
    emit disconnecting();
  }
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
QString TrayApp::GetSystemLanguageCode() const {
  const QLocale locale;
  const QString locale_name = locale.name();
  if (locale_name.contains('_')) {
    const QString language_code = locale.name().split('_').first();
    return language_code;
  }
  return "en";
}

void TrayApp::RetranslateUi() {
  if (connect_menu_) {
    connect_menu_->setTitle(QObject::tr("Connect") + "    ");
  }
  if (settings_action_) {
    settings_action_->setText(QObject::tr("Settings"));
  }
  if (quit_action_) {
    quit_action_->setText(QObject::tr("Quit"));
  }
  if (connecting_label_action_) {
    connecting_label_action_->setText(QObject::tr("Connecting..."));
  }
  if (empty_configuration_action_) {
    empty_configuration_action_->setText(QObject::tr("No servers"));
  }
  if (smart_connect_action_) {
    smart_connect_action_->setText(QObject::tr("Smart Connect"));
  }
  if (limited_zone_connect_menu_) {
    limited_zone_connect_menu_->setTitle(
        QObject::tr("Limited access servers") + "  ");
  }
  if (connecting_label_action_) {
    connecting_label_action_->setText(QObject::tr("Connecting..."));
  }
  if (disconnecting_label_action_) {
    disconnecting_label_action_->setText(QObject::tr("Disconnecting..."));
  }
  if (reconnecting_label_action_) {
    reconnecting_label_action_->setText(QObject::tr("Reconnecting..."));
  }

  if (disconnect_action_) {
    const QString disconnect_text =
        QString(QObject::tr("Disconnect") + ": %1")
            .arg(QString::fromStdString(selected_server_.name));
    disconnect_action_->setText(disconnect_text);
  }
  if (auto_update_action_) {
    auto_update_action_->setText(
        QObject::tr("New version available") + " " + auto_available_version_);
  }
}

void TrayApp::stop() {
  SPDLOG_INFO("Stopping TrayApp");
  settings_->StopPingMonitoring();
  stopVpn();
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
void TrayApp::OpenWebBrowser(const std::string& url) {
#if __APPLE__
  QDesktopServices::openUrl(QString::fromStdString(url));
#elif __linux__
  const std::string command = fmt::format(
      R"(sh -c "xhost +SI:localuser:root && (xdg-open \"{0}\" || sensible-browser \"{0}\" || x-www-browser \"{0}\" || gnome-open \"{0}\" ) "  )",
      url);
  fptn::common::system::command::run(command);
#elif _WIN32
  const std::string command = fmt::format(R"(explorer "{}" )", url);
  fptn::common::system::command::run(command);
#endif
}

bool TrayApp::startVpn(QString& err_msg) {
  SPDLOG_DEBUG("Handling connecting state");

  const fptn::common::network::IPv4Address tun_interface_address_ipv4(
      FPTN_CLIENT_DEFAULT_ADDRESS_IP4);
  const fptn::common::network::IPv6Address tun_interface_address_ipv6(
      FPTN_CLIENT_DEFAULT_ADDRESS_IP6);
  const std::string tun_interface_name = "tun0";

  /* check gateway address */
  const auto gateway_ip =
      (settings_->GatewayIp() == "auto"
              ? fptn::routing::GetDefaultGatewayIPAddress(tun_interface_name)
              : fptn::common::network::IPv4Address(
                    settings_->GatewayIp().toStdString()));

  const auto gateway_ipv6 =
      fptn::routing::GetDefaultGatewayIPv6Address(tun_interface_name);

  if (gateway_ip.IsEmpty()) {
    err_msg = QObject::tr(
        "Unable to find the default gateway IP address. "
        "Please check your connection and make sure no other VPN "
        "is active. "
        "If the error persists, specify the gateway address in the "
        "FPTN settings using your router's IP address, "
        "and ensure that an active internet interface (adapter) is "
        "selected. If the issue remains unresolved, "
        "please contact the developer via Telegram @fptn_chat.");
    return false;
  }

  /* config */
  const std::string network_interface =
      (settings_->UsingNetworkInterface() == "auto"
              ? ""
              : settings_->UsingNetworkInterface().toStdString());

  const std::string sni = !settings_->SNI().isEmpty()
                              ? settings_->SNI().toStdString()
                              : FPTN_DEFAULT_SNI;
  fptn::protocol::https::CensorshipStrategy censorship_strategy =
      fptn::protocol::https::CensorshipStrategy::kSni;

  using fptn::protocol::https::CensorshipStrategy;
  const auto& bypass_method = settings_->BypassMethod();
  if (bypass_method == SettingsModel::kBypassMethodSni) {
    SPDLOG_INFO("Using default spoofing to bypass censorship");
    censorship_strategy = CensorshipStrategy::kSni;
  } else if (bypass_method == SettingsModel::kBypassMethodObfuscation) {
    SPDLOG_INFO("Using obfuscation to bypass censorship");
    censorship_strategy = CensorshipStrategy::kTlsObfuscator;
  } else if (bypass_method == SettingsModel::kBypassMethodSniReality) {
    // DEPRECATED
    SPDLOG_INFO("Using generic reality mode to bypass censorship");
    censorship_strategy = CensorshipStrategy::kSniRealityMode;
  }
  /* chrome */
  else if (bypass_method == SettingsModel::kBypassMethodSniRealityChrome149) {
    censorship_strategy = CensorshipStrategy::kSniRealityModeChrome149;
  } else if (bypass_method == SettingsModel::kBypassMethodSniRealityChrome148) {
    censorship_strategy = CensorshipStrategy::kSniRealityModeChrome148;
  } else if (bypass_method == SettingsModel::kBypassMethodSniRealityChrome147) {
    censorship_strategy = CensorshipStrategy::kSniRealityModeChrome147;
  } else if (bypass_method == SettingsModel::kBypassMethodSniRealityChrome146) {
    censorship_strategy = CensorshipStrategy::kSniRealityModeChrome146;
  } else if (bypass_method == SettingsModel::kBypassMethodSniRealityChrome145) {
    censorship_strategy = CensorshipStrategy::kSniRealityModeChrome145;
  }
  /* firefox */
  else if (bypass_method == SettingsModel::kBypassMethodSniRealityFirefox151) {
    censorship_strategy = CensorshipStrategy::kSniRealityModeFirefox151;
  } else if (bypass_method ==
             SettingsModel::kBypassMethodSniRealityFirefox150) {
    censorship_strategy = CensorshipStrategy::kSniRealityModeFirefox150;
  } else if (bypass_method ==
             SettingsModel::kBypassMethodSniRealityFirefox149) {
    censorship_strategy = CensorshipStrategy::kSniRealityModeFirefox149;
  }
  /* Yandex */
  else if (bypass_method == SettingsModel::kBypassMethodSniRealityYandex26_4) {
    censorship_strategy = CensorshipStrategy::kSniRealityModeYandex26_4;
  } else if (bypass_method ==
             SettingsModel::kBypassMethodSniRealityYandex26_3) {
    censorship_strategy = CensorshipStrategy::kSniRealityModeYandex26_3;
  } else if (bypass_method == SettingsModel::kBypassMethodSniRealityYandex25) {
    censorship_strategy = CensorshipStrategy::kSniRealityModeYandex25;
  } else if (bypass_method == SettingsModel::kBypassMethodSniRealityYandex24) {
    censorship_strategy = CensorshipStrategy::kSniRealityModeYandex24;
  }
  /* Safari */
  else if (bypass_method == SettingsModel::kBypassMethodSniRealitySafari26_5) {
    censorship_strategy = CensorshipStrategy::kSniRealityModeSafari26_5;
  } else if (bypass_method ==
             SettingsModel::kBypassMethodSniRealitySafari26_4) {
    censorship_strategy = CensorshipStrategy::kSniRealityModeSafari26_4;
  }

  if (cancel_connecting_) {
    return false;
  }

  fptn::config::ConfigFile config(sni, censorship_strategy);  // SET SNI
  if (smart_connect_) {  // find the best server
    for (const auto& service : settings_->Services()) {
      for (const auto& s : service.servers) {
        fptn::utils::speed_estimator::ServerInfo cfg_server;
        {
          cfg_server.name = s.name.toStdString();
          cfg_server.host = s.host.toStdString();
          cfg_server.port = s.port;
          cfg_server.is_using = s.is_using;
          cfg_server.service_name = service.service_name.toStdString();
          cfg_server.username = service.username.toStdString();
          cfg_server.password = service.password.toStdString();
          cfg_server.md5_fingerprint = s.md5_fingerprint.toStdString();
        }
        config.AddServer(cfg_server);
      }
    }
    const auto login_result = config.FindServerByLogin(10);
    if (!login_result) {
      err_msg = QObject::tr("All servers unavailable!");
      return false;
    }
    selected_server_ = login_result->server;
    pre_obtained_token_ = login_result->access_token;
  }

  const auto server_ip = fptn::routing::ResolveDomain(selected_server_.host);
  if (server_ip == fptn::common::network::IPv4Address()) {
    err_msg = QObject::tr(
        "The server is unavailable. Please select another server "
        "or use Auto-connect to find the best available server.");
    return false;
  }

  if (cancel_connecting_) {
    return false;
  }

  using fptn::protocol::connection::strategies::ConnectionStrategy;
  const auto strategy_name = settings_->ConnectionStrategy();
  auto connection_strategy = ConnectionStrategy::kSingleRollingTunnel;
  if (strategy_name == SettingsModel::kConnectionStrategyBrowserMimicry) {
    connection_strategy = ConnectionStrategy::kBrowserMimicry;
  } else if (strategy_name == SettingsModel::kConnectionStrategyDual) {
    connection_strategy = ConnectionStrategy::kDualRollingTunnel;
  } else if (strategy_name == SettingsModel::kConnectionStrategyTriple) {
    connection_strategy = ConnectionStrategy::kTripleRollingTunnel;
  }

  auto http_client = std::make_unique<fptn::vpn::http::Client>(
      fptn::protocol::https::ConnectionConfig{
          .common ={
                  .server_ip = server_ip,
                  .server_port =
                      static_cast<std::uint16_t>(selected_server_.port),
                  .sni = sni,
                  .md5_fingerprint = selected_server_.md5_fingerprint,
                  .client_version = FPTN_VERSION,
                  .censorship_strategy = censorship_strategy,
                  .tun_interface_address_ipv4 = common::network::IPv4Address(
                      FPTN_CLIENT_DEFAULT_ADDRESS_IP4),
                  .tun_interface_address_ipv6 = common::network::IPv6Address(
                      FPTN_CLIENT_DEFAULT_ADDRESS_IP6),
              }},
      connection_strategy);

  if (!pre_obtained_token_.empty()) {
    http_client->SetAccessToken(pre_obtained_token_);
    pre_obtained_token_.clear();
  }

  // login (no-op if token already set via SetAccessToken)
  bool login_status =
      http_client->Login(selected_server_.username, selected_server_.password);
  if (!login_status) {
    const std::string error = http_client->LatestError();
    QString reason;
    switch (http_client->LatestErrorCode()) {
      case 503:
        reason = QObject::tr(
            "The authorization server is temporarily unavailable. Please try "
            "again later.");
        break;
      case 608:
        reason = QObject::tr(
            "The server did not respond in time (operation timeout). Please "
            "try again.");
        break;
      default:
        reason = QObject::tr(
            "Unable to connect to the server. Please use the Telegram "
            "bot to generate a new TOKEN with your personal settings, "
            "then try again.");
        break;
    }
    err_msg = reason + "\n\n" + QObject::tr("Error message: ") +
              QString::fromStdString(error);
    return false;
  }

  if (cancel_connecting_) {
    return false;
  }

  // get dns
  const auto [dns_server_ipv4, dns_server_ipv6] = http_client->GetDns();
  if (dns_server_ipv4.IsEmpty() || dns_server_ipv6.IsEmpty()) {
    const std::string error = http_client->LatestError();
    err_msg = QObject::tr("DNS server error! Check your connection!") + "\n\n" +
              QObject::tr("Error message: ") + QString::fromStdString(error);
    return false;
  }

  if (cancel_connecting_) {
    return false;
  }

  const auto blacklist_domains = settings_->BlacklistDomains();
  const auto exclude_networks = settings_->ExcludeTunnelNetworks();
  const auto include_networks = settings_->IncludeTunnelNetworks();
  const bool enable_split_tunnel = settings_->EnableSplitTunnel();
  const QString split_tunnel_mode = settings_->SplitTunnelMode();
  const auto split_tunnel_domains = settings_->SplitTunnelDomains();

  /* route manager */
  std::vector<std::string> exclude_networks_std;
  if (!exclude_networks.empty()) {
    for (const auto& network : exclude_networks) {
      exclude_networks_std.push_back(network.toStdString());
    }
  }
  std::vector<std::string> include_networks_std;
  if (!include_networks.empty()) {
    for (const auto& network : include_networks) {
      include_networks_std.push_back(network.toStdString());
    }
  }
  auto route_manager = std::make_shared<fptn::routing::RouteManager>(
      fptn::routing::RouteManager::Config{
          .out_interface_name = network_interface,
          .tun_interface_address_ipv4 =
              common::network::IPv4Address(FPTN_CLIENT_DEFAULT_ADDRESS_IP4),
          .tun_interface_address_ipv6 =
              common::network::IPv6Address(FPTN_CLIENT_DEFAULT_ADDRESS_IP6),
          .vpn_server_ip = server_ip,
          .dns_server_ipv4 = dns_server_ipv4,
          .dns_server_ipv6 = dns_server_ipv6,
          .custom_dns_ipv4 = common::network::IPv4Address(
              settings_->CustomDns().toStdString()),
          .gateway_ipv4 = gateway_ip,
          .gateway_ipv6 = gateway_ipv6,
          .exclude_networks = exclude_networks_std,
          .include_networks = include_networks_std
#if _WIN32
          ,
          .enable_advanced_dns_management =
              settings_->EnableAdvancedDnsManagement()
#endif
      });

  if (cancel_connecting_) {
    return false;
  }

  /* plugins */
  std::vector<fptn::plugin::BasePluginPtr> client_plugins;
  if (settings_->EnableAdBlock()) {
    client_plugins.push_back(std::make_unique<fptn::plugin::AdBlock>());
  }
  if (selected_server_.censored_zone) {
    SPDLOG_INFO("Limited access server: domain rules are not applied");
  } else {
    if (!blacklist_domains.empty()) {
      std::vector<std::string> blacklist_domains_std;
      for (const auto& domain : blacklist_domains) {
        blacklist_domains_std.push_back(domain.toStdString());
      }
      auto blacklist_plugin = std::make_unique<fptn::plugin::DomainBlacklist>(
          blacklist_domains_std, route_manager);
      client_plugins.push_back(std::move(blacklist_plugin));
    }
    if (enable_split_tunnel) {
      std::vector<std::string> split_domains_std;
      for (const auto& domain : split_tunnel_domains) {
        split_domains_std.push_back(domain.toStdString());
      }

      const auto policy = (split_tunnel_mode == "exclude")
                              ? fptn::routing::RoutingPolicy::kExcludeFromVpn
                              : fptn::routing::RoutingPolicy::kIncludeInVpn;

      auto split_tunnel_plugin = std::make_unique<fptn::plugin::Tunneling>(
          split_domains_std, route_manager, policy);
      client_plugins.push_back(std::move(split_tunnel_plugin));
    }
  }

  if (cancel_connecting_) {
    return false;
  }

  // setup tun interface
  auto virtual_network_interface =
      std::make_shared<fptn::common::network::TunInterface>(
          common::network::TunInterface::Config{.name = tun_interface_name,
              .mtu_size = FPTN_DEFAULT_MTU_SIZE,
              .using_rate_calculator = true,
              .ipv4_addr =
                  common::network::IPv4Address(FPTN_CLIENT_DEFAULT_ADDRESS_IP4),
              .ipv4_netmask = 32,
              .ipv6_addr =
                  common::network::IPv6Address(FPTN_CLIENT_DEFAULT_ADDRESS_IP6),
              .ipv6_netmask = 126});

  // setup vpn client
  auto vpn_client = std::make_shared<fptn::vpn::VpnManager>(
      fptn::vpn::VpnManager::Config{.http_client = std::move(http_client),
          .route_manager = route_manager,
          .virtual_net_interface = virtual_network_interface,
          .plugins = std::move(client_plugins)});
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    vpn_client_ = vpn_client;
  }

  if (cancel_connecting_) {
    return false;
  }

  // Wait for the WebSocket tunnel to establish
  vpn_client->Start();

  if (cancel_connecting_) {
    return false;
  }

  constexpr auto kTimeout = std::chrono::seconds(10);
  const auto start = std::chrono::steady_clock::now();
  while (!vpn_client->IsStarted()) {
    if (std::chrono::steady_clock::now() - start > kTimeout) {
      err_msg = QObject::tr("Failed to connect to the server!");
      return false;
    }
    std::this_thread::sleep_for(std::chrono::microseconds(300));
  }

  return !cancel_connecting_;
}

bool TrayApp::stopVpn() {
  SPDLOG_INFO("Stopping vpn");

  fptn::vpn::VpnClientPtr vpn_client;
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    vpn_client = std::move(vpn_client_);
  }
  if (vpn_client) {
    vpn_client->Stop();
  }
  return true;
}

void TrayApp::handleVpnStarted(bool success, const QString& err_msg) {
  cancel_connecting_ = false;
  if (success) {
    emit connected();
  } else {
    ShowError(QObject::tr("FPTN Connection Error"), err_msg);
    emit disconnecting();

    settings_->StartPingMonitoring();
  }
}

void TrayApp::UpdatePings() {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (connection_state_ == ConnectionState::Connected ||
      connection_state_ == ConnectionState::Connecting ||
      connection_state_ == ConnectionState::Disconnecting) {
    return;
  }

  for (auto* action : connect_menu_->actions()) {
    if (auto* server_action = qobject_cast<ServerMenuItemWidget*>(action)) {
      for (const auto& service : settings_->Services()) {
        for (const auto& server : service.servers) {
          if (server.name == server_action->ServerName()) {
            server_action->UpdatePing(server.ping_ms);
            break;
          }
        }
      }
    }
  }
}
