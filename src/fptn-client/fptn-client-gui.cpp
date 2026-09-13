/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#endif

#include <iostream>
#include <memory>

#include <QApplication>   // NOLINT(build/include_order)
#include <QFontDatabase>  // NOLINT(build/include_order)
#include <QStyleFactory>  // NOLINT(build/include_order)

#include "common/logger/logger.h"

#include "fptn-protocol-lib/time/time_provider.h"

#include "gui/tray/tray.h"
#include "routing/route_manager.h"

#ifdef __APPLE__
#include "utils/macos/admin.h"
#endif

namespace {
#if defined(__linux__) || defined(__APPLE__)
void SignalHandler(int) { QApplication::quit(); }
#elif defined(_WIN32)
BOOL WINAPI SignalHandler(DWORD ctrlType) {
  if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
    qApp->quit();
    return TRUE;
  }
  return FALSE;
}
#else
#error "Unsupported platform"
#endif

}  // namespace

int main(int argc, char* argv[]) {
  try {
#ifdef __linux__
    if (geteuid() != 0) {
      std::cerr << "You must be root to run this program.\n";
      return EXIT_FAILURE;
    }
#elif defined(__APPLE__)
    if (!fptn::utils::macos::RestartApplicationWithAdminRights()) {
      return EXIT_FAILURE;  // Failed to get admin rights
    }
#endif

    // Initialize logger
    if (fptn::logger::init("fptn-client-gui")) {
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

    // Setup signal handler
#if defined(__APPLE__) || defined(__linux__)
    std::signal(SIGINT, SignalHandler);
    std::signal(SIGHUP, SignalHandler);
    std::signal(SIGTERM, SignalHandler);
    std::signal(SIGQUIT, SignalHandler);
#if __linux__
    std::signal(SIGPWR, SignalHandler);
#endif
#elif defined(_WIN32)
    SetConsoleCtrlHandler(SignalHandler, TRUE);
#endif

    // Initialize GUI app
    QApplication::setDesktopSettingsAware(true);
    QApplication::setQuitOnLastWindowClosed(false);
#if __APPLE__
    QCoreApplication::setSetuidAllowed(true);
    QApplication::setAttribute(Qt::AA_MacDontSwapCtrlAndMeta, false);
#elif defined(_WIN32)
    QApplication::setStyle(QStyleFactory::create("windowsvista"));
#endif

    QApplication app(argc, argv);
    QFontDatabase::addApplicationFont(":/fonts/Vazirmatn-Regular.ttf");
    const auto settings =
        std::make_shared<fptn::gui::SettingsModel>(
            QMap<QString, QString>{{"en", "English"}, {"ru", "Русский"}});

    // Start GUI app
    fptn::gui::TrayApp tray(settings);

    // NOLINTNEXTLINE(readability-static-accessed-through-instance)
    const int code = app.exec();

    // Clean resources
    tray.stop();
    spdlog::shutdown();
    return code;
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("An error occurred: {}. Exiting...", ex.what());
  } catch (...) {
    SPDLOG_ERROR("An unknown error occurred. Exiting...");
  }
  return EXIT_FAILURE;
}
