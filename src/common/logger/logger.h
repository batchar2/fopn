/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <clocale>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#ifdef __ANDROID__
#include <spdlog/sinks/android_sink.h>  // NOLINT(build/include_order)
#elif __APPLE__
#include <TargetConditionals.h>  // NOLINT(build/include_order)
#include <pwd.h>                 // NOLINT(build/include_order)
#include <unistd.h>              // NOLINT(build/include_order)
#elif __linux__
#include <pwd.h>     // NOLINT(build/include_order)
#include <unistd.h>  // NOLINT(build/include_order)
#elif _WIN32
#include <windows.h>
#endif

#include <spdlog/async.h>                     // NOLINT(build/include_order)
#include <spdlog/pattern_formatter.h>         // NOLINT(build/include_order)
#include <spdlog/sinks/rotating_file_sink.h>  // NOLINT(build/include_order)
#include <spdlog/sinks/stdout_color_sinks.h>  // NOLINT(build/include_order)
#include <spdlog/spdlog.h>                    // NOLINT(build/include_order)

namespace fptn::logger {

constexpr char kLogPattern[] = "[%Y-%m-%d %H:%M:%S] [%^%l%$] [%s:%#] %v";

inline std::string MaskIPv4Addresses(const std::string& text) {
  const auto is_digit = [](char c) { return c >= '0' && c <= '9'; };

  std::string result;
  result.reserve(text.size());

  std::size_t i = 0;
  while (i < text.size()) {
    std::size_t pos = i;
    std::size_t last_octet = i;
    int octets = 0;

    while (octets < 4 && pos < text.size() && is_digit(text[pos])) {
      last_octet = pos;
      std::size_t digits = 0;
      while (pos < text.size() && is_digit(text[pos]) && digits < 3) {
        ++pos;
        ++digits;
      }
      ++octets;
      if (octets < 4) {
        if (pos < text.size() && text[pos] == '.') {
          ++pos;
        } else {
          break;
        }
      }
    }

    if (octets == 4) {
      result += "***.***.***.";
      result.append(text, last_octet, pos - last_octet);
      i = pos;
    } else {
      result += text[i];
      ++i;
    }
  }
  return result;
}

class MaskingFormatter : public spdlog::formatter {
 public:
  MaskingFormatter()
      : inner_(std::make_unique<spdlog::pattern_formatter>(kLogPattern)) {}

  void format(const spdlog::details::log_msg& msg,
      spdlog::memory_buf_t& dest) override {
    spdlog::memory_buf_t buffer;
    inner_->format(msg, buffer);

    const std::string masked =
        MaskIPv4Addresses(std::string(buffer.data(), buffer.size()));
    dest.append(masked.data(), masked.data() + masked.size());
  }

  std::unique_ptr<spdlog::formatter> clone() const override {
    return std::make_unique<MaskingFormatter>();
  }

 private:
  std::unique_ptr<spdlog::pattern_formatter> inner_;
};

inline bool init(const std::string& app_name) {
  // Set locale
#ifdef _WIN32
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);
  std::ios::sync_with_stdio(false);
  std::wcout.imbue(std::locale(".UTF-8"));
#endif
  std::locale::global(std::locale::classic());
  setlocale(LC_ALL, "en_US.UTF-8");
  try {
#ifdef __ANDROID__
    auto logger = spdlog::android_logger_mt("android", app_name);
#elif TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR
    // iOS specific logging - use console only since filesystem access is
    // restricted
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto logger = std::make_shared<spdlog::logger>(app_name, console_sink);
    logger->flush_on(spdlog::level::debug);
    spdlog::flush_every(std::chrono::seconds(3));
#else

#ifdef __linux__
    const std::filesystem::path log_dir = "/var/log/fptn/";
#elif defined(__APPLE__) && TARGET_OS_MAC
    const std::filesystem::path log_dir = []() {
      if (const char* home = getenv("HOME")) {
        return std::filesystem::path(home) / "Library/Logs/fptn";
      }
      struct passwd pwd = {};
      struct passwd* result = nullptr;
      char buffer[1024] = {};
      if (getpwuid_r(getuid(), &pwd, buffer, sizeof(buffer), &result) != 0 ||
          !result) {
        throw std::runtime_error("Failed to get user home directory");
      }
      return std::filesystem::path(pwd.pw_dir) / "Library/Logs/fptn";
    }();
#elif _WIN32
    const std::filesystem::path log_dir = "./logs/";
#endif
    const std::filesystem::path log_file = log_dir / (app_name + ".log");
    if (!std::filesystem::exists(log_dir)) {
      try {
        std::filesystem::create_directories(log_dir);
      } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Failed to create log directory: " << e.what() << "\n";
        return false;
      }
    }
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
#ifdef FPTN_OPENWRT
    // На роутере /var/log - симлинк на tmpfs, то есть лог живёт в оперативной
    // памяти, а её там 512 МБ на всё. Дефолтные 12 МБ на файл при трёх файлах
    // съедали бы 36 МБ ОЗУ: держим 2 МБ на два файла.
    constexpr std::size_t kLogFileSize = 1024 * 1024;
    constexpr std::size_t kLogFiles = 2;
#else
    constexpr std::size_t kLogFileSize = 12 * 1024 * 1024;
    constexpr std::size_t kLogFiles = 3;
#endif
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        log_file.string(), kLogFileSize, kLogFiles, true);
#ifdef FPTN_OPENWRT
    constexpr std::size_t kLogQueueSize = 4096;
#else
    constexpr std::size_t kLogQueueSize = 32768;
#endif
    spdlog::init_thread_pool(kLogQueueSize, 1);
    auto logger = std::make_shared<spdlog::async_logger>(app_name,
        spdlog::sinks_init_list{console_sink, file_sink}, spdlog::thread_pool(),
        spdlog::async_overflow_policy::overrun_oldest);
    spdlog::flush_every(std::chrono::seconds(3));
#endif

    spdlog::set_default_logger(logger);
    spdlog::set_level(spdlog::level::info);
    spdlog::set_formatter(std::make_unique<MaskingFormatter>());

#if TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR
    SPDLOG_INFO("Logger initialized for iOS - console output only");
#elif __ANDROID__
    SPDLOG_INFO("Logger inited");
#else
    SPDLOG_INFO("Logging to file: {}", log_file.string());
    SPDLOG_INFO("FPTN version: {}", FPTN_VERSION);
#endif
    return true;
  } catch (const spdlog::spdlog_ex& ex) {
#ifdef __ANDROID__
    __android_log_print(ANDROID_LOG_ERROR, "FPTN",
        "Logger initialization failed: %s", ex.what());
#else
    std::cerr << "Logger initialization failed: " << ex.what() << "\n";
#endif
  } catch (...) {
    std::cerr << "Unhandled exception caught in logger\n";
  }
  return false;
}
}  // namespace fptn::logger
