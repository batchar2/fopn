/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>

#include <openssl/evp.h>  // NOLINT(build/include_order)

namespace fptn::common::user {
class CommonUserManager final {
 public:
  explicit CommonUserManager(std::string file_path)
      : file_path_(std::move(file_path)) {
    CreateFileIfNotExists(file_path_);
    LoadUsers();
  }

  bool AddUser(
      const std::string& username, const std::string& password, int bandwidth) {
    const std::scoped_lock lock(mutex_);  // mutex

    if (!ValidateUsername(username)) {
      std::cerr << "Invalid username." << std::endl;
      return false;
    }

    if (bandwidth < 0) {
      std::cerr << "Invalid bandwidth value. It should be a positive number."
                << std::endl;
      return false;
    }

    if (users_.find(username) != users_.end()) {
      std::cout << "User " << username << " already exists." << std::endl;
      return false;
    }
    std::string hash = HashPassword(password);
    users_[username] = {hash, bandwidth};
    SaveUsers();
    std::cout << "User " << username << " added with bandwidth " << bandwidth
              << " MB." << std::endl;
    return true;
  }

  bool DeleteUser(const std::string& username) {
    const std::scoped_lock lock(mutex_);  // mutex

    if (users_.find(username) == users_.end()) {
      return false;
    }
    users_.erase(username);
    SaveUsers();
    return true;
  }

  void ListUsers() const {
    const std::scoped_lock lock(mutex_);  // mutex

    for (const auto& user_entry : users_) {
      const auto& username = user_entry.first;
      const auto& [hash_password, max_speed] = user_entry.second;
      std::cout << username << " " << std::string(hash_password.length(), 'X')
                << " " << max_speed << " MB" << std::endl;
    }
  }

  bool Authenticate(const std::string& username, const std::string& password) {
    const std::scoped_lock lock(mutex_);  // mutex

    ReloadIfChanged();

    auto it = users_.find(username);
    if (it != users_.end()) {
      std::string hash = HashPassword(password);
      return it->second.first == hash;
    }
    return false;
  }

  // Returns bits per second. int overflowed here: a 10000 MB/s limit came to
  // 10,485,760,000, which does not fit in 32 bits, so the value handed out was
  // 1,895,825,408 - over five times lower than configured.
  std::int64_t GetUserBandwidthBit(const std::string& username) const {
    const std::scoped_lock lock(mutex_);  // mutex

    auto it = users_.find(username);
    if (it != users_.end()) {
      return static_cast<std::int64_t>(it->second.second) * 1024 * 1024;
    }
    return 0;
  }
  int GetUserBandwidth(const std::string& username) const {
    const std::scoped_lock lock(mutex_);  // mutex

    auto it = users_.find(username);
    if (it != users_.end()) {
      return it->second.second;
    }
    return 0;
  }

 protected:
  void ReloadIfChanged() {
    try {
      const auto mtime = std::filesystem::last_write_time(file_path_);
      if (mtime != last_write_time_) {
        last_write_time_ = mtime;
        LoadUsers();
      }
    } catch (const std::filesystem::filesystem_error& e) {
      std::cerr << "Failed to check file mtime: " << e.what() << std::endl;
    }
  }

  void LoadUsers() {
    users_.clear();

    std::ifstream file(file_path_);
    if (file.is_open()) {
      std::string line;
      while (std::getline(file, line)) {
        std::string username;
        std::string passwordHash;
        int bandwidth;

        std::istringstream iss(line);
        if (iss >> username >> passwordHash >> bandwidth) {
          users_[username] = {passwordHash, bandwidth};
        } else {
          std::cerr << "Skipping invalid line: " << line << std::endl;
        }
      }
    } else {
      std::cerr << "Unable to open file: " << file_path_ << std::endl;
    }
  }

  void SaveUsers() const {
    std::ofstream file(file_path_);
    if (file.is_open()) {
      for (const auto& user_entry : users_) {
        const auto& username = user_entry.first;
        const auto& [hash_password, max_speed] = user_entry.second;  // NOLINT
        file << username << " " << hash_password << " " << max_speed << "\n";
      }
    } else {
      std::cerr << "Unable to open file: " << file_path_ << std::endl;
    }
  }

  // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
  std::string HashPassword(const std::string& password) const {
    unsigned int length = 0;
    unsigned char hash[EVP_MAX_MD_SIZE] = {0};

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
      std::cerr << "Failed to create EVP_MD_CTX" << std::endl;
      return "";
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr)) {
      std::cerr << "Failed to initialize digest" << std::endl;
      EVP_MD_CTX_free(mdctx);
      return "";
    }

    if (1 != EVP_DigestUpdate(mdctx, password.c_str(), password.size())) {
      std::cerr << "Failed to update digest" << std::endl;
      EVP_MD_CTX_free(mdctx);
      return "";
    }

    if (1 != EVP_DigestFinal_ex(mdctx, hash, &length)) {
      std::cerr << "Failed to finalize digest" << std::endl;
      EVP_MD_CTX_free(mdctx);
      return "";
    }

    EVP_MD_CTX_free(mdctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < length; ++i) {
      oss << std::hex << std::setw(2) << std::setfill('0')
          << static_cast<int>(hash[i]);
    }
    return oss.str();
  }

  // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
  bool ValidateUsername(const std::string& username) const {
    return !username.empty() &&
           std::all_of(username.begin(), username.end(), ::isalnum);
  }

  // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
  void CreateFileIfNotExists(const std::string& file_path) {
    const std::filesystem::path path(file_path);
    const std::filesystem::path directory_path = path.parent_path();
    if (!directory_path.empty() && !std::filesystem::exists(directory_path)) {
      std::error_code ec;
      if (!std::filesystem::create_directories(directory_path, ec)) {
        std::cerr << "Failed to create directories: " << ec.message()
                  << std::endl;
        return;
      }
    }
    if (!std::filesystem::exists(file_path)) {
      std::ofstream file(file_path);
      if (!file.is_open()) {
        std::cerr << "Failed to create file: " << file_path << std::endl;
      }
    }
  }

 private:
  std::unordered_map<std::string, std::pair<std::string, int>> users_;
  mutable std::mutex mutex_;
  std::string file_path_;
  std::filesystem::file_time_type last_write_time_{};
};

using CommonUserManagerPtr = std::unique_ptr<CommonUserManager>;
}  // namespace fptn::common::user
