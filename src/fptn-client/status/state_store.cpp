/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-client/status/state_store.h"

#include <cstdio>
#include <fstream>
#include <string>

#include <nlohmann/json.hpp>  // NOLINT(build/include_order)
#include <spdlog/spdlog.h>    // NOLINT(build/include_order)

namespace fptn::client::status {

namespace {
// Bumped only when the shape changes in a way an older client cannot read.
// A file from the future is ignored rather than guessed at.
constexpr int kStateVersion = 1;
}  // namespace

bool LoadState(const std::string& path, PersistedState* out) {
  if (path.empty() || out == nullptr) {
    return false;
  }
  try {
    std::ifstream file(path);
    if (!file.is_open()) {
      return false;
    }
    nlohmann::json doc;
    file >> doc;
    if (!doc.is_object() || doc.value("version", 0) != kStateVersion) {
      return false;
    }
    out->selected = doc.value("selected", std::string());
    out->latency.clear();
    const auto latency = doc.find("latency");
    if (latency != doc.end() && latency->is_object()) {
      for (const auto& [key, value] : latency->items()) {
        if (value.is_number_unsigned()) {
          out->latency[key] = value.get<std::uint32_t>();
        }
      }
    }
    return true;
  } catch (const std::exception& ex) {
    SPDLOG_DEBUG("Could not read the state file {}: {}", path, ex.what());
    return false;
  } catch (...) {  // NOLINT
    return false;
  }
}

bool SaveState(const std::string& path, const PersistedState& state) {
  if (path.empty()) {
    return false;
  }
  const std::string temporary = path + ".tmp";
  try {
    nlohmann::json doc;
    doc["version"] = kStateVersion;
    doc["selected"] = state.selected;
    doc["latency"] = nlohmann::json::object();
    for (const auto& [key, value] : state.latency) {
      doc["latency"][key] = value;
    }
    {
      std::ofstream file(temporary, std::ios::trunc);
      if (!file.is_open()) {
        return false;
      }
      file << doc.dump();
      if (!file.good()) {
        return false;
      }
    }
    if (std::rename(temporary.c_str(), path.c_str()) != 0) {
      std::remove(temporary.c_str());
      return false;
    }
    return true;
  } catch (const std::exception& ex) {
    SPDLOG_DEBUG("Could not write the state file {}: {}", path, ex.what());
    std::remove(temporary.c_str());
    return false;
  } catch (...) {  // NOLINT
    std::remove(temporary.c_str());
    return false;
  }
}

}  // namespace fptn::client::status
