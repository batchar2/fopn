/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace fptn::client::status {

// What a run leaves behind for the next one: the server that was in use and
// how the pool measured. Without it every start races the whole pool from
// scratch - on a public pool of forty servers that means forty logins to
// learn what the previous run already knew, and a restart costs seconds it
// does not have to. sing-box keeps the same thing in its cache file under
// `store_selected`.
//
// A latency of zero means the server did not answer when it was last tried.
// It is kept rather than dropped: knowing a node is dead is worth as much as
// knowing one is fast, and it keeps the next start from leading with it.
struct PersistedState {
  std::string selected;  // ServerRegistry::KeyOf of the server in use
  std::unordered_map<std::string, std::uint32_t> latency;  // key -> ms
};

// Reads the file written by SaveState. Returns false when there is nothing
// usable - no file, unreadable, malformed, or written by a newer format. None
// of that is worth failing a start over: it only means racing as before.
bool LoadState(const std::string& path, PersistedState* out);

// Writes atomically through a temporary file, so a start that reads the file
// while it is being written sees either the old state or the new one, never a
// half of each. Returns false when the file could not be written.
bool SaveState(const std::string& path, const PersistedState& state);

}  // namespace fptn::client::status
