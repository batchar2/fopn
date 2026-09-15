/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <cstdio>
#include <fstream>
#include <string>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "status/state_store.h"

namespace {

using fptn::client::status::LoadState;
using fptn::client::status::PersistedState;
using fptn::client::status::SaveState;

// Each case writes into its own file: the tests run in one process and a
// leftover from a neighbour would make a failure look like a pass.
class StateFile {
 public:
  explicit StateFile(const std::string& name)
      : path_("/tmp/fptn-state-test-" + name + ".json") {
    std::remove(path_.c_str());
  }
  ~StateFile() {
    std::remove(path_.c_str());
    std::remove((path_ + ".tmp").c_str());
  }

  StateFile(const StateFile&) = delete;
  StateFile& operator=(const StateFile&) = delete;

  [[nodiscard]] const std::string& Path() const { return path_; }

  void Write(const std::string& content) const {
    std::ofstream file(path_, std::ios::trunc);
    file << content;
  }

 private:
  const std::string path_;
};

TEST(StateStoreTest, RoundTripKeepsSelectedAndLatency) {
  const StateFile file("roundtrip");
  PersistedState written;
  written.selected = "1.2.3.4:443";
  written.latency["1.2.3.4:443"] = 214;
  written.latency["5.6.7.8:443"] = 0;  // did not answer last time

  ASSERT_TRUE(SaveState(file.Path(), written));

  PersistedState read;
  ASSERT_TRUE(LoadState(file.Path(), &read));
  EXPECT_EQ(read.selected, "1.2.3.4:443");
  ASSERT_EQ(read.latency.size(), 2U);
  EXPECT_EQ(read.latency.at("1.2.3.4:443"), 214U);
  EXPECT_EQ(read.latency.at("5.6.7.8:443"), 0U);
}

TEST(StateStoreTest, MissingFileIsNotAnError) {
  PersistedState read;
  EXPECT_FALSE(LoadState("/tmp/fptn-state-test-does-not-exist.json", &read));
  EXPECT_TRUE(read.selected.empty());
}

TEST(StateStoreTest, MalformedFileIsRefusedRatherThanGuessed) {
  const StateFile file("malformed");
  file.Write("{this is not json");

  PersistedState read;
  EXPECT_FALSE(LoadState(file.Path(), &read));
}

// A file from a newer client is not read on a guess: the next start races the
// pool, which is slower but always correct.
TEST(StateStoreTest, FutureVersionIsIgnored) {
  const StateFile file("future");
  file.Write(R"({"version":99,"selected":"1.2.3.4:443","latency":{}})");

  PersistedState read;
  EXPECT_FALSE(LoadState(file.Path(), &read));
}

// Latency values of the wrong type are dropped one by one rather than making
// the whole file unusable.
TEST(StateStoreTest, NonNumericLatencyEntriesAreSkipped) {
  const StateFile file("types");
  file.Write(
      R"({"version":1,"selected":"a:443",)"
      R"("latency":{"a:443":100,"b:443":"fast","c:443":null}})");

  PersistedState read;
  ASSERT_TRUE(LoadState(file.Path(), &read));
  EXPECT_EQ(read.selected, "a:443");
  ASSERT_EQ(read.latency.size(), 1U);
  EXPECT_EQ(read.latency.at("a:443"), 100U);
}

TEST(StateStoreTest, SavingTwiceReplacesTheEarlierState) {
  const StateFile file("replace");
  PersistedState first;
  first.selected = "old:443";
  first.latency["old:443"] = 500;
  ASSERT_TRUE(SaveState(file.Path(), first));

  PersistedState second;
  second.selected = "new:443";
  second.latency["new:443"] = 120;
  ASSERT_TRUE(SaveState(file.Path(), second));

  PersistedState read;
  ASSERT_TRUE(LoadState(file.Path(), &read));
  EXPECT_EQ(read.selected, "new:443");
  ASSERT_EQ(read.latency.size(), 1U);
  EXPECT_EQ(read.latency.at("new:443"), 120U);
}

// The temporary file the atomic write goes through must not be left behind:
// on a router /tmp is RAM, and a stale copy per restart adds up.
TEST(StateStoreTest, NoTemporaryFileIsLeftBehind) {
  const StateFile file("tmpfile");
  PersistedState written;
  written.selected = "1.2.3.4:443";
  ASSERT_TRUE(SaveState(file.Path(), written));

  const std::ifstream leftover(file.Path() + ".tmp");
  EXPECT_FALSE(leftover.good());
}

TEST(StateStoreTest, EmptyPathIsRefusedByBothDirections) {
  PersistedState state;
  state.selected = "1.2.3.4:443";
  EXPECT_FALSE(SaveState("", state));

  PersistedState read;
  EXPECT_FALSE(LoadState("", &read));
}

}  // namespace
