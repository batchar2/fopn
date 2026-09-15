/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/user/common_user_manager.h"

namespace {

using fptn::common::user::CommonUserManager;

std::filesystem::path TempUserFile(const std::string& name) {
  auto path = std::filesystem::temp_directory_path() /
              ("fptn-users-" + name + ".list");
  std::filesystem::remove(path);
  return path;
}

}  // namespace

// cppcheck-suppress syntaxError
TEST(CommonUserManagerTest, BandwidthBitIsMegabytesTimesTwoToTheTwenty) {
  const auto path = TempUserFile("scale");
  CommonUserManager manager(path.string());
  ASSERT_TRUE(manager.AddUser("u1", "p", 1));
  ASSERT_TRUE(manager.AddUser("u100", "p", 100));

  EXPECT_EQ(manager.GetUserBandwidthBit("u1"), 1048576);
  EXPECT_EQ(manager.GetUserBandwidthBit("u100"), 104857600);
  std::filesystem::remove(path);
}

// The regression: an int multiplication turned 10000 into 1'895'825'408,
// silently giving the user a fifth of the configured limit.
TEST(CommonUserManagerTest, BandwidthBitDoesNotOverflowInThirtyTwoBits) {
  const auto path = TempUserFile("overflow");
  CommonUserManager manager(path.string());
  ASSERT_TRUE(manager.AddUser("big", "p", 10000));

  EXPECT_EQ(manager.GetUserBandwidthBit("big"), 10485760000LL);
  EXPECT_NE(manager.GetUserBandwidthBit("big"), 1895825408LL);
  std::filesystem::remove(path);
}

TEST(CommonUserManagerTest, BandwidthBitIsZeroForUnknownUser) {
  const auto path = TempUserFile("unknown");
  CommonUserManager manager(path.string());

  EXPECT_EQ(manager.GetUserBandwidthBit("nobody"), 0);
  std::filesystem::remove(path);
}

TEST(CommonUserManagerTest, AddUserRejectsNegativeBandwidth) {
  const auto path = TempUserFile("negative");
  CommonUserManager manager(path.string());

  EXPECT_FALSE(manager.AddUser("u", "p", -1));
  std::filesystem::remove(path);
}

TEST(CommonUserManagerTest, AddUserRejectsDuplicate) {
  const auto path = TempUserFile("duplicate");
  CommonUserManager manager(path.string());
  ASSERT_TRUE(manager.AddUser("u", "p", 100));

  EXPECT_FALSE(manager.AddUser("u", "other", 200));
  EXPECT_EQ(manager.GetUserBandwidth("u"), 100);
  std::filesystem::remove(path);
}

TEST(CommonUserManagerTest, UsersSurviveReload) {
  const auto path = TempUserFile("reload");
  {
    CommonUserManager manager(path.string());
    ASSERT_TRUE(manager.AddUser("u", "secret", 4096));
  }

  CommonUserManager reopened(path.string());
  EXPECT_TRUE(reopened.Authenticate("u", "secret"));
  EXPECT_EQ(reopened.GetUserBandwidthBit("u"), 4096LL * 1024 * 1024);
  std::filesystem::remove(path);
}

TEST(CommonUserManagerTest, AuthenticateRejectsWrongPassword) {
  const auto path = TempUserFile("auth");
  CommonUserManager manager(path.string());
  ASSERT_TRUE(manager.AddUser("u", "right", 100));

  EXPECT_TRUE(manager.Authenticate("u", "right"));
  EXPECT_FALSE(manager.Authenticate("u", "wrong"));
  EXPECT_FALSE(manager.Authenticate("nobody", "right"));
  std::filesystem::remove(path);
}

TEST(CommonUserManagerTest, MalformedLinesAreSkipped) {
  const auto path = TempUserFile("malformed");
  {
    std::ofstream out(path);
    out << "good hash 100\n";
    out << "broken-line-without-fields\n";
    out << "\n";
    out << "also_good hash2 200\n";
  }

  CommonUserManager manager(path.string());
  EXPECT_EQ(manager.GetUserBandwidth("good"), 100);
  EXPECT_EQ(manager.GetUserBandwidth("also_good"), 200);
  EXPECT_EQ(manager.GetUserBandwidth("broken-line-without-fields"), 0);
  std::filesystem::remove(path);
}
