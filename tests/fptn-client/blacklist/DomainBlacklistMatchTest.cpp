/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <string>

#include <gtest/gtest.h>  // NOLINT(build/include_order)
#include <re2/re2.h>      // NOLINT(build/include_order)

#include "utils/utils.h"

namespace {

bool SniBlocked(const std::string& rule, const std::string& sni) {
  RE2::Options options;
  options.set_case_sensitive(false);
  options.set_log_errors(false);
  const RE2 re(fptn::utils::DomainToRegex(rule), options);
  return re.ok() && RE2::PartialMatch(sni, re);
}

}  // namespace

// cppcheck-suppress syntaxError
TEST(DomainBlacklistMatchTest, BlocksSubdomainViaParentRule) {
  EXPECT_TRUE(SniBlocked("vk.com", "vk.com"));
  EXPECT_TRUE(SniBlocked("vk.com", "m.vk.com"));
  EXPECT_TRUE(SniBlocked("vk.com", "api.m.vk.com"));
  EXPECT_FALSE(SniBlocked("vk.com", "notvk.com"));
  EXPECT_FALSE(SniBlocked("vk.com", "vk.com.evil.net"));
}

TEST(DomainBlacklistMatchTest, MatchesSniCaseInsensitively) {
  EXPECT_TRUE(SniBlocked("vk.com", "M.VK.COM"));
}
