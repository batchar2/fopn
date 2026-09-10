/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <string>
#include <unordered_set>
#include <vector>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "utils/utils.h"

namespace {

using fptn::utils::IsDomainMatched;
using fptn::utils::NormalizeDomainRule;

std::unordered_set<std::string> MakeRules(
    const std::vector<std::string>& rules) {
  std::unordered_set<std::string> out;
  for (const auto& rule : rules) {
    out.insert(NormalizeDomainRule(rule));
  }
  return out;
}

std::unordered_set<std::string> DefaultRules() {
  return MakeRules({"ru", "su", "рф", "xn--p1ai", "vk.com"});
}

}  // namespace

// cppcheck-suppress syntaxError
TEST(SplitTunnelingTest, MatchesTopLevelDomainRule) {
  const auto rules = DefaultRules();

  EXPECT_TRUE(IsDomainMatched(rules, "ru"));
  EXPECT_TRUE(IsDomainMatched(rules, "mail.ru"));
  EXPECT_TRUE(IsDomainMatched(rules, "gosuslugi.ru"));
  EXPECT_TRUE(IsDomainMatched(rules, "api.some.sub.gosuslugi.ru"));
  EXPECT_TRUE(IsDomainMatched(rules, "example.su"));
}

TEST(SplitTunnelingTest, MatchesCyrillicAndPunycodeTld) {
  const auto rules = DefaultRules();

  EXPECT_TRUE(IsDomainMatched(rules, "рф"));
  EXPECT_TRUE(IsDomainMatched(rules, "сайт.рф"));
  EXPECT_TRUE(IsDomainMatched(rules, "почта.сайт.рф"));
  EXPECT_TRUE(IsDomainMatched(rules, "xn--p1ai"));
  EXPECT_TRUE(IsDomainMatched(rules, "xn--80aswg.xn--p1ai"));
}

TEST(SplitTunnelingTest, MatchesDomainAndItsSubdomains) {
  const auto rules = DefaultRules();

  EXPECT_TRUE(IsDomainMatched(rules, "vk.com"));
  EXPECT_TRUE(IsDomainMatched(rules, "sub.vk.com"));
  EXPECT_TRUE(IsDomainMatched(rules, "a.b.c.vk.com"));
}

TEST(SplitTunnelingTest, DoesNotMatchUnrelatedDomains) {
  const auto rules = DefaultRules();

  EXPECT_FALSE(IsDomainMatched(rules, "google.com"));
  EXPECT_FALSE(IsDomainMatched(rules, "vk.com.evil.net"));
  EXPECT_FALSE(IsDomainMatched(rules, "notvk.com"));
  EXPECT_FALSE(IsDomainMatched(rules, "ruse.com"));
  EXPECT_FALSE(IsDomainMatched(rules, "myru"));
  EXPECT_FALSE(IsDomainMatched(rules, ""));
}

TEST(SplitTunnelingTest, AcceptsLegacyAndDirtyRules) {
  const auto rules = MakeRules({"domain:vk.com", "  YANDEX.RU  ", "ok.ru."});

  EXPECT_TRUE(IsDomainMatched(rules, "vk.com"));
  EXPECT_TRUE(IsDomainMatched(rules, "sub.vk.com"));
  EXPECT_TRUE(IsDomainMatched(rules, "yandex.ru"));
  EXPECT_TRUE(IsDomainMatched(rules, "mail.yandex.ru"));
  EXPECT_TRUE(IsDomainMatched(rules, "ok.ru"));
}

TEST(SplitTunnelingTest, EmptyRulesMatchNothing) {
  const std::unordered_set<std::string> rules;

  EXPECT_FALSE(IsDomainMatched(rules, "vk.com"));
  EXPECT_FALSE(IsDomainMatched(rules, "mail.ru"));
}

TEST(SplitTunnelingTest, SplitsSubdomainViaParentRule) {
  const auto rules = MakeRules({"vk.com"});

  EXPECT_TRUE(IsDomainMatched(rules, "vk.com"));
  EXPECT_TRUE(IsDomainMatched(rules, "m.vk.com"));
  EXPECT_TRUE(IsDomainMatched(rules, "api.m.vk.com"));
  EXPECT_FALSE(IsDomainMatched(rules, "notvk.com"));
  EXPECT_FALSE(IsDomainMatched(rules, "vk.com.evil.net"));
}
