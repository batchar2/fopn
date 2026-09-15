/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "status/server_registry.h"

namespace {

using fptn::client::status::ServerRegistry;
using fptn::utils::speed_estimator::ServerInfo;

ServerInfo MakeServer(const std::string& name,
    const std::string& host,
    int port = 443,
    const std::string& service = "") {
  ServerInfo server(name, host, port, "fingerprint");
  server.service_name = service;
  return server;
}

}  // namespace

// cppcheck-suppress syntaxError
TEST(ServerRegistryTest, KeyOfIsHostAndPort) {
  EXPECT_EQ(ServerRegistry::KeyOf(MakeServer("n", "a.b", 443)), "a.b:443");
  EXPECT_EQ(ServerRegistry::KeyOf(MakeServer("n", "a.b", 0)), "a.b:0");
}

TEST(ServerRegistryTest, DisplayNameQualifiesWithService) {
  EXPECT_EQ(ServerRegistry::DisplayName(MakeServer("srv", "h")), "srv");
  EXPECT_EQ(
      ServerRegistry::DisplayName(MakeServer("srv", "h", 443, "svc")),
      "svc/srv");
}

TEST(ServerRegistryTest, ResetFillsPoolInTokenOrder) {
  ServerRegistry registry;
  registry.Reset({MakeServer("a", "1.1.1.1"), MakeServer("b", "2.2.2.2"),
      MakeServer("c", "3.3.3.3")});

  const auto servers = registry.Servers();
  ASSERT_EQ(servers.size(), 3U);
  EXPECT_EQ(servers[0].name, "a");
  EXPECT_EQ(servers[1].name, "b");
  EXPECT_EQ(servers[2].name, "c");
}

TEST(ServerRegistryTest, ResetDeduplicatesByHostPort) {
  ServerRegistry registry;
  registry.Reset({MakeServer("first", "1.1.1.1"), MakeServer("second",
      "1.1.1.1")});

  const auto servers = registry.Servers();
  ASSERT_EQ(servers.size(), 1U);
  EXPECT_EQ(servers[0].name, "first");
}

// Rebuilding the pool must not wipe what is already known about a server.
TEST(ServerRegistryTest, ResetKeepsMeasurementsForSurvivingServers) {
  ServerRegistry registry;
  const auto server = MakeServer("a", "1.1.1.1");
  registry.Reset({server});
  registry.RecordProbe(server, 120);

  registry.Reset({server});

  const auto stats = registry.Stats(server);
  EXPECT_EQ(stats.total, 1U);
  EXPECT_EQ(stats.average_ms, 120U);
  EXPECT_TRUE(stats.alive);
}

TEST(ServerRegistryTest, ResetDropsServersRemovedFromPool) {
  ServerRegistry registry;
  const auto a = MakeServer("a", "1.1.1.1");
  const auto b = MakeServer("b", "2.2.2.2");
  registry.Reset({a, b});
  registry.RecordProbe(b, 50);

  registry.Reset({a});
  EXPECT_EQ(registry.Servers().size(), 1U);

  // Coming back means starting over: the old history does not return.
  registry.Reset({a, b});
  EXPECT_EQ(registry.Stats(b).total, 0U);
}

TEST(ServerRegistryTest, ResetClearsActiveWhenServerLeavesPool) {
  ServerRegistry registry;
  const auto a = MakeServer("a", "1.1.1.1");
  const auto b = MakeServer("b", "2.2.2.2");
  registry.Reset({a, b});
  registry.SetActive(b);
  ASSERT_EQ(registry.ToJson()["current"], "2.2.2.2:443");

  registry.Reset({a});
  EXPECT_EQ(registry.ToJson()["current"], "");
}

TEST(ServerRegistryTest, RecordProbeIgnoresUnknownServer) {
  ServerRegistry registry;
  registry.Reset({MakeServer("a", "1.1.1.1")});

  registry.RecordProbe(MakeServer("gone", "9.9.9.9"), 10);

  EXPECT_EQ(registry.Servers().size(), 1U);
  EXPECT_EQ(registry.ToJson()["servers"].size(), 1U);
}

TEST(ServerRegistryTest, WindowKeepsOnlyLastTenMeasurements) {
  ServerRegistry registry;
  const auto server = MakeServer("a", "1.1.1.1");
  registry.Reset({server});
  for (std::uint32_t i = 1; i <= 15; ++i) {
    registry.RecordProbe(server, i);
  }

  const auto stats = registry.Stats(server);
  EXPECT_EQ(stats.total, fptn::client::status::kMeasurementWindow);
  EXPECT_EQ(stats.min_ms, 6U);
  EXPECT_EQ(stats.max_ms, 15U);
}

TEST(ServerRegistryTest, AverageIgnoresFailures) {
  ServerRegistry registry;
  const auto server = MakeServer("a", "1.1.1.1");
  registry.Reset({server});
  registry.RecordProbe(server, 100);
  registry.RecordProbe(server, 0, "boom");
  registry.RecordProbe(server, 200);

  const auto stats = registry.Stats(server);
  EXPECT_EQ(stats.average_ms, 150U);
  EXPECT_EQ(stats.total, 3U);
  EXPECT_EQ(stats.failed, 1U);
  EXPECT_EQ(stats.min_ms, 100U);
  EXPECT_EQ(stats.max_ms, 200U);
}

TEST(ServerRegistryTest, AllFailedGivesZeroStats) {
  ServerRegistry registry;
  const auto server = MakeServer("a", "1.1.1.1");
  registry.Reset({server});
  registry.RecordProbe(server, 0, "down");
  registry.RecordProbe(server, 0, "down");

  const auto stats = registry.Stats(server);
  EXPECT_EQ(stats.average_ms, 0U);
  EXPECT_EQ(stats.failed, 2U);
  EXPECT_FALSE(stats.alive);
}

// The whole point of the window: a single blip must not strike a node out,
// while the latest reading is what decides.
TEST(ServerRegistryTest, AliveFollowsTheLastMeasurement) {
  ServerRegistry registry;
  const auto server = MakeServer("a", "1.1.1.1");
  registry.Reset({server});

  registry.RecordProbe(server, 100);
  registry.RecordProbe(server, 0, "blip");
  EXPECT_FALSE(registry.Stats(server).alive);

  registry.RecordProbe(server, 90);
  EXPECT_TRUE(registry.Stats(server).alive);
}

TEST(ServerRegistryTest, AliveIsFalseWithoutMeasurements) {
  ServerRegistry registry;
  const auto server = MakeServer("a", "1.1.1.1");
  registry.Reset({server});

  EXPECT_FALSE(registry.Stats(server).alive);
  EXPECT_EQ(registry.Stats(server).total, 0U);
}

TEST(ServerRegistryTest, SuccessClearsLastErrorFailureKeepsIt) {
  ServerRegistry registry;
  const auto server = MakeServer("a", "1.1.1.1");
  registry.Reset({server});

  registry.RecordProbe(server, 0, "boom");
  auto json = registry.ToJson()["servers"][0];
  EXPECT_EQ(json["last_error"], "boom");
  EXPECT_EQ(json["last_seen"], "");

  registry.RecordProbe(server, 50);
  json = registry.ToJson()["servers"][0];
  EXPECT_EQ(json["last_error"], "");
  EXPECT_NE(json["last_seen"], "");
}

TEST(ServerRegistryTest, FindByNameIsCaseInsensitiveAndTrimmed) {
  ServerRegistry registry;
  registry.Reset({MakeServer("Server-1", "1.1.1.1", 443, "Svc")});

  EXPECT_TRUE(registry.FindByName(" server-1 ").has_value());
  EXPECT_TRUE(registry.FindByName("SVC/SERVER-1").has_value());
  EXPECT_FALSE(registry.FindByName("").has_value());
  EXPECT_FALSE(registry.FindByName("   ").has_value());
  EXPECT_FALSE(registry.FindByName("nope").has_value());
}

TEST(ServerRegistryTest, FindByKeyMatchesExactly) {
  ServerRegistry registry;
  registry.Reset({MakeServer("a", "1.1.1.1")});

  EXPECT_TRUE(registry.FindByKey("1.1.1.1:443").has_value());
  EXPECT_FALSE(registry.FindByKey("1.1.1.1:80").has_value());
}

TEST(ServerRegistryTest, ClashViewCarriesSelectorGroup) {
  ServerRegistry registry;
  const auto a = MakeServer("a", "1.1.1.1");
  registry.Reset({a, MakeServer("b", "2.2.2.2")});
  registry.SetActive(a);

  const auto proxies = registry.ToClashProxies()["proxies"];
  ASSERT_TRUE(proxies.contains("FPTN"));
  EXPECT_EQ(proxies["FPTN"]["type"], "Selector");
  EXPECT_EQ(proxies["FPTN"]["now"], "a");
  EXPECT_EQ(proxies["FPTN"]["all"].size(), 2U);
  EXPECT_EQ(proxies["a"]["type"], "FPTN");
  EXPECT_TRUE(proxies["a"]["udp"]);
}

TEST(ServerRegistryTest, ClashHistoryHoldsOnlyTheLastMeasurement) {
  ServerRegistry registry;
  const auto server = MakeServer("a", "1.1.1.1");
  registry.Reset({server});
  registry.RecordProbe(server, 10);
  registry.RecordProbe(server, 20);
  registry.RecordProbe(server, 30);

  const auto proxies = registry.ToClashProxies()["proxies"];
  ASSERT_EQ(proxies["a"]["history"].size(), 1U);
  EXPECT_EQ(proxies["a"]["history"][0]["delay"], 30U);
}

// A display name is not unique by contract, while a JSON key is: a collision
// must not make a server disappear from the view.
TEST(ServerRegistryTest, ClashViewKeepsServersWithTheSameDisplayName) {
  ServerRegistry registry;
  registry.Reset({MakeServer("same", "1.1.1.1"), MakeServer("same",
      "2.2.2.2")});

  const auto proxies = registry.ToClashProxies()["proxies"];
  // Selector plus two distinct entries.
  EXPECT_EQ(proxies.size(), 3U);
  EXPECT_TRUE(proxies.contains("same"));
  EXPECT_TRUE(proxies.contains("2.2.2.2:443"));
}

TEST(ServerRegistryTest, ServerNamedLikeTheSelectorDoesNotShadowIt) {
  ServerRegistry registry;
  registry.Reset({MakeServer("FPTN", "1.1.1.1")});

  const auto proxies = registry.ToClashProxies()["proxies"];
  EXPECT_EQ(proxies["FPTN"]["type"], "Selector");
  EXPECT_TRUE(proxies.contains("1.1.1.1:443"));
}

TEST(ServerRegistryTest, JsonListsServersWithInUseFlag) {
  ServerRegistry registry;
  const auto a = MakeServer("a", "1.1.1.1");
  const auto b = MakeServer("b", "2.2.2.2");
  registry.Reset({a, b});
  registry.SetActive(b);

  const auto json = registry.ToJson();
  EXPECT_EQ(json["window"], fptn::client::status::kMeasurementWindow);
  EXPECT_EQ(json["current"], "2.2.2.2:443");
  ASSERT_EQ(json["servers"].size(), 2U);
  EXPECT_FALSE(json["servers"][0]["in_use"]);
  EXPECT_TRUE(json["servers"][1]["in_use"]);
}

TEST(ServerRegistryTest, JsonHistoryCarriesErrorOnlyWhenPresent) {
  ServerRegistry registry;
  const auto server = MakeServer("a", "1.1.1.1");
  registry.Reset({server});
  registry.RecordProbe(server, 42);
  registry.RecordProbe(server, 0, "timeout");

  const auto history = registry.ToJson()["servers"][0]["history"];
  ASSERT_EQ(history.size(), 2U);
  EXPECT_FALSE(history[0].contains("error"));
  EXPECT_EQ(history[1]["error"], "timeout");
}

TEST(ServerRegistryTest, JsonSurvivesUnicodeAndSlashesInNames) {
  ServerRegistry registry;
  registry.Reset({MakeServer("se snowfall / test", "1.1.1.1", 443, "svc")});

  EXPECT_NO_THROW({
    const auto dumped = registry.ToJson().dump();
    EXPECT_FALSE(dumped.empty());
  });
}

TEST(ServerRegistryTest, ConcurrentProbesAndReadsDoNotRace) {
  ServerRegistry registry;
  std::vector<ServerInfo> pool;
  for (int i = 0; i < 8; ++i) {
    pool.push_back(MakeServer("s" + std::to_string(i),
        "10.0.0." + std::to_string(i)));
  }
  registry.Reset(pool);

  std::atomic<bool> stop{false};
  std::vector<std::thread> threads;
  for (const auto& server : pool) {
    threads.emplace_back([&registry, server, &stop]() {
      for (int i = 0; i < 500 && !stop; ++i) {
        registry.RecordProbe(server, static_cast<std::uint32_t>(i % 300) + 1);
      }
    });
  }
  for (int i = 0; i < 4; ++i) {
    threads.emplace_back([&registry, &stop]() {
      for (int j = 0; j < 500 && !stop; ++j) {
        (void)registry.ToJson();
        (void)registry.ToClashProxies();
      }
    });
  }
  for (auto& thread : threads) {
    thread.join();
  }
  SUCCEED();
}
