/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <algorithm>
#include <chrono>
#include <cstddef>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "traffic_shaper/leaky_bucket.h"

namespace {

using fptn::traffic_shaper::LeakyBucket;

// 8000 bit/s is exactly 1000 byte/s - the arithmetic stays readable.
constexpr std::size_t kBitsPerSecond = 8000;
constexpr std::size_t kBytesPerSecond = kBitsPerSecond / 8;

// The bucket stamps its own creation time from the real clock, so the test
// clock has to start from there rather than from the epoch.
std::chrono::steady_clock::time_point Start() {
  return std::chrono::steady_clock::now();
}

}  // namespace

// cppcheck-suppress syntaxError
TEST(LeakyBucketTest, AdmitsPacketsUpToTheBudget) {
  LeakyBucket bucket(kBitsPerSecond);
  const auto now = Start();

  for (int i = 0; i < 10; ++i) {
    EXPECT_TRUE(bucket.CheckSpeedLimitAt(100, now)) << "packet " << i;
  }
  EXPECT_FALSE(bucket.CheckSpeedLimitAt(100, now));
}

TEST(LeakyBucketTest, BoundaryPacketFitsExactly) {
  LeakyBucket bucket(kBitsPerSecond);
  const auto now = Start();

  EXPECT_TRUE(bucket.CheckSpeedLimitAt(kBytesPerSecond, now));
  EXPECT_FALSE(bucket.CheckSpeedLimitAt(1, now));
}

TEST(LeakyBucketTest, RejectedPacketIsNotCounted) {
  LeakyBucket bucket(kBitsPerSecond);
  const auto now = Start();

  ASSERT_TRUE(bucket.CheckSpeedLimitAt(kBytesPerSecond, now));
  const auto before = bucket.FullDataAmount();
  EXPECT_FALSE(bucket.CheckSpeedLimitAt(1, now));
  EXPECT_EQ(bucket.FullDataAmount(), before);
}

// The bucket has to drain in proportion to time, not on a full second of
// silence.
TEST(LeakyBucketTest, LeaksProportionallyToElapsedTime) {
  LeakyBucket bucket(kBitsPerSecond);
  const auto now = Start();

  ASSERT_TRUE(bucket.CheckSpeedLimitAt(kBytesPerSecond, now));
  ASSERT_FALSE(bucket.CheckSpeedLimitAt(1, now));

  const auto half = now + std::chrono::milliseconds(500);
  EXPECT_TRUE(bucket.CheckSpeedLimitAt(kBytesPerSecond / 2, half));
  EXPECT_FALSE(bucket.CheckSpeedLimitAt(1, half));
}

// The regression this class was fixed for: a dense stream with no pauses used
// to be blacked out for most of every second.
TEST(LeakyBucketTest, DenseStreamKeepsFlowingAtTheLimit) {
  constexpr std::size_t kPacket = 100;
  LeakyBucket bucket(kBitsPerSecond);
  auto now = Start();

  std::size_t admitted = 0;
  for (int ms = 0; ms < 10000; ++ms) {
    now += std::chrono::milliseconds(1);
    if (bucket.CheckSpeedLimitAt(kPacket, now)) {
      admitted += kPacket;
    }
  }

  // Ten seconds at 1000 byte/s, plus at most one bucket depth of burst.
  const std::size_t expected = kBytesPerSecond * 10;
  EXPECT_GE(admitted, expected * 95 / 100);
  EXPECT_LE(admitted, expected + kBytesPerSecond);
}

// The real symptom of the old code was not the total but its distribution:
// a full second of budget went out in the first milliseconds, and the rest of
// the second was a blackout. TCP survives a steady trickle far better than a
// burst followed by a second of silence, so what is measured here is the
// longest run of consecutive rejects.
TEST(LeakyBucketTest, DenseStreamHasNoLongBlackouts) {
  constexpr std::size_t kPacket = 100;
  LeakyBucket bucket(kBitsPerSecond);
  auto now = Start();

  int longest_blackout = 0;
  int current_blackout = 0;
  for (int ms = 0; ms < 5000; ++ms) {
    now += std::chrono::milliseconds(1);
    if (bucket.CheckSpeedLimitAt(kPacket, now)) {
      current_blackout = 0;
    } else {
      ++current_blackout;
      longest_blackout = std::max(longest_blackout, current_blackout);
    }
  }

  // At 1000 byte/s and 100-byte packets one packet is due every 100 ms, so a
  // gap of a few hundred milliseconds is normal and a second is not.
  EXPECT_LE(longest_blackout, 300) << "longest silence " << longest_blackout
                                   << " ms";
}

TEST(LeakyBucketTest, IdleTimeDoesNotOverfillTheBucket) {
  LeakyBucket bucket(kBitsPerSecond);
  const auto now = Start();
  ASSERT_TRUE(bucket.CheckSpeedLimitAt(kBytesPerSecond, now));

  // Ten seconds of silence must not buy ten seconds of budget.
  const auto later = now + std::chrono::seconds(10);
  std::size_t admitted = 0;
  while (bucket.CheckSpeedLimitAt(100, later)) {
    admitted += 100;
    ASSERT_LE(admitted, kBytesPerSecond * 2) << "bucket never filled up";
  }
  EXPECT_EQ(admitted, kBytesPerSecond);
}

TEST(LeakyBucketTest, RefillIsSmoothWithinASecond) {
  // Spend the budget, then take it back in ten steps of a tenth of a second.
  // The old code released nothing until a full second had passed, so each of
  // the first nine steps would have been refused outright.
  LeakyBucket bucket(kBitsPerSecond);
  auto now = Start();
  for (int i = 0; i < 10; ++i) {
    ASSERT_TRUE(bucket.CheckSpeedLimitAt(kBytesPerSecond / 10, now));
  }
  ASSERT_FALSE(bucket.CheckSpeedLimitAt(1, now));

  int accepted_steps = 0;
  for (int step = 0; step < 9; ++step) {
    now += std::chrono::milliseconds(100);
    if (bucket.CheckSpeedLimitAt(kBytesPerSecond / 10, now)) {
      ++accepted_steps;
    }
  }

  EXPECT_EQ(accepted_steps, 9);
}

// A zero limit means "no limit": the server builds a shaper unconditionally,
// and a bucket of zero would silence the tunnel instead of slowing it.
TEST(LeakyBucketTest, ZeroLimitAdmitsEverything) {
  LeakyBucket bucket(0);
  const auto now = Start();

  for (int i = 0; i < 1000; ++i) {
    EXPECT_TRUE(bucket.CheckSpeedLimitAt(1500, now));
  }
  EXPECT_EQ(bucket.FullDataAmount(), 1500U * 1000U);
}

TEST(LeakyBucketTest, HugeLimitDoesNotOverflow) {
  // 10 Gbit/s and a long silence: the intermediate product must stay in 64
  // bits and the drain must not wrap.
  LeakyBucket bucket(10ULL * 1000 * 1000 * 1000);
  const auto now = Start();
  ASSERT_TRUE(bucket.CheckSpeedLimitAt(1500, now));

  const auto much_later = now + std::chrono::hours(24);
  EXPECT_TRUE(bucket.CheckSpeedLimitAt(1500, much_later));
}

TEST(LeakyBucketTest, BitsAreConvertedToBytesByEight) {
  LeakyBucket bucket(800);  // 100 byte/s
  const auto now = Start();

  EXPECT_TRUE(bucket.CheckSpeedLimitAt(100, now));
  EXPECT_FALSE(bucket.CheckSpeedLimitAt(1, now));
}

TEST(LeakyBucketTest, FullDataAmountCountsOnlyAdmittedBytes) {
  LeakyBucket bucket(kBitsPerSecond);
  const auto now = Start();

  ASSERT_TRUE(bucket.CheckSpeedLimitAt(400, now));
  ASSERT_TRUE(bucket.CheckSpeedLimitAt(400, now));
  ASSERT_FALSE(bucket.CheckSpeedLimitAt(400, now));

  EXPECT_EQ(bucket.FullDataAmount(), 800U);
}
