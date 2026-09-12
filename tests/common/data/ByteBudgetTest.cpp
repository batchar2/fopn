/*
 * Copyright Nixort <https://github.com/Nixort/fptn> 2026.
 *
 * License: MIT
 * You can find the license file in the project root.
 *
 * FPTN
 * The code was written for FPTN.
 * 15 August 2026.
 *
 * Transport and protocol implementation.
 *
 * This file contains a focused implementation component for the FPTN
 * transport optimization and its deterministic test coverage.
 */
#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/data/byte_budget.h"

namespace {

TEST(ByteBudgetTest, AcquiresUpToConfiguredLimit) {
  fptn::common::data::ByteBudget budget(100);

  EXPECT_TRUE(budget.TryAcquire(40));
  EXPECT_TRUE(budget.TryAcquire(60));
  EXPECT_EQ(budget.UsedBytes(), 100U);
  EXPECT_FALSE(budget.TryAcquire(1));
}

TEST(ByteBudgetTest, RejectsRequestLargerThanLimit) {
  fptn::common::data::ByteBudget budget(100);

  EXPECT_FALSE(budget.TryAcquire(101));
  EXPECT_EQ(budget.UsedBytes(), 0U);
}

TEST(ByteBudgetTest, ReleasesCapacityForNextBatch) {
  fptn::common::data::ByteBudget budget(100);

  ASSERT_TRUE(budget.TryAcquire(80));
  budget.Release(50);

  EXPECT_EQ(budget.UsedBytes(), 30U);
  EXPECT_TRUE(budget.TryAcquire(70));
  EXPECT_EQ(budget.UsedBytes(), 100U);
}

TEST(ByteBudgetTest, AcceptsZeroByteReservation) {
  fptn::common::data::ByteBudget budget(0);

  EXPECT_TRUE(budget.TryAcquire(0));
  EXPECT_FALSE(budget.TryAcquire(1));
  EXPECT_EQ(budget.UsedBytes(), 0U);
}

}  // namespace
