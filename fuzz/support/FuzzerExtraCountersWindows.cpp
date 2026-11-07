//===- FuzzerExtraCountersWindows.cpp - Extra coverage counters -----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// MinGW replacement for upstream `FuzzerExtraCountersWindows.cpp`.
//
// The upstream implementation relies on MSVC section ordering (`.data$...`)
// and `__declspec(allocate)` to place sentinel bytes around user-defined extra
// coverage counters. GNU ld does not preserve that ordering, so its
// `__stop - __start` calculation underflows and `ClearExtraCounters` tries to
// zero an enormous range. Litric's fuzz targets define no extra counters, so
// an empty range is the correct, safe behavior.
//
//===----------------------------------------------------------------------===//

#include "FuzzerPlatform.h"

#if LIBFUZZER_WINDOWS

#include <cstdint>

namespace fuzzer {

uint8_t *ExtraCountersBegin() { return nullptr; }
uint8_t *ExtraCountersEnd() { return nullptr; }
void ClearExtraCounters() {}

} // namespace fuzzer

#endif // LIBFUZZER_WINDOWS
