//===- FuzzerExtFunctionsWindows.cpp - Interface to external functions ----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// MinGW replacement for upstream `FuzzerExtFunctionsWindows.cpp`.
//
// The upstream file is written for MSVC and clang-cl: it uses `__pragma`,
// `/alternatename` linker directives, and clang's `__builtin_function_start`.
// GCC/MinGW supports none of those, so the fuzz runtime cannot be built with
// the only C++ toolchain available on this host.
//
// libFuzzer's external functions are optional crash/leak-reporting hooks and
// the optional user `LLVMFuzzerInitialize` hooks. Leaving every pointer null is
// a supported configuration: libFuzzer checks each pointer before use. This
// shim deliberately does not try to emulate weak aliases, because a stub that
// silently reports "not defined" would be worse than a null check.
//
// This file is compiled only by `fuzz/build_libfuzzer_mingw.sh`, which builds
// the runtime with MinGW and passes it to libfuzzer-sys through
// `CUSTOM_LIBFUZZER_PATH`. It is not part of the product workspace.
//
//===----------------------------------------------------------------------===//

#include "FuzzerPlatform.h"

#if LIBFUZZER_WINDOWS

#include "FuzzerExtFunctions.h"

namespace fuzzer {

ExternalFunctions::ExternalFunctions() {
  // All members are initialized to nullptr in FuzzerExtFunctions.h. Keeping
  // this constructor empty is the whole point of the shim.
}

} // namespace fuzzer

#endif // LIBFUZZER_WINDOWS
