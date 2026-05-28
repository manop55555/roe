// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The roe Authors
#pragma once

/**
 * @file version.hpp
 * @brief Build-time version constants for roe.
 */

namespace roe {

inline constexpr int version_major = 1;
inline constexpr int version_minor = 0;
inline constexpr int version_patch = 1;
inline constexpr const char* version_string = "1.0.1";
inline constexpr const char* program_name = "roe";

#ifndef ROE_BUILD_COMMIT
#define ROE_BUILD_COMMIT "unknown"
#endif

#ifndef ROE_BUILD_DATE
#define ROE_BUILD_DATE "unknown"
#endif

#ifndef ROE_CAPSTONE_VERSION
#define ROE_CAPSTONE_VERSION "unknown"
#endif

inline constexpr const char* build_commit = ROE_BUILD_COMMIT;
inline constexpr const char* build_date = ROE_BUILD_DATE;
inline constexpr const char* capstone_version = ROE_CAPSTONE_VERSION;

} // namespace roe
