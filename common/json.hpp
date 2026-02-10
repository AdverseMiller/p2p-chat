#pragma once

#if __has_include(<nlohmann/json.hpp>)
#include <nlohmann/json.hpp>
#elif __has_include("third_party/nlohmann/json.hpp")
#include "third_party/nlohmann/json.hpp"
#else
#error "nlohmann/json.hpp not found (install nlohmann-json3-dev or vendor the header)"
#endif

namespace common {
using json = nlohmann::json;
} // namespace common
