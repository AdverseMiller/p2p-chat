cmake_minimum_required(VERSION 3.20)

project(p2p_chat LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)

include(CheckCXXCompilerFlag)

if(WIN32)
  # MinGW LTO has been observed to produce unwind symbol link failures on CI.
  option(P2PCHAT_ENABLE_LTO "Enable link-time optimization (IPO/LTO) if supported" OFF)
else()
  option(P2PCHAT_ENABLE_LTO "Enable link-time optimization (IPO/LTO) if supported" ON)
endif()

set(P2PCHAT_ON_GITHUB_CI OFF)
if(DEFINED ENV{GITHUB_ACTIONS} AND "$ENV{GITHUB_ACTIONS}" STREQUAL "true")
  set(P2PCHAT_ON_GITHUB_CI ON)
endif()

if(P2PCHAT_ON_GITHUB_CI OR CMAKE_CROSSCOMPILING)
  set(P2PCHAT_ENABLE_MARCH_NATIVE_DEFAULT OFF)
else()
  set(P2PCHAT_ENABLE_MARCH_NATIVE_DEFAULT ON)
endif()
option(P2PCHAT_ENABLE_MARCH_NATIVE "Enable -march=native for local non-CI builds" ${P2PCHAT_ENABLE_MARCH_NATIVE_DEFAULT})

include(CheckIPOSupported)
check_ipo_supported(RESULT P2PCHAT_IPO_OK OUTPUT P2PCHAT_IPO_ERR)
if(P2PCHAT_ENABLE_LTO AND P2PCHAT_IPO_OK AND CMAKE_BUILD_TYPE MATCHES "^[Rr]elease$")
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

function(p2pchat_max_perf target_name)
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # "Max perf" for production builds. Note: `-ffast-math` changes floating-point semantics.
    if(WIN32)
      target_compile_options(${target_name} PRIVATE
        $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-O3 -ffast-math -DNDEBUG -g0>
      )
    else()
      target_compile_options(${target_name} PRIVATE
        $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-O3 -ffast-math -DNDEBUG -g0 -fno-unwind-tables -fno-asynchronous-unwind-tables>
      )
    endif()
    if(P2PCHAT_ENABLE_MARCH_NATIVE)
      target_compile_options(${target_name} PRIVATE
        $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-march=native>
      )
    endif()
    target_link_options(${target_name} PRIVATE
      $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-Wl,-O2>
    )
  endif()
endfunction()

function(p2pchat_small_binary target_name)
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target_name} PRIVATE $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-ffunction-sections -fdata-sections>)
    # Note: `--as-needed` has caused MinGW CI to drop unwind/runtime libs, leading to unresolved _Unwind_SjLj_*.
    if(WIN32)
      target_link_options(${target_name} PRIVATE $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-Wl,--gc-sections>)
    else()
      target_link_options(${target_name} PRIVATE $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-Wl,--gc-sections -Wl,--as-needed>)
    endif()
    # Strip in Release/MinSizeRel (keeps Debug usable).
    target_link_options(${target_name} PRIVATE $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-s>)
  endif()
endfunction()

function(p2pchat_windows_eh target_name)
  # GitHub CI has shown MinGW builds accidentally producing SJLJ unwind references.
  # Force SEH exceptions when supported to avoid unresolved _Unwind_SjLj_* / __gxx_personality_sj0 at link time.
  if(WIN32 AND MINGW AND (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang"))
    check_cxx_compiler_flag("-fseh-exceptions" P2PCHAT_HAVE_FSEH_EXCEPTIONS)
    if(P2PCHAT_HAVE_FSEH_EXCEPTIONS)
      target_compile_options(${target_name} PRIVATE -fseh-exceptions)
    endif()
  endif()
endfunction()

find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

include(CheckIncludeFileCXX)

find_package(PkgConfig)

find_package(Qt6 QUIET COMPONENTS Core Widgets Multimedia)

option(P2PCHAT_ENABLE_VOICE "Enable voice call support (requires Qt6 Multimedia + Opus)" ON)

set(P2PCHAT_HAVE_OPUS OFF)
if(P2PCHAT_ENABLE_VOICE)
  # Prefer pkg-config (Linux/MSYS2), but also support toolchains without it.
  if(PKG_CONFIG_FOUND)
    pkg_check_modules(OPUS opus)
  endif()
  if(OPUS_FOUND)
    set(P2PCHAT_HAVE_OPUS ON)
  else()
    find_path(OPUS_INCLUDE_DIR opus/opus.h)
    find_library(OPUS_LIBRARY NAMES opus libopus)
    if(OPUS_INCLUDE_DIR AND OPUS_LIBRARY)
      set(P2PCHAT_HAVE_OPUS ON)
      set(OPUS_INCLUDE_DIRS ${OPUS_INCLUDE_DIR})
      set(OPUS_LIBRARIES ${OPUS_LIBRARY})
    endif()
  endif()
endif()

option(P2PCHAT_ENABLE_VIDEO "Enable webcam video over P2P UDP (Linux + FFmpeg)" ON)
set(P2PCHAT_HAVE_VIDEO_FFMPEG OFF)
if(P2PCHAT_ENABLE_VIDEO AND UNIX AND NOT WIN32 AND PKG_CONFIG_FOUND)
  pkg_check_modules(AVCODEC libavcodec)
  pkg_check_modules(AVUTIL libavutil)
  pkg_check_modules(SWSCALE libswscale)
  if(AVCODEC_FOUND AND AVUTIL_FOUND AND SWSCALE_FOUND)
    set(P2PCHAT_HAVE_VIDEO_FFMPEG ON)
  endif()
endif()

if(NOT WIN32)
  add_executable(rendezvous_server rendezvous_server.cpp)
  target_include_directories(rendezvous_server PRIVATE .)
  target_link_libraries(rendezvous_server PRIVATE Boost::system OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
  p2pchat_max_perf(rendezvous_server)
  p2pchat_small_binary(rendezvous_server)
  p2pchat_windows_eh(rendezvous_server)
endif()

if(UNIX)
  add_executable(p2p_chat p2p_chat.cpp)
  target_include_directories(p2p_chat PRIVATE .)
  target_link_libraries(p2p_chat PRIVATE Boost::system OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
  p2pchat_max_perf(p2p_chat)
  p2pchat_small_binary(p2p_chat)
  p2pchat_windows_eh(p2p_chat)
endif()

if(Qt6Widgets_FOUND)
  set(P2PCHAT_VIDEO_SOURCES
    src/video/v4l2_caps.cpp
    src/video/v4l2_caps.h
    src/video/v4l2_capture.cpp
    src/video/v4l2_capture.h
    src/video/video_codec.cpp
    src/video/video_codec.h
    src/video/video_packetizer.cpp
    src/video/video_packetizer.h
  )

  add_executable(p2p_chat_gui
    gui/main.cpp
    gui/MainWindow.cpp
    gui/MainWindow.hpp
    gui/Profile.cpp
    gui/Profile.hpp
    gui/ChatBackend.cpp
    gui/ChatBackend.hpp
    gui/SettingsDialog.cpp
    gui/SettingsDialog.hpp
    ${P2PCHAT_VIDEO_SOURCES}
  )
  target_include_directories(p2p_chat_gui PRIVATE .)
  target_link_libraries(p2p_chat_gui PRIVATE Qt6::Widgets Qt6::Core Boost::system OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
  p2pchat_max_perf(p2p_chat_gui)
  p2pchat_small_binary(p2p_chat_gui)
  p2pchat_windows_eh(p2p_chat_gui)
  if(WIN32)
    target_link_libraries(p2p_chat_gui PRIVATE ws2_32 mswsock)
  endif()

  if(P2PCHAT_ENABLE_VOICE AND Qt6Multimedia_FOUND AND P2PCHAT_HAVE_OPUS)
    target_compile_definitions(p2p_chat_gui PRIVATE P2PCHAT_VOICE)
    target_link_libraries(p2p_chat_gui PRIVATE Qt6::Multimedia)
    target_include_directories(p2p_chat_gui PRIVATE ${OPUS_INCLUDE_DIRS})
    target_link_libraries(p2p_chat_gui PRIVATE ${OPUS_LIBRARIES})
    if(P2PCHAT_HAVE_VIDEO_FFMPEG)
      target_compile_definitions(p2p_chat_gui PRIVATE P2PCHAT_VIDEO)
      target_include_directories(p2p_chat_gui PRIVATE ${AVCODEC_INCLUDE_DIRS} ${AVUTIL_INCLUDE_DIRS} ${SWSCALE_INCLUDE_DIRS})
      target_link_libraries(p2p_chat_gui PRIVATE ${AVCODEC_LIBRARIES} ${AVUTIL_LIBRARIES} ${SWSCALE_LIBRARIES})
    else()
      message(STATUS "Video disabled for p2p_chat_gui (need FFmpeg libs: libavcodec/libavutil/libswscale)")
    endif()
  else()
    target_compile_definitions(p2p_chat_gui PRIVATE P2PCHAT_NO_VOICE)
    if(P2PCHAT_ENABLE_VOICE)
      message(STATUS "Voice disabled for p2p_chat_gui (need Qt6 Multimedia + Opus): "
                     "Qt6Multimedia_FOUND=${Qt6Multimedia_FOUND}, "
                     "P2PCHAT_HAVE_OPUS=${P2PCHAT_HAVE_OPUS}")
    endif()
  endif()

  if(NOT WIN32)
    add_executable(udp_smoke
      smoke/udp_smoke.cpp
      gui/ChatBackend.cpp
      gui/ChatBackend.hpp
      gui/Profile.cpp
      gui/Profile.hpp
      ${P2PCHAT_VIDEO_SOURCES}
    )
    target_include_directories(udp_smoke PRIVATE .)
    target_link_libraries(udp_smoke PRIVATE Qt6::Core Boost::system OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
    if(P2PCHAT_ENABLE_VOICE AND Qt6Multimedia_FOUND AND P2PCHAT_HAVE_OPUS)
      target_compile_definitions(udp_smoke PRIVATE P2PCHAT_VOICE)
      target_link_libraries(udp_smoke PRIVATE Qt6::Multimedia ${OPUS_LIBRARIES})
      target_include_directories(udp_smoke PRIVATE ${OPUS_INCLUDE_DIRS})
      if(P2PCHAT_HAVE_VIDEO_FFMPEG)
        target_compile_definitions(udp_smoke PRIVATE P2PCHAT_VIDEO)
        target_include_directories(udp_smoke PRIVATE ${AVCODEC_INCLUDE_DIRS} ${AVUTIL_INCLUDE_DIRS} ${SWSCALE_INCLUDE_DIRS})
        target_link_libraries(udp_smoke PRIVATE ${AVCODEC_LIBRARIES} ${AVUTIL_LIBRARIES} ${SWSCALE_LIBRARIES})
      endif()
    endif()

    add_executable(v4l2_dump_modes
      tools/v4l2_dump_modes.cpp
      src/video/v4l2_caps.cpp
      src/video/v4l2_caps.h
    )
    target_include_directories(v4l2_dump_modes PRIVATE .)
    target_link_libraries(v4l2_dump_modes PRIVATE Qt6::Core Threads::Threads)

    add_executable(video_packetizer_smoke
      tests/video_packetizer_smoke.cpp
      src/video/video_packetizer.cpp
      src/video/video_packetizer.h
    )
    target_include_directories(video_packetizer_smoke PRIVATE .)
  endif()
else()
  message(STATUS "Qt6 not found; p2p_chat_gui target will not be built.")
endif()
