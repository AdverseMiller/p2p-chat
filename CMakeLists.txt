cmake_minimum_required(VERSION 3.20)

project(p2p_chat LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)

option(P2PCHAT_ENABLE_LTO "Enable link-time optimization (IPO/LTO) if supported" ON)
include(CheckIPOSupported)
check_ipo_supported(RESULT P2PCHAT_IPO_OK OUTPUT P2PCHAT_IPO_ERR)
if(P2PCHAT_ENABLE_LTO AND P2PCHAT_IPO_OK AND CMAKE_BUILD_TYPE MATCHES "^[Rr]elease$")
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

function(p2pchat_max_perf target_name)
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # "Max perf" for production builds. Note: `-ffast-math` changes floating-point semantics.
    target_compile_options(${target_name} PRIVATE
      $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-O3 -ffast-math -DNDEBUG -g0 -fno-unwind-tables -fno-asynchronous-unwind-tables>
    )
    target_link_options(${target_name} PRIVATE
      $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-Wl,-O2>
    )
  endif()
endfunction()

function(p2pchat_small_binary target_name)
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target_name} PRIVATE $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-ffunction-sections -fdata-sections>)
    target_link_options(${target_name} PRIVATE $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-Wl,--gc-sections -Wl,--as-needed>)
    # Strip in Release/MinSizeRel (keeps Debug usable).
    target_link_options(${target_name} PRIVATE $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-s>)
  endif()
endfunction()

find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

include(CheckIncludeFileCXX)

find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(MINIUPNPC miniupnpc)
endif()

find_package(Qt6 QUIET COMPONENTS Widgets)

add_executable(rendezvous_server rendezvous_server.cpp)
target_include_directories(rendezvous_server PRIVATE .)
target_link_libraries(rendezvous_server PRIVATE Boost::system OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
p2pchat_max_perf(rendezvous_server)
p2pchat_small_binary(rendezvous_server)
if(WIN32)
  target_link_libraries(rendezvous_server PRIVATE ws2_32 mswsock)
endif()
if(MINIUPNPC_FOUND)
  target_compile_definitions(rendezvous_server PRIVATE HAVE_UPNP)
  target_include_directories(rendezvous_server PRIVATE ${MINIUPNPC_INCLUDE_DIRS})
  target_link_libraries(rendezvous_server PRIVATE ${MINIUPNPC_LIBRARIES})
endif()

if(UNIX)
  add_executable(p2p_chat p2p_chat.cpp)
  target_include_directories(p2p_chat PRIVATE .)
  target_link_libraries(p2p_chat PRIVATE Boost::system OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
  p2pchat_max_perf(p2p_chat)
  p2pchat_small_binary(p2p_chat)
  if(MINIUPNPC_FOUND)
    target_compile_definitions(p2p_chat PRIVATE HAVE_UPNP)
    target_include_directories(p2p_chat PRIVATE ${MINIUPNPC_INCLUDE_DIRS})
    target_link_libraries(p2p_chat PRIVATE ${MINIUPNPC_LIBRARIES})
  endif()
endif()

if(Qt6_FOUND)
  add_executable(p2p_chat_gui
    gui/main.cpp
    gui/MainWindow.cpp
    gui/MainWindow.hpp
    gui/Profile.cpp
    gui/Profile.hpp
    gui/ChatBackend.cpp
    gui/ChatBackend.hpp
  )
  target_include_directories(p2p_chat_gui PRIVATE .)
  target_link_libraries(p2p_chat_gui PRIVATE Qt6::Widgets Boost::system OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
  p2pchat_max_perf(p2p_chat_gui)
  p2pchat_small_binary(p2p_chat_gui)
  if(WIN32)
    target_link_libraries(p2p_chat_gui PRIVATE ws2_32 mswsock)
  endif()
  if(MINIUPNPC_FOUND)
    target_compile_definitions(p2p_chat_gui PRIVATE HAVE_UPNP)
    target_include_directories(p2p_chat_gui PRIVATE ${MINIUPNPC_INCLUDE_DIRS})
    target_link_libraries(p2p_chat_gui PRIVATE ${MINIUPNPC_LIBRARIES})
  endif()

  add_executable(udp_smoke
    smoke/udp_smoke.cpp
    gui/ChatBackend.cpp
    gui/ChatBackend.hpp
    gui/Profile.cpp
    gui/Profile.hpp
  )
  target_include_directories(udp_smoke PRIVATE .)
  target_link_libraries(udp_smoke PRIVATE Qt6::Core Boost::system OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
  if(WIN32)
    target_link_libraries(udp_smoke PRIVATE ws2_32 mswsock)
  endif()
else()
  message(STATUS "Qt6 not found; p2p_chat_gui target will not be built.")
endif()
