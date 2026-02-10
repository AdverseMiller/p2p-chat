cmake_minimum_required(VERSION 3.20)

project(p2p_chat LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)

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
if(WIN32)
  target_link_libraries(rendezvous_server PRIVATE ws2_32 mswsock)
endif()
if(MINIUPNPC_FOUND)
  target_compile_definitions(rendezvous_server PRIVATE HAVE_UPNP)
  target_include_directories(rendezvous_server PRIVATE ${MINIUPNPC_INCLUDE_DIRS})
  target_link_libraries(rendezvous_server PRIVATE ${MINIUPNPC_LIBRARIES})
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
  if(WIN32)
    target_link_libraries(p2p_chat_gui PRIVATE ws2_32 mswsock)
  endif()
  if(MINIUPNPC_FOUND)
    target_compile_definitions(p2p_chat_gui PRIVATE HAVE_UPNP)
    target_include_directories(p2p_chat_gui PRIVATE ${MINIUPNPC_INCLUDE_DIRS})
    target_link_libraries(p2p_chat_gui PRIVATE ${MINIUPNPC_LIBRARIES})
  endif()
else()
  message(STATUS "Qt6 not found; p2p_chat_gui target will not be built.")
endif()
