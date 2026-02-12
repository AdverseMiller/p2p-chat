CXX ?= g++

CXXFLAGS ?= -O3 -ffast-math
CXXFLAGS += -std=c++20 -Wall -Wextra -Wpedantic -I.
LDFLAGS ?=

# Size/perf defaults:
# - Release-like builds by default (no -g), stripped, with dead-code elimination.
# - For debug symbols, run: `make DEBUG=1`
DEBUG ?= 0
ifeq ($(DEBUG),1)
  CXXFLAGS := $(filter-out -ffast-math,$(filter-out -O3,$(CXXFLAGS)))
  CXXFLAGS += -O0 -g
else
  CXXFLAGS += -DNDEBUG
  LDFLAGS += -s
endif

CXXFLAGS += -ffunction-sections -fdata-sections
LDFLAGS += -Wl,--gc-sections

ifeq ($(GITHUB_ACTIONS),true)
  NATIVE_ARCH ?= 0
else
  NATIVE_ARCH ?= 1
endif
ifeq ($(NATIVE_ARCH),1)
  CXXFLAGS += -march=native
endif

LDLIBS += -lboost_system -lpthread
LDLIBS += -lssl -lcrypto

all: rendezvous_server

rendezvous_server: rendezvous_server.cpp common/framing.hpp common/util.hpp common/json.hpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ rendezvous_server.cpp $(LDLIBS)

p2p_chat: p2p_chat.cpp common/framing.hpp common/util.hpp common/json.hpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ p2p_chat.cpp $(LDLIBS)

gui:
	cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
	cmake --build build -j

clean:
	rm -f rendezvous_server p2p_chat

.PHONY: all clean gui p2p_chat
