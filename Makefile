CXX ?= g++

CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++20 -Wall -Wextra -Wpedantic -I.

LDLIBS += -lboost_system -lpthread
LDLIBS += -lssl -lcrypto

HAVE_UPNP := $(shell pkg-config --exists miniupnpc && echo 1 || echo 0)
ifeq ($(HAVE_UPNP),1)
  CXXFLAGS += $(shell pkg-config --cflags miniupnpc) -DHAVE_UPNP
  LDLIBS += $(shell pkg-config --libs miniupnpc)
endif

all: rendezvous_server

rendezvous_server: rendezvous_server.cpp common/framing.hpp common/util.hpp common/json.hpp
	$(CXX) $(CXXFLAGS) -o $@ rendezvous_server.cpp $(LDLIBS)

gui:
	cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
	cmake --build build -j

clean:
	rm -f rendezvous_server

.PHONY: all clean gui
