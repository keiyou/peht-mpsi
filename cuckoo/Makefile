CXX ?= g++

CPPFLAGS := -DNDEBUG
CXXFLAGS := -std=c++20 -O3 -Wall -Wextra \
	-maes -msse2 -mpclmul -mavx2 -march=native -fopenmp -flto=auto
LDFLAGS := -L/usr/local/lib
LDLIBS := -lvolePSI -llibOTe -lcryptoTools -lcoproto -lbitpolymul \
	-lsodium -lboost_system -lhelib -lntl -lgmp -lm -lpthread

BIN := bin
TARGET := $(BIN)/ot_mpsi
SOURCES := $(wildcard psi/*.cpp psi/*/*.cpp frontend/*.cpp)
OBJECTS := $(SOURCES:.cpp=.o)
DEPS := $(OBJECTS:.o=.d)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS) | $(BIN)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(BIN):
	mkdir -p $@

clean:
	rm -f $(OBJECTS) $(DEPS) $(TARGET)

-include $(DEPS)
