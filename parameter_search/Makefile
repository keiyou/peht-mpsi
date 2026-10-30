CXX ?= g++

CXXFLAGS := -std=c++20 -O2 -Wall -Wextra -pthread
LDFLAGS := -L/usr/local/lib
LDLIBS := -lsodium -lhelib -lntl -lgmp -lm -lpthread

BIN := bin
TARGET := $(BIN)/find_parameters
SOURCE := find_parameters.cpp
DEP := $(BIN)/find_parameters.d

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCE) | $(BIN)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -MF $(DEP) -MT $@ \
		$(LDFLAGS) $< $(LDLIBS) -o $@

$(BIN):
	mkdir -p $@

clean:
	rm -rf $(BIN)

-include $(DEP)
