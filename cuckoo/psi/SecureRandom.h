#pragma once

#include "Defines.h"

#include <array>
#include <sodium.h>
#include <stdexcept>

namespace protocol_randomness
{
inline void ensureAvailable()
{
    static const int initializationResult = sodium_init();
    if (initializationResult < 0)
        throw std::runtime_error("Unable to initialize secure protocol randomness");
}

// os rng, not the bench seed
inline block freshBlock()
{
    ensureAvailable();
    std::array<u64, 2> words{};
    randombytes_buf(words.data(), sizeof(words));
    return oc::toBlock(words[0], words[1]);
}
}
