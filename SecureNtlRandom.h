#pragma once

#include <NTL/ZZ.h>
#include <sodium.h>

#include <array>
#include <stdexcept>

namespace secure_ntl_random
{

// ntl rng is thread-local
inline void seedCurrentThread()
{
    static const bool sodiumReady = []
    {
        if (sodium_init() < 0)
            throw std::runtime_error("Unable to initialize secure NTL randomness");
        return true;
    }();
    (void)sodiumReady;

    static thread_local const bool seeded = []
    {
        std::array<unsigned char, 32> seed{};
        randombytes_buf(seed.data(), seed.size());
        try
        {
            NTL::SetSeed(seed.data(), static_cast<long>(seed.size()));
        }
        catch (...)
        {
            sodium_memzero(seed.data(), seed.size());
            throw;
        }
        sodium_memzero(seed.data(), seed.size());
        return true;
    }();
    (void)seeded;
}

}
