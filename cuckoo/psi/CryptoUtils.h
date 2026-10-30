#pragma once

#include <algorithm>
#include <array>
#include <string>
#include <vector>
#include <helib/helib.h>
#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include "Defines.h"

struct Param
{
    u64 n;
    u64 bits;
    u64 ring_dim;
};

[[nodiscard]] inline bool get_params(u64 n, bool traceable, u64 &bits, u64 &ring_dim)
{
    // memory-capped params
    static constexpr std::array<Param, 35> nonTraceableTable{{
        {4, 63, 8191},
        {5, 81, 8191},
        {6, 108, 8191},
        {7, 128, 16383},
        {8, 162, 16383},
        {9, 185, 32767},
        {10, 224, 32767},
        {11, 246, 32767},
        {12, 285, 32767},
        {13, 315, 32767},
        {14, 353, 32767},
        {15, 392, 32767},
        {16, 434, 32767},
        {17, 486, 65535},
        {18, 533, 69905},
        {19, 581, 69905},
        {20, 631, 69905},
        {21, 688, 42799},
        {22, 745, 69905},
        {23, 800, 69905},
        {24, 860, 55831},
        {25, 919, 60787},
        {26, 977, 60787},
        {27, 1028, 109655},
        {28, 1059, 143395},
        {29, 1165, 143395},
        {30, 1239, 143395},
        {31, 1272, 209715},
        {32, 1334, 209715},
        {33, 1412, 209715},
        {34, 1496, 209715},
        {35, 1571, 209715},
        {36, 1647, 197379},
        {37, 1755, 215265},
        {38, 1842, 215265},
    }};

    // traceable stops at 36
    static constexpr std::array<Param, 33> traceableTable{{
        {4, 63, 8191},
        {5, 81, 8191},
        {6, 108, 8191},
        {7, 128, 16383},
        {8, 162, 16383},
        {9, 185, 32767},
        {10, 224, 32767},
        {11, 246, 32767},
        {12, 285, 32767},
        {13, 315, 32767},
        {14, 353, 32767},
        {15, 392, 32767},
        {16, 434, 32767},
        {17, 486, 65535},
        {18, 533, 69905},
        {19, 581, 69905},
        {20, 631, 69905},
        {21, 688, 42799},
        {22, 745, 69905},
        {23, 800, 69905},
        {24, 860, 55831},
        {25, 919, 60787},
        {26, 977, 60787},
        {27, 1028, 109655},
        {28, 1099, 209715},
        {29, 1157, 209715},
        {30, 1235, 209715},
        {31, 1294, 209715},
        {32, 1388, 209715},
        {33, 1446, 209715},
        {34, 1529, 209715},
        {35, 1647, 215265},
        {36, 1677, 197379},
    }};

    const auto find_param = [n, &bits, &ring_dim](const auto &table) {
        const auto it = std::lower_bound(
            table.begin(), table.end(), n,
            [](const Param &p, u64 val)
            { return p.n < val; });

        if (it == table.end() || it->n != n)
            return false;

        bits = it->bits;
        ring_dim = it->ring_dim;
        return true;
    };

    return traceable ? find_param(traceableTable) : find_param(nonTraceableTable);
}

void InitializeCryptoContext(
    CryptoContext &cc,
    u64 n,
    bool traceable);

std::vector<KeyPair> GenerateKeyPairs(
    CryptoContext &cc,
    size_t numParties);

void SaveCryptoContext(
    const CryptoContext &cc,
    const std::string &filename);

void SaveKeyPair(
    const KeyPair &keyPair,
    const std::string &secretKeyFile,
    const std::string &publicKeyFile);

CryptoContext LoadCryptoContext(const std::string &filename);

KeyPair LoadKeyPair(
    const CryptoContext &cc,
    const std::string &secretKeyFile,
    const std::string &publicKeyFile);
