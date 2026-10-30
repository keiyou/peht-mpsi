#pragma once

#include <cstddef>
#include <cstdint>
#include <sodium.h>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

namespace benchmark_thresholds
{
using Threshold = std::uint64_t;

inline void ensureSecureRandomness()
{
    static const int initializationResult = sodium_init();
    if (initializationResult < 0)
        throw std::runtime_error("Unable to initialize secure threshold randomness");
}

inline Threshold secureRandomBelow(Threshold upperBound)
{
    if (upperBound == 0)
        throw std::invalid_argument("Random upper bound must be positive");

    ensureSecureRandomness();
    const Threshold rejectionThreshold = (Threshold{0} - upperBound) % upperBound;
    Threshold value;
    do
    {
        randombytes_buf(&value, sizeof(value));
    } while (value < rejectionThreshold);
    return value % upperBound;
}

template <typename T>
inline void secureShuffle(std::vector<T> &values)
{
    for (std::size_t remaining = values.size(); remaining > 1; --remaining)
    {
        const std::size_t selected = static_cast<std::size_t>(
            secureRandomBelow(static_cast<Threshold>(remaining)));
        std::swap(values[remaining - 1], values[selected]);
    }
}

// even spread, then shuffle
inline std::vector<Threshold> generateBalanced(
    std::size_t elementCount,
    Threshold numParties)
{
    if (numParties < 2)
        throw std::invalid_argument("numParties must be at least 2");

    const std::size_t levelCount = static_cast<std::size_t>(numParties - 1);
    const std::size_t copiesPerLevel = elementCount / levelCount;
    const std::size_t remainder = elementCount % levelCount;

    std::vector<Threshold> thresholds;
    thresholds.reserve(elementCount);

    std::vector<Threshold> levels;
    levels.reserve(levelCount);
    for (Threshold value = 2; value <= numParties; ++value)
    {
        levels.push_back(value);
        thresholds.insert(thresholds.end(), copiesPerLevel, value);
    }

    if (remainder != 0)
    {
        secureShuffle(levels);
        thresholds.insert(thresholds.end(), levels.begin(), levels.begin() + remainder);
    }
    secureShuffle(thresholds);
    return thresholds;
}

// duplicates share a threshold
inline std::vector<Threshold> generateBalancedForElementIds(
    const std::vector<Threshold> &elementIds,
    Threshold numParties)
{
    std::unordered_map<Threshold, std::size_t> uniqueIndex;
    uniqueIndex.reserve(elementIds.size());

    std::vector<std::size_t> inputToUnique;
    inputToUnique.reserve(elementIds.size());
    for (const Threshold elementId : elementIds)
    {
        auto it = uniqueIndex.find(elementId);
        if (it == uniqueIndex.end())
        {
            const std::size_t nextIndex = uniqueIndex.size();
            it = uniqueIndex.emplace(elementId, nextIndex).first;
        }
        inputToUnique.push_back(it->second);
    }

    const auto uniqueThresholds = generateBalanced(uniqueIndex.size(), numParties);
    std::vector<Threshold> thresholds(elementIds.size());
    for (std::size_t i = 0; i < inputToUnique.size(); ++i)
        thresholds[i] = uniqueThresholds[inputToUnique[i]];
    return thresholds;
}
}
