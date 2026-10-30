#pragma once

#include "Binarymap.h"
#include <stdexcept>

class Bitmap : public BinaryMapBase
{
public:
    explicit Bitmap(size_t numBits)
        : BinaryMapBase(numBits, Type::Bitmap)
    {
    }

    // low 64 bits are the index
    void add(const block &element) override
    {
        u64 idx;
        memcpy(&idx, &element, sizeof(u64));
        if (idx >= mSize)
            throw std::out_of_range("Bitmap::add: index out of range");
        set(idx);
    }

    void remove(const block &element) override
    {
        u64 idx;
        memcpy(&idx, &element, sizeof(u64));
        if (idx >= mSize)
            throw std::out_of_range("Bitmap::remove: index out of range");
        unset(idx);
    }

    bool contains(const block &element) const override
    {
        u64 idx;
        memcpy(&idx, &element, sizeof(u64));
        if (idx >= mSize)
            return false;
        return (*this)[idx];
    }
};
