#pragma once

#include <vector>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <stdexcept>
#include "Defines.h"

class BinaryMapBase
{
public:
    enum class Type
    {
        Bitmap
    };

    explicit BinaryMapBase(size_t numBits, Type t)
        : mSize(numBits),
          mType(t),
          mData((numBits + BitsPerWord - 1) / BitsPerWord, 0ULL)
    {
    }

    virtual ~BinaryMapBase() = default;

    Type type() const { return mType; }

    virtual void add(const block &element) = 0;
    virtual void remove(const block &element) = 0;
    virtual bool contains(const block &element) const = 0;

    void reset()
    {
        std::fill(mData.begin(), mData.end(), 0ULL);
    }

    size_t size() const { return mSize; }

    size_t count() const
    {
        size_t c = 0;
        for (auto w : mData)
            c += __builtin_popcountll(w);
        return c;
    }

    // keeps [] writable
    class BitReference
    {
    public:
        BitReference(BinaryMapBase &bmp, u64 pos)
            : mBitmap(bmp), mPos(pos)
        {
        }

        operator bool() const
        {
            auto w = mPos / BitsPerWord;
            auto b = mPos % BitsPerWord;
            return (mBitmap.mData[w] >> b) & 1ULL;
        }

        BitReference &operator=(bool v)
        {
            auto w = mPos / BitsPerWord;
            auto b = mPos % BitsPerWord;
            if (v)
                mBitmap.mData[w] |= (1ULL << b);
            else
                mBitmap.mData[w] &= ~(1ULL << b);
            return *this;
        }

        BitReference &operator=(const BitReference &o)
        {
            return *this = static_cast<bool>(o);
        }

    private:
        BinaryMapBase &mBitmap;
        u64 mPos;
    };

    BitReference operator[](u64 pos)
    {
        if (pos >= mSize)
            throw std::out_of_range("index");
        return BitReference(*this, pos);
    }

    bool operator[](u64 pos) const
    {
        if (pos >= mSize)
            throw std::out_of_range("index");
        auto w = pos / BitsPerWord;
        auto b = pos % BitsPerWord;
        return (mData[w] >> b) & 1ULL;
    }

protected:
    size_t mSize;
    Type mType;
    std::vector<u64> mData;
    static constexpr size_t BitsPerWord = 64;

    void set(u64 idx)
    {
        if (idx >= mSize)
            throw std::out_of_range("BinaryMapBase::set: index out of range");
        mData[idx / BitsPerWord] |= (1ULL << (idx % BitsPerWord));
    }

    void unset(u64 idx)
    {
        if (idx >= mSize)
            throw std::out_of_range("BinaryMapBase::unset: index out of range");
        mData[idx / BitsPerWord] &= ~(1ULL << (idx % BitsPerWord));
    }
};
