#pragma once

#include <volePSI/RsOpprf.h>
#include "Defines.h"

struct OtMpPsiBase
{
    u64 mNumberOfParties;
    u64 mThreshold; // 0 = per-item
    u64 mPartyID;
    u64 mSenderSize;
    u64 mRecverSize;
    u64 mValueByteLength = 0;
    u64 mSsp;
    u64 mNumThreads = 1;
    bool mDebug = false;
    bool mTraceable = false;

    u64 mPlaintextModulus;
    CryptoContext mCc;
    KeyPair mKeyPair;

    void init(u64 numberOfParties,
              u64 threshold,
              u64 partyID,
              u64 senderSize,
              u64 recverSize,
              u64 statSecParam,
              bool traceable,
              bool debug);

    std::string getCryptoSecurityLevel() const
    {
        return std::to_string(mCc->securityLevel());
    }

    virtual void InitializeCrypto(u64 n, bool traceable) = 0;
    virtual void Sync(std::vector<Socket> &chls) = 0;
};

class OtMpPsiMember : public OtMpPsiBase, public oc::TimerAdapter
{
public:
    struct Sharing
    {
        oc::BitVector mFlagBits;

        oc::Matrix<u8> mValues;

        // row -> 3 candidates
        std::vector<std::array<u64, 3>> mMapping;
    };

    Proto Run(span<block> inputs, std::vector<Socket> &chls, bool traceableFlag);

    void InitializeCrypto(u64 n, bool traceable) override;
    void Sync(std::vector<Socket> &chls) override;
};

class OtMpPsiLeader : public OtMpPsiBase, public oc::TimerAdapter
{
public:
    struct Sharing
    {
        std::vector<oc::BitVector> mFlagBits;

        std::vector<u64> mMapping;
    };

    Proto Run(span<block> inputs,
              const std::vector<u64> &inputThresholds,
              std::vector<Socket> &chls,
              bool traceableFlag);

    void InitializeCrypto(u64 n, bool traceable) override;
    void Sync(std::vector<Socket> &chls) override;
};
