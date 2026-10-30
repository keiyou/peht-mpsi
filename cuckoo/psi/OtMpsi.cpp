#include "OtMpsi.h"
#include "Logger.h"
#include "Defines.h"
#include "cryptoTools/Common/CuckooIndex.h"
#include "volePSI/SimpleIndex.h"
#include "CryptoUtils.h"
#include "SecureRandom.h"
#include "../../SecureNtlRandom.h"

#include <filesystem>
#include <coproto/coproto.h>
#include <sstream>
#include <coroutine>
#include <chrono>
#include <helib/EncryptedArray.h>
#include <helib/DoubleCRT.h>

inline void SerializeToString(const Ciphertext &ct, std::string &out)
{
    std::ostringstream oss(std::ios::binary);
    ct.writeTo(oss);
    out = oss.str();
}

inline void DeserializeFromString(const std::string &in, Ciphertext &ct, const PubKey &pk)
{
    std::istringstream iss(in, std::ios::binary);
    ct = helib::Ctxt::readFrom(iss, *pk);
}

inline void SerializeToString(const DoubleCRT &dcrt, std::string &out)
{
    std::ostringstream oss(std::ios::out | std::ios::binary);
    dcrt.writeTo(oss);
    out = oss.str();
}

inline void DeserializeFromString(const std::string &in, DoubleCRT &dcrt, const CryptoContext &cc)
{
    std::istringstream iss(in, std::ios::in | std::ios::binary);
    dcrt = helib::DoubleCRT::readFrom(iss, *cc);
}

void OtMpPsiBase::init(u64 numberOfParties,
                       u64 threshold,
                       u64 partyID,
                       u64 senderSize,
                       u64 recverSize,
                       u64 statSecParam,
                       bool traceable,
                       bool debug)
{
    u64 parameterBits = 0;
    u64 parameterRingDimension = 0;
    if (!get_params(numberOfParties, traceable, parameterBits, parameterRingDimension))
        throw std::invalid_argument("No cryptographic parameters for numParties and mode");
    if (threshold == 1 || threshold > numberOfParties)
        throw std::invalid_argument("threshold must be 0 or in [2, numParties]");

    secure_ntl_random::seedCurrentThread();

    mNumberOfParties = numberOfParties;
    mThreshold = threshold;
    mPartyID = partyID;
    mSenderSize = senderSize;
    mRecverSize = recverSize;
    mSsp = statSecParam;

    mDebug = debug;
    mTraceable = traceable;

    InitializeCrypto(numberOfParties, traceable);
}

Proto OtMpPsiMember::Run(span<block> inputs,
                         std::vector<Socket> &chls,
                         bool traceableFlag)
{
    secure_ntl_random::seedCurrentThread();
    Logger &logger = Logger::getInstance();

    auto recvStrings = [&](std::vector<std::string> &buf, size_t chIdx)
    {
        for (auto &s : buf)
            coproto::sync_wait(chls[chIdx].recvResize(s));
    };

    auto deserializeBatch = [&](const std::vector<std::string> &ser,
                                std::vector<Ciphertext> &out)
    {
        out.clear();
        out.reserve(ser.size());
        for (const auto &s : ser)
        {
            Ciphertext ct(*mKeyPair.second);
            DeserializeFromString(s, ct, mKeyPair.second);
            out.emplace_back(std::move(ct));
        }
    };

    auto serializeAndSend = [&](auto &objs, size_t chIdx)
    {
        std::string tmp;
        for (auto &o : objs)
        {
            tmp.clear();
            SerializeToString(o, tmp);
            coproto::sync_wait(chls[chIdx].send(tmp));
        }
    };

    auto partialDecryptBatch = [&](const std::vector<Ciphertext> &in,
                                   std::vector<DoubleCRT> &out)
    {
        out.clear();
        out.reserve(in.size());
        for (const auto &ct : in)
        {
            DoubleCRT share(*mCc, ct.getPrimeSet());
            mKeyPair.first->PartialDecrypt(share, ct);
            out.emplace_back(std::move(share));
        }
    };

    auto makeZeroPlain = [&]()
    {
        Plaintext zero(*mCc);
        const size_t cap = mCc->getEA().size();
        for (size_t i = 0; i < cap; ++i)
            zero[i] = 0;
        return zero;
    };

    auto encZeroBatch = [&](size_t n, const Plaintext &zeroPt,
                            std::vector<Ciphertext> &out)
    {
        out.clear();
        out.reserve(n);
        for (size_t i = 0; i < n; ++i)
        {
            Ciphertext z(*mKeyPair.second);
            mKeyPair.second->Encrypt(z, zeroPt);
            out.emplace_back(std::move(z));
        }
    };

    setTimePoint("OtMpPsiMember::Run - started");
    logger.log("[Member (", mPartyID, ")] started Run()");

    SenderSharing sharing;
    const u64 valueByteLength = 0;

    {
        auto cpsi = std::make_unique<RsCpsiSender>();
        cpsi->init(mRecverSize, mSenderSize, valueByteLength, mSsp,
                   protocol_randomness::freshBlock(), mNumThreads);
        coproto::sync_wait(cpsi->send(oc::span<oc::block>(inputs), oc::MatrixView<u8>(), sharing, chls[0]));
    }

    setTimePoint("OtMpPsiMember::Run - CPSI completed");
    logger.log("[Member (", mPartyID, ")] has completed the CPSI phase with the leader");

    const u64 numBins = sharing.mFlagBits.size();
    const u64 packingCapacity = mCc->getEA().size();
    const u64 numPacks = (numBins + packingCapacity - 1) / packingCapacity;

    std::vector<Plaintext> ptVec;
    ptVec.reserve(numPacks);
    {
        Plaintext pt(*mCc);
        u64 idx = 0;
        for (u64 i = 0; i < numBins; ++i)
        {
            // non-match=1, match=-2
            pt[idx++] = sharing.mFlagBits[i] ? 1 : -2;
            if (idx == packingCapacity || i == numBins - 1)
            {
                ptVec.emplace_back(std::move(pt));
                pt = Plaintext(*mCc);
                idx = 0;
            }
        }
    }

    setTimePoint("OtMpPsiMember::Run - CPSI result processing completed");
    logger.log("[Member (", mPartyID, ")] has completed the CPSI result processing");

    std::vector<Ciphertext> encZero;
    const Plaintext zeroPt = makeZeroPlain();
    encZeroBatch(numPacks, zeroPt, encZero);

    setTimePoint("OtMpPsiMember::Run - prepared ciphertexts for rerandomization");
    logger.log("[Member (", mPartyID, ")] has prepared ciphertexts for rerandomization");

    for (u64 packIdx = 0; packIdx < numPacks; ++packIdx)
    {
        std::string s;
        Ciphertext incoming(*mKeyPair.second);
        const size_t prevCh = (mPartyID == 0) ? 0 : 1;
        coproto::sync_wait(chls[prevCh].recvResize(s));
        DeserializeFromString(s, incoming, mKeyPair.second);

        Ciphertext leaderCt(*mKeyPair.second);
        coproto::sync_wait(chls[0].recvResize(s));
        DeserializeFromString(s, leaderCt, mKeyPair.second);

        incoming.multByConstant(ptVec[packIdx]);
        incoming.addCtxt(leaderCt);
        incoming.addCtxt(encZero[packIdx]);

        s.clear();
        SerializeToString(incoming, s);
        coproto::sync_wait(chls[0].send(s));
        if (mPartyID != mNumberOfParties - 2)
        {
            coproto::sync_wait(chls[2].send(s));
        }
    }

    setTimePoint("OtMpPsiMember::Run - voting phase completed");
    logger.log("[Member (", mPartyID, ")] has completed the voting phase");

    if (!traceableFlag)
    {
        std::vector<std::string> serIn(numPacks);
        std::vector<Ciphertext> ctIn;
        ctIn.reserve(numPacks);
        std::vector<DoubleCRT> shares;
        shares.reserve(numPacks);

        recvStrings(serIn, 0);
        deserializeBatch(serIn, ctIn);

        setTimePoint("OtMpPsiMember::Run - collaborative decryption: ciphertext received from leader");
        logger.log("[Member (", mPartyID, ")] has received ciphertext from the leader for collaborative decryption");

        partialDecryptBatch(ctIn, shares);

        setTimePoint("OtMpPsiMember::Run - collaborative decryption: partial decryption completed");
        logger.log("[Member (", mPartyID, ")] has completed partial decryption for collaborative decryption");

        serializeAndSend(shares, 0);

        setTimePoint("OtMpPsiMember::Run - collaborative decryption: decryption shares sent to leader");
        logger.log("[Member (", mPartyID, ")] has sent decryption shares to the leader for collaborative decryption");
    }
    else
    {
        std::vector<Ciphertext> randZero;
        encZeroBatch(numPacks, zeroPt, randZero);

        std::vector<Plaintext> ptVec;
        ptVec.reserve(numPacks);
        {
            Plaintext pt(*mCc);
            u64 idx = 0;
            for (u64 i = 0; i < numBins; ++i)
            {
                pt[idx++] = sharing.mFlagBits[i];
                if (idx == packingCapacity || i == numBins - 1)
                {
                    ptVec.emplace_back(std::move(pt));
                    pt = Plaintext(*mCc);
                    idx = 0;
                }
            }
        }

        {
            std::vector<std::string> serFirst(numPacks);
            std::vector<Ciphertext> ctFirst;
            ctFirst.reserve(numPacks);

            recvStrings(serFirst, 0);
            deserializeBatch(serFirst, ctFirst);

            for (size_t i = 0; i < numPacks; ++i)
            {
                ctFirst[i].multByConstant(ptVec[i]);
                ctFirst[i].addCtxt(randZero[i]);
            }
            serializeAndSend(ctFirst, 0);
        }

        const size_t numRounds = mNumberOfParties - 1;
        std::vector<std::string> serRound(numPacks);
        std::vector<std::vector<Ciphertext>> allCtRounds(numRounds);
        std::vector<DoubleCRT> shares;

        for (size_t round = 0; round < numRounds; ++round)
        {
            recvStrings(serRound, 0);
            deserializeBatch(serRound, allCtRounds[round]);
        }

        for (size_t round = 0; round < numRounds; ++round)
        {
            partialDecryptBatch(allCtRounds[round], shares);
            serializeAndSend(shares, 0);
            logger.log("[Member (", mPartyID, ")] completed round ", round, " of multiparty decryption (traceable).");
        }
    }

    co_return;
}

void OtMpPsiMember::InitializeCrypto(u64 n, bool traceable)
{
    Logger &logger = Logger::getInstance();
    namespace fs = std::filesystem;

    const fs::path keysDir = fs::path("keys");
    const fs::path ready = keysDir / "keys_ready.txt";
    const fs::path ctxFile = keysDir / "CryptoContext.bin";

    while (!fs::exists(ready))
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    mCc = std::move(LoadCryptoContext(ctxFile.string()));

    const fs::path skFile = keysDir / ("SecretKey_Party" + std::to_string(mPartyID) + ".bin");
    const fs::path pkFile = keysDir / ("PublicKey_Party" + std::to_string(mPartyID) + ".bin");

    while (!fs::exists(skFile) || !fs::exists(pkFile))
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    mKeyPair = std::move(LoadKeyPair(mCc, skFile.string(), pkFile.string()));

    logger.log("[Member (", mPartyID, ")] loaded keys for n=", n, " mode=",
               (traceable ? "traceable" : "non-traceable"), " from ", keysDir.string());
}

void OtMpPsiMember::Sync(std::vector<Socket> &chls)
{
    std::string dummy;
    chls[0].recvResize(dummy);
}

Proto OtMpPsiLeader::Run(span<block> inputs,
                         const std::vector<u64> &inputThresholds,
                         std::vector<Socket> &chls,
                         bool traceableFlag)
{
    secure_ntl_random::seedCurrentThread();
    Logger &logger = Logger::getInstance();

    if (mThreshold == 0)
    {
        if (inputThresholds.size() != inputs.size())
            throw std::invalid_argument("Per-element mode requires one threshold per leader input");
        for (const u64 threshold : inputThresholds)
        {
            if (threshold < 2 || threshold > mNumberOfParties)
                throw std::invalid_argument("Each element threshold must be in [2, numParties]");
        }
    }
    else if (!inputThresholds.empty())
        throw std::invalid_argument("A threshold vector is only valid when threshold mode is 0");
    if (inputs.empty())
        throw std::invalid_argument("Leader input set must not be empty");
    if (chls.size() != mNumberOfParties - 1)
        throw std::invalid_argument("Leader requires exactly numParties - 1 member channels");

    const u64 numMembers = chls.size();
    std::vector<ReceiverSharing> sharingVec(numMembers);
    const u64 valueByteLength = 0;

    std::vector<std::thread> pThreads;
    pThreads.reserve(numMembers);

    setTimePoint("OtMpPsiLeader::Run - start");
    logger.log("[Leader] Run() has started");

    auto parallel_for = [&](size_t nThreads, auto &&fn)
    {
        std::vector<std::thread> ts;
        ts.reserve(nThreads);
        for (size_t t = 0; t < nThreads; ++t)
            ts.emplace_back([&, t]
                            { fn(t); });
        for (auto &th : ts)
            if (th.joinable())
                th.join();
    };

    auto broadcastToAllMembers = [&](const std::vector<std::string> &ser)
    {
        parallel_for(numMembers, [&](size_t memberIdx)
                     {
            for (const auto& s : ser) coproto::sync_wait(chls[memberIdx].send(s)); });
    };

    auto serializeBatch = [&](const std::vector<Ciphertext> &C, std::vector<std::string> &out)
    {
        out.resize(C.size());
        for (size_t i = 0; i < C.size(); ++i)
            SerializeToString(C[i], out[i]);
    };

    auto encryptBatch = [&](const std::vector<Plaintext> &plaintexts,
                            std::vector<Ciphertext> &ciphertexts)
    {
        ciphertexts.clear();
        ciphertexts.resize(plaintexts.size(), Ciphertext(*mKeyPair.second));
        const size_t nThreads = std::min<size_t>(numMembers, plaintexts.size());
        parallel_for(nThreads, [&](size_t tid)
                     {
            secure_ntl_random::seedCurrentThread();
            for (size_t i = tid; i < plaintexts.size(); i += nThreads) {
                Ciphertext c(*mKeyPair.second);
                mKeyPair.second->Encrypt(c, plaintexts[i]);
                ciphertexts[i] = std::move(c);
            } });
    };

    auto encryptBatchSamePt = [&](const Plaintext &plaintext,
                                  size_t count,
                                  std::vector<Ciphertext> &ciphertexts)
    {
        ciphertexts.clear();
        ciphertexts.resize(count, Ciphertext(*mKeyPair.second));
        const size_t nThreads = std::min<size_t>(numMembers, count);
        parallel_for(nThreads, [&](size_t tid)
                     {
            secure_ntl_random::seedCurrentThread();
            for (size_t i = tid; i < count; i += nThreads) {
                Ciphertext c(*mKeyPair.second);
                mKeyPair.second->Encrypt(c, plaintext);
                ciphertexts[i] = std::move(c);
            } });
    };

    auto makeZeroPlain = [&]()
    {
        Plaintext zero(*mCc);
        const u64 cap = mCc->getEA().size();
        for (u64 i = 0; i < cap; ++i)
            zero[i] = 0;
        return zero;
    };

    auto encZeroBatch = [&](size_t n, const Plaintext &zeroPt, std::vector<Ciphertext> &out)
    {
        out.clear();
        out.reserve(n);
        for (size_t i = 0; i < n; ++i)
        {
            Ciphertext z(*mKeyPair.second);
            mKeyPair.second->Encrypt(z, zeroPt);
            out.emplace_back(std::move(z));
        }
    };

    auto leaderPartialDecrypt = [&](const std::vector<Ciphertext> &C,
                                    std::vector<std::vector<DoubleCRT>> &shares)
    {
        const size_t nThreads = std::min<u64>(numMembers, C.size());
        parallel_for(nThreads, [&](size_t tid)
                     {
            secure_ntl_random::seedCurrentThread();
            for (size_t i = tid; i < C.size(); i += nThreads) {
                mKeyPair.first->PartialDecrypt(shares[i].back(), C[i]);
            } });
    };

    auto gatherMemberShares = [&](std::vector<std::vector<DoubleCRT>> &shares)
    {
        parallel_for(numMembers, [&](size_t memberIdx)
                     {
            std::string s;
            for (size_t packIdx = 0; packIdx < shares.size(); ++packIdx) {
                coproto::sync_wait(chls[memberIdx].recvResize(s));
                DeserializeFromString(s, shares[packIdx][memberIdx], mCc);
            } });
    };

    {
        auto cpsiVec = std::vector<std::unique_ptr<RsCpsiReceiver>>(numMembers);
        const block layoutSeed = protocol_randomness::freshBlock();
        for (u64 i = 0; i < numMembers; ++i)
        {
            cpsiVec[i] = std::make_unique<RsCpsiReceiver>();

            // same layout, fresh private rng
            cpsiVec[i]->init(mSenderSize, mRecverSize, valueByteLength, mSsp,
                             protocol_randomness::freshBlock(), mNumThreads);
            cpsiVec[i]->setCuckooSeed(layoutSeed);
        }

        pThreads.clear();
        for (u64 i = 0; i < numMembers; ++i)
        {
            pThreads.emplace_back([&, i]
                                  { coproto::sync_wait(cpsiVec[i]->receive(oc::span<oc::block>(inputs), sharingVec[i], chls[i])); });
        }
        for (auto &th : pThreads)
            if (th.joinable())
                th.join();
    }

    setTimePoint("OtMpPsiLeader::Run - CPSI with all members completed");
    logger.log("[Leader] has completed the CPSI phase with all members");

    const u64 numBins = sharingVec[0].mFlagBits.size();
    const u64 packingCapacity = mCc->getEA().size();
    const u64 numPacks = (numBins + packingCapacity - 1) / packingCapacity;

    // sessions need the same slots
    for (u64 memberIdx = 0; memberIdx < numMembers; ++memberIdx)
    {
        if (sharingVec[memberIdx].mFlagBits.size() != numBins ||
            sharingVec[memberIdx].mMapping.size() != inputs.size())
            throw std::runtime_error("CPSI returned an unexpected output shape");
        if (sharingVec[memberIdx].mMapping != sharingVec[0].mMapping)
            throw std::runtime_error("CPSI sessions produced inconsistent cuckoo-bin mappings");
    }

    std::vector<u64> thresholdByBin;
    if (mThreshold == 0)
    {
        // empty slots just use n
        thresholdByBin.assign(numBins, mNumberOfParties);
        std::vector<bool> assignedThreshold(numBins, false);
        for (u64 inputIdx = 0; inputIdx < inputs.size(); ++inputIdx)
        {
            const u64 binIdx = sharingVec[0].mMapping[inputIdx];
            if (binIdx == ~u64(0) || binIdx >= numBins)
                throw std::runtime_error("CPSI failed to map a leader input to a cuckoo bin");
            if (assignedThreshold[binIdx])
                throw std::runtime_error("Multiple leader inputs mapped to one cuckoo bin");
            thresholdByBin[binIdx] = inputThresholds[inputIdx];
            assignedThreshold[binIdx] = true;
        }
    }

    logger.log("[Leader] Packing parameters | numBins=", numBins,
               ", packingCapacity=", packingCapacity, ", numPacks=", numPacks);

    std::vector<std::vector<Plaintext>> sharesVec;
    sharesVec.reserve(numMembers);

    for (u64 i = 0; i < numMembers; ++i)
    {
        std::vector<Plaintext> ptVec;
        ptVec.reserve(numPacks);
        Plaintext pt(*mCc);
        u64 idx = 0;
        for (u64 j = 0; j < numBins; ++j)
        {
            pt[idx++] = sharingVec[i].mFlagBits[j];
            if (idx == packingCapacity || j == numBins - 1)
            {
                ptVec.emplace_back(std::move(pt));
                pt = Plaintext(*mCc);
                idx = 0;
            }
        }
        sharesVec.emplace_back(std::move(ptVec));
        sharingVec[i].mFlagBits.reset();
        sharingVec[i].mValues.resize(0, 0);
    }

    setTimePoint("OtMpPsiLeader::Run - CPSI outputs from all members processed");
    logger.log("[Leader] has processed CPSI outputs from all members");

    std::vector<std::vector<Ciphertext>> zeroCtsVec(numMembers);
    {
        Plaintext zeroPt = makeZeroPlain();
        pThreads.clear();
        for (u64 t = 0; t < numMembers; ++t)
        {
            pThreads.emplace_back([&, t]
                                  {
                secure_ntl_random::seedCurrentThread();
                std::vector<Ciphertext> zeroCts;
                encZeroBatch(numPacks, zeroPt, zeroCts);
                zeroCtsVec[t] = std::move(zeroCts); });
        }
        for (auto &th : pThreads)
            if (th.joinable())
                th.join();
    }

    setTimePoint("OtMpPsiLeader::Run - ciphertexts prepared for rerandomization");
    logger.log("[Leader] has prepared ciphertexts for rerandomization");

    // base = 2^(t - 1)
    std::vector<Ciphertext> ctVec;
    if (mThreshold != 0)
    {
        Plaintext votePt(*mCc);
        const u64 base = 1ULL << (mThreshold - 1);
        for (u64 slotIdx = 0; slotIdx < packingCapacity; ++slotIdx)
            votePt[slotIdx] = base;
        encryptBatchSamePt(votePt, numPacks, ctVec);
    }
    else
    {
        std::vector<Plaintext> votePtVec;
        votePtVec.reserve(numPacks);
        {
            Plaintext votePt(*mCc);
            u64 slotIdx = 0;
            for (u64 binIdx = 0; binIdx < numBins; ++binIdx)
            {
                votePt[slotIdx++] = 1ULL << (thresholdByBin[binIdx] - 1);
                if (slotIdx == packingCapacity || binIdx == numBins - 1)
                {
                    votePtVec.emplace_back(std::move(votePt));
                    votePt = Plaintext(*mCc);
                    slotIdx = 0;
                }
            }
        }
        encryptBatch(votePtVec, ctVec);
    }

    setTimePoint("OtMpPsiLeader::Run - ciphertexts prepared for voting");
    logger.log("[Leader] has prepared ciphertexts for voting");

    // send it around the ring
    {
        pThreads.clear();

        pThreads.emplace_back([&]
                              {
            std::string s;
            for (u64 packIdx = 0; packIdx < numPacks; ++packIdx) {
                s.clear();
                SerializeToString(ctVec[packIdx], s);
                coproto::sync_wait(chls[0].send(s));

                Ciphertext temp = ctVec[packIdx];
                temp.multByConstant(sharesVec[0][packIdx]);
                temp.addCtxt(zeroCtsVec[0][packIdx]);
                s.clear();
                SerializeToString(temp, s);
                coproto::sync_wait(chls[0].send(s));
            } });

        for (u64 memberIdx = 0; memberIdx < numMembers - 1; ++memberIdx)
        {
            pThreads.emplace_back([&, memberIdx]
                                  {
                std::string s;
                Ciphertext temp(*mKeyPair.second);
                for (u64 packIdx = 0; packIdx < numPacks; ++packIdx) {
                    coproto::sync_wait(chls[memberIdx].recvResize(s));
                    DeserializeFromString(s, temp, mKeyPair.second);

                    temp.multByConstant(sharesVec[memberIdx + 1][packIdx]);
                    temp.addCtxt(zeroCtsVec[memberIdx + 1][packIdx]);

                    s.clear();
                    SerializeToString(temp, s);
                    coproto::sync_wait(chls[memberIdx + 1].send(s));
                } });
        }

        pThreads.emplace_back([&]
                              {
            std::string s;
            for (u64 packIdx = 0; packIdx < numPacks; ++packIdx) {
                coproto::sync_wait(chls[numMembers - 1].recvResize(s));
                DeserializeFromString(s, ctVec[packIdx], mKeyPair.second);
            } });

        for (auto &th : pThreads)
            if (th.joinable())
                th.join();
    }

    setTimePoint("OtMpPsiLeader::Run - voting phase completed");
    logger.log("[Leader] has completed the voting phase");

    if (!traceableFlag)
    {
        std::vector<std::string> ser;
        serializeBatch(ctVec, ser);
        broadcastToAllMembers(ser);

        setTimePoint("OtMpPsiLeader::Run - ciphertexts sent to all members for collaborative decryption");
        logger.log("[Leader] has sent ciphertexts to all members for collaborative decryption");

        std::vector<std::vector<DoubleCRT>> partialDecryptions(
            numPacks, std::vector<DoubleCRT>(mNumberOfParties, DoubleCRT(*mCc, ctVec[0].getPrimeSet())));

        leaderPartialDecrypt(ctVec, partialDecryptions);
        setTimePoint("OtMpPsiLeader::Run - collaborative decryption: partial decryption completed");
        logger.log("[Leader] has completed partial decryption for collaborative decryption");

        gatherMemberShares(partialDecryptions);
        setTimePoint("OtMpPsiLeader::Run - collaborative decryption: partial decryptions received from all members");
        logger.log("[Leader] has received partial decryptions from all members for collaborative decryption");

        std::vector<Plaintext> ptVec(numPacks, Plaintext(*mCc));
        const size_t fuseThreads = numMembers;
        parallel_for(std::min<size_t>(fuseThreads, numPacks), [&](size_t tid)
                     {
            const size_t step = std::min<size_t>(fuseThreads, numPacks);
            for (size_t i = tid; i < numPacks; i += step) {
                mKeyPair.first->DecryptFusion(ptVec[i], ctVec[i], partialDecryptions[i]);
            } });

        setTimePoint("OtMpPsiLeader::Run - collaborative decryption: fusion completed");
        logger.log("[Leader] has completed decryption fusion for collaborative decryption");

        std::vector<u64> intersectionCount(numBins, 0);
        const u64 plaintextModulus = static_cast<u64>(mKeyPair.second->getPtxtSpace());

        for (u64 i = 0; i < inputs.size(); ++i)
        {
            u64 binIdx = sharingVec[0].mMapping[i];
            if (binIdx != ~u64(0))
            {
                const u64 packIndex = binIdx / packingCapacity;
                const u64 ptIndex = binIdx % packingCapacity;
                u64 val = static_cast<u64>(long(ptVec[packIndex][ptIndex]));
                if (val != 0)
                {
                    const u64 elementThreshold =
                        (mThreshold == 0) ? thresholdByBin[binIdx] : mThreshold;
                    const u64 maxShifts = mNumberOfParties - elementThreshold + 1;
                    u64 shifts = 0;
                    while (val % plaintextModulus != 0 && shifts < maxShifts)
                    {
                        val <<= 1;
                        ++shifts;
                    }
                    if (val % plaintextModulus != 0 || shifts == 0)
                        throw std::runtime_error("Invalid decrypted tally encoding");
                    intersectionCount[binIdx] = shifts + elementThreshold - 1;
                }
            }
        }

        if (mDebug)
        {
            int cnt = 0;
            for (u64 i = 0; i < numBins; ++i)
                if (intersectionCount[i] != 0)
                    ++cnt;
            logger.log("[Leader] Intersection results | elements found = ", cnt);
        }
        logger.log(getTimer());
    }
    else
    {
        // mask and decrypt each round
        {
            Plaintext zeroPt = makeZeroPlain();
            pThreads.clear();
            for (u64 t = 0; t < numMembers; ++t)
            {
                pThreads.emplace_back([&, t]
                                      {
                    secure_ntl_random::seedCurrentThread();
                    std::vector<Ciphertext> zeroCts;
                    encZeroBatch(numPacks, zeroPt, zeroCts);
                    zeroCtsVec[t] = std::move(zeroCts); });
            }
            for (auto &th : pThreads)
                if (th.joinable())
                    th.join();
        }

        std::vector<std::string> initSer;
        serializeBatch(ctVec, initSer);
        broadcastToAllMembers(initSer);

        std::vector<std::vector<Ciphertext>> tracableCiphertexts(
            numMembers, std::vector<Ciphertext>(numPacks, Ciphertext(*mKeyPair.second)));
        parallel_for(numMembers, [&](size_t memberIdx)
                     {
            std::string s;
            for (size_t packIdx = 0; packIdx < numPacks; ++packIdx) {
                coproto::sync_wait(chls[memberIdx].recvResize(s));
                DeserializeFromString(s, tracableCiphertexts[memberIdx][packIdx], mKeyPair.second);
            } });

        std::vector<std::vector<u64>> tracable(numBins);

        for (size_t round = 0; round < numMembers; ++round)
        {
            for (size_t i = 0; i < numPacks; ++i)
            {
                Ciphertext temp = ctVec[i];
                temp.multByConstant(sharesVec[round][i]);
                temp.negate();
                tracableCiphertexts[round][i].addCtxt(temp);
                tracableCiphertexts[round][i].addCtxt(zeroCtsVec[round][i]);
            }
        }

        {
            std::vector<std::string> allSer;
            allSer.reserve(numMembers * numPacks);
            for (size_t round = 0; round < numMembers; ++round)
            {
                std::vector<std::string> roundSer;
                serializeBatch(tracableCiphertexts[round], roundSer);
                allSer.insert(allSer.end(),
                              std::make_move_iterator(roundSer.begin()),
                              std::make_move_iterator(roundSer.end()));
            }
            broadcastToAllMembers(allSer);
        }

        std::vector<std::vector<std::vector<DoubleCRT>>> allShares(numMembers);
        for (size_t round = 0; round < numMembers; ++round)
        {
            allShares[round].resize(
                numPacks, std::vector<DoubleCRT>(mNumberOfParties,
                    DoubleCRT(*mCc, tracableCiphertexts[round][0].getPrimeSet())));
            leaderPartialDecrypt(tracableCiphertexts[round], allShares[round]);
        }

        parallel_for(numMembers, [&](size_t memberIdx)
                     {
            std::string s;
            for (size_t round = 0; round < numMembers; ++round) {
                for (size_t packIdx = 0; packIdx < numPacks; ++packIdx) {
                    coproto::sync_wait(chls[memberIdx].recvResize(s));
                    DeserializeFromString(s, allShares[round][packIdx][memberIdx], mCc);
                }
            } });

        std::vector<std::vector<Plaintext>> allPt(numMembers);
        for (size_t round = 0; round < numMembers; ++round)
            allPt[round].resize(numPacks, Plaintext(*mCc));

        const size_t totalFusions = numMembers * numPacks;
        parallel_for(std::min<size_t>(numMembers, totalFusions), [&](size_t tid)
                     {
            for (size_t idx = tid; idx < totalFusions; idx += std::min<size_t>(numMembers, totalFusions)) {
                const size_t round = idx / numPacks;
                const size_t packIdx = idx % numPacks;
                mKeyPair.first->DecryptFusion(allPt[round][packIdx], tracableCiphertexts[round][packIdx], allShares[round][packIdx]);
            } });

        for (size_t round = 0; round < numMembers; ++round)
        {
            for (size_t binIdx = 0; binIdx < numBins; ++binIdx)
            {
                const u64 packIndex = binIdx / packingCapacity;
                const u64 ptIndex = binIdx % packingCapacity;
                const u64 val = static_cast<u64>(long(allPt[round][packIndex][ptIndex]));
                if (val != 0)
                    tracable[binIdx].emplace_back(round);
            }
        }
        logger.log("[Leader] completed multiparty decryption for traceable");
        setTimePoint("OtMpPsiLeader::Run - traceable completed");

        if (mDebug)
        {
            int cnt = 0;
            for (const auto &v : tracable)
                if (!v.empty())
                    ++cnt;
            logger.log("[Leader] Traceable results | elements found = ", cnt);

            for (size_t i = 0; i < tracable.size(); ++i)
            {
                if (i > 255)
                    break;
                if (!tracable[i].empty())
                {
                    std::ostringstream oss;
                    oss << "Element " << i << " trace : ";
                    for (const auto &round : tracable[i])
                        oss << round << " ";
                    logger.log(oss.str());
                }
            }
        }
        logger.log(getTimer());
    }

    co_return;
}

void OtMpPsiLeader::InitializeCrypto(u64 n, bool traceable)
{
    Logger &logger = Logger::getInstance();

    if (mNumberOfParties < 2)
        throw std::invalid_argument("[Leader] mNumberOfParties must be >= 2");
    if (n == 0)
        throw std::invalid_argument("[Leader] ring parameter n must be > 0");

    namespace fs = std::filesystem;
    const fs::path keysDir = fs::path("keys");
    const u64 numParties = mNumberOfParties;
    const u64 leaderIdx = numParties - 1;

    InitializeCryptoContext(mCc, n, traceable);

    logger.log("[Leader] generating keys under: ", keysDir.string(),
               " mode=", (traceable ? "traceable" : "non-traceable"));
    std::vector<KeyPair> keyPairs = GenerateKeyPairs(mCc, numParties);

    SaveCryptoContext(mCc, (keysDir / "CryptoContext.bin").string());

    for (u64 i = 0; i < numParties; ++i)
    {
        const fs::path sk = keysDir / ("SecretKey_Party" + std::to_string(i) + ".bin");
        const fs::path pk = keysDir / ("PublicKey_Party" + std::to_string(i) + ".bin");
        SaveKeyPair(keyPairs[i], sk.string(), pk.string());
    }

    {
        const fs::path sk = keysDir / ("SecretKey_Party" + std::to_string(leaderIdx) + ".bin");
        const fs::path pk = keysDir / ("PublicKey_Party" + std::to_string(leaderIdx) + ".bin");
        SaveKeyPair(keyPairs[leaderIdx], sk.string(), pk.string());
    }

    mKeyPair = std::move(keyPairs[leaderIdx]);

    std::ofstream(keysDir / "keys_ready.txt") << "Keys for n=" << n << " are ready.\n";
    logger.log("[Leader] Generated and saved all key pairs (leader idx = ", leaderIdx, ").");

    if (logger.isEnabled())
    {
        std::ostringstream oss, ctx;
        mCc->printout(ctx);
        oss
            << "  CryptoContext Parameters (HElib)\n"
            << "------------------------------------------------------------\n"
            << ctx.str();
        logger.log(oss.str());
    }

    setTimePoint("OtMpPsiLeader::InitializeCrypto completed");
}

void OtMpPsiLeader::Sync(std::vector<Socket> &chls)
{
    std::vector<std::thread> pThreads;
    pThreads.reserve(mNumberOfParties - 1);
    {
        pThreads.clear();
        for (u64 memberIdx = 0; memberIdx < mNumberOfParties - 1; ++memberIdx)
        {
            std::string dummy = "0";
            pThreads.emplace_back(
                [&, memberIdx]()
                {
                    chls[memberIdx].send(dummy);
                    chls[memberIdx].flush();
                });
        }

        for (auto &th : pThreads)
        {
            if (th.joinable())
                th.join();
        }
    }
}
