#include "OtMpsi.h"
#include "Logger.h"
#include "Defines.h"
#include "cryptoTools/Common/CuckooIndex.h"
#include "volePSI/SimpleIndex.h"
#include "CryptoUtils.h"
#include "Binarymap.h"
#include "Bitmap.h"
#include "../../SecureNtlRandom.h"

#include <filesystem>
#include <coproto/coproto.h>
#include <sstream>
#include <coroutine>
#include <chrono>
#include <algorithm>

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

    mDebug = debug;
    mTraceable = traceable;

    InitializeCrypto(numberOfParties, traceable);
}

Proto OtMpPsiMember::Run(span<block> inputs,
                         std::vector<Socket> &chls,
                         BinaryMapBase::Type type,
                         size_t inputBitSize,
                         bool traceableFlag)
{
    secure_ntl_random::seedCurrentThread();
    Logger &logger = Logger::getInstance();
    setTimePoint("OtMpPsiMember::Run begin");
    logger.log("Member ", mPartyID, " begins");

    auto recvStrings = [&](std::vector<std::string> &buf, size_t n, size_t chIdx)
    {
        for (size_t i = 0; i < n; ++i)
            coproto::sync_wait(chls[chIdx].recvResize(buf[i]));
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
        for (size_t i = 0, cap = mCc->getEA().size(); i < cap; ++i)
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

    std::unique_ptr<BinaryMapBase> map;

    if (type == BinaryMapBase::Type::Bitmap)
    {
        map = std::make_unique<Bitmap>((1ULL << inputBitSize));
        for (u64 i = 0; i < inputs.size(); ++i)
            map->add(inputs[i]);
    }
    else
    {
        throw std::invalid_argument("Unsupported BinaryMapBase::Type");
    }

    setTimePoint("OtMpPsiMember::Run converted input set to binary representation.");
    logger.log("Member ", mPartyID, " converted input set to binary representation.");

    const u64 numBins = map->size();
    const size_t packingCap = mCc->getEA().size();
    const u64 numPacks = (numBins + packingCap - 1) / packingCap;

    std::vector<Plaintext> ptVec;
    ptVec.reserve(numPacks);
    {
        Plaintext pt(*mCc);
        u64 idx = 0;
        for (u64 i = 0; i < numBins; ++i)
        {
            pt[idx++] = (*map)[i] ? 1 : 2;
            if (idx == packingCap || i == numBins - 1)
            {
                ptVec.emplace_back(std::move(pt));
                pt = Plaintext(*mCc);
                idx = 0;
            }
        }
    }

    std::vector<Ciphertext> encZero;
    encZero.reserve(numPacks);
    const Plaintext zeroPt = makeZeroPlain();
    encZeroBatch(numPacks, zeroPt, encZero);

    for (size_t packIdx = 0; packIdx < numPacks; ++packIdx)
    {
        std::string ser;
        Ciphertext incoming(*mKeyPair.second);

        const size_t recvCh = (mPartyID == 0) ? 0 : 1;
        coproto::sync_wait(chls[recvCh].recvResize(ser));
        DeserializeFromString(ser, incoming, mKeyPair.second);

        incoming.multByConstant(ptVec[packIdx]);

        incoming.addCtxt(encZero[packIdx]);

        ser.clear();
        SerializeToString(incoming, ser);
        const size_t sendCh = (mPartyID == mNumberOfParties - 2) ? 0 : 2;
        coproto::sync_wait(chls[sendCh].send(ser));
    }

    encZero.clear();

    logger.log("Member ", mPartyID, " finished the voting phase.");
    setTimePoint("OtMpPsiMember::Run finished the voting phase.");

    if (!traceableFlag)
    {
        // one-shot decrypt
        std::vector<std::string> serIn(numPacks);
        std::vector<Ciphertext> ctIn;
        ctIn.reserve(numPacks);
        std::vector<DoubleCRT> shares;
        shares.reserve(numPacks);

        recvStrings(serIn, numPacks, 0);
        deserializeBatch(serIn, ctIn);
        setTimePoint("OtMpPsiMember::Run received ciphertext from the leader.");

        partialDecryptBatch(ctIn, shares);
        setTimePoint("OtMpPsiMember::Run completed partial decryption.");

        serializeAndSend(shares, 0);

        logger.log("Member ", mPartyID, " done multiparty decryption.");
        setTimePoint("OtMpPsiMember::Run sent decryption shares to the leader.");
    }
    else
    {
        logger.log("Member ", mPartyID, "enter traceable procedure.");

        std::vector<Plaintext> ptVec;
        ptVec.reserve(numPacks);
        {
            Plaintext pt(*mCc);
            u64 idx = 0;
            for (u64 i = 0; i < numBins; ++i)
            {
                pt[idx++] = (*map)[i];
                if (idx == packingCap || i == numBins - 1)
                {
                    ptVec.emplace_back(std::move(pt));
                    pt = Plaintext(*mCc);
                    idx = 0;
                }
            }
        }

        encZeroBatch(numPacks, zeroPt, encZero);
        // mask back, then decrypt by round
        {
            std::vector<std::string> serFirst(numPacks);
            std::vector<Ciphertext> ctFirst;
            ctFirst.reserve(numPacks);
            recvStrings(serFirst, numPacks, 0);
            deserializeBatch(serFirst, ctFirst);
            setTimePoint("OtMpPsiMember::Run received ciphertext from the leader.");

            for (size_t i = 0; i < numPacks; ++i)
            {
                ctFirst[i].multByConstant(ptVec[i]);
                ctFirst[i].addCtxt(encZero[i]);
            }
            serializeAndSend(ctFirst, 0);
        }

        std::vector<std::string> serRound(numPacks);
        std::vector<Ciphertext> ctRound;
        ctRound.reserve(numPacks);
        std::vector<DoubleCRT> shares;
        shares.reserve(numPacks);

        for (size_t round = 0; round < mNumberOfParties - 1; ++round)
        {
            recvStrings(serRound, numPacks, 0);
            deserializeBatch(serRound, ctRound);
            partialDecryptBatch(ctRound, shares);
            serializeAndSend(shares, 0);

            logger.log("Member ", mPartyID, " completed round ", round,
                       " of multiparty decryption.");
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
                         BinaryMapBase::Type type,
                         size_t inputBitSize,
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

    logger.log("Leader begins");
    setTimePoint("OtMpPsiLeader::Run begin");

    const size_t numMembers = chls.size();

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

    auto serializeBatch = [&](const std::vector<Ciphertext> &C, std::vector<std::string> &out)
    {
        out.resize(C.size());
        for (size_t i = 0; i < C.size(); ++i)
            SerializeToString(C[i], out[i]);
    };

    auto encryptBatch = [&](const std::vector<Plaintext> &P, std::vector<Ciphertext> &C)
    {
        C.clear();
        C.reserve(P.size());
        for (const auto &p : P)
        {
            Ciphertext c(*mKeyPair.second);
            mKeyPair.second->Encrypt(c, p);
            C.emplace_back(std::move(c));
        }
    };

    auto leaderPartialDecrypt = [&](const std::vector<Ciphertext> &C,
                                    std::vector<std::vector<DoubleCRT>> &shares)
    {
        // leader share goes last
        parallel_for(std::min<size_t>(10, C.size()), [&](size_t tid)
                     {
            secure_ntl_random::seedCurrentThread();
            for (size_t i = tid; i < C.size(); i += std::min<size_t>(10, C.size())) {
                mKeyPair.first->PartialDecrypt(shares[i].back(), C[i]);
            } });
    };

    auto gatherMemberShares = [&](std::vector<std::vector<DoubleCRT>> &shares)
    {
        parallel_for(numMembers, [&](size_t memberIdx)
                     {
            std::string buf;
            for (size_t packIdx = 0; packIdx < shares.size(); ++packIdx) {
                coproto::sync_wait(chls[memberIdx].recvResize(buf));
                DeserializeFromString(buf, shares[packIdx][memberIdx], mCc);
            } });
    };

    auto broadcastToAllMembers = [&](const std::vector<std::string> &ser)
    {
        parallel_for(numMembers, [&](size_t memberIdx)
                     {
            for (const auto& s : ser) coproto::sync_wait(chls[memberIdx].send(s)); });
    };

    std::unique_ptr<BinaryMapBase> map;
    if (type == BinaryMapBase::Type::Bitmap)
    {
        map = std::make_unique<Bitmap>((1ULL << inputBitSize));
        for (u64 i = 0; i < inputs.size(); ++i)
            map->add(inputs[i]);
    }
    else
    {
        throw std::invalid_argument("Unsupported BinaryMapBase::Type");
    }

    logger.log("Leader converted input set to binary representation.");
    setTimePoint("OtMpPsiLeader::Run converted input set to binary representation.");

    const u64 numBins = map->size();
    const u64 packingCapacity = mCc->getEA().size();
    const u64 numPacks = (numBins + packingCapacity - 1) / packingCapacity;

    // 0 means no leader item in this bin
    std::vector<u8> thresholdByBin;
    std::vector<u64> uniqueLeaderBins;
    if (mThreshold == 0)
    {
        thresholdByBin.assign(numBins, 0);
        uniqueLeaderBins.reserve(inputs.size());
        for (u64 inputIdx = 0; inputIdx < inputs.size(); ++inputIdx)
        {
            u64 binIdx;
            std::memcpy(&binIdx, &inputs[inputIdx], sizeof(u64));
            if (binIdx >= numBins)
                throw std::out_of_range("Leader input is outside the bitmap domain");
            if (thresholdByBin[binIdx] == 0)
            {
                thresholdByBin[binIdx] = static_cast<u8>(inputThresholds[inputIdx]);
                uniqueLeaderBins.push_back(binIdx);
            }
            else if (thresholdByBin[binIdx] != inputThresholds[inputIdx])
            {
                throw std::runtime_error("Conflicting thresholds mapped to one bitmap element");
            }
        }
    }

    // start each item at its threshold bit
    std::vector<Plaintext> ptVec;
    ptVec.reserve(numPacks);
    {
        Plaintext pt(*mCc);
        u64 idx = 0;
        const u64 uniformBase = (mThreshold == 0) ? 0 : (1ULL << (mThreshold - 1));
        for (u64 i = 0; i < numBins; ++i)
        {
            u64 base = 0;
            if ((*map)[i])
            {
                if (mThreshold == 0)
                {
                    if (thresholdByBin[i] == 0)
                        throw std::runtime_error("Occupied bitmap slot has no element threshold");
                    base = 1ULL << (thresholdByBin[i] - 1);
                }
                else
                {
                    base = uniformBase;
                }
            }
            pt[idx++] = base;
            if (idx == packingCapacity || i == numBins - 1)
            {
                ptVec.emplace_back(std::move(pt));
                pt = Plaintext(*mCc);
                idx = 0;
            }
        }
    }

    setTimePoint("OtMpPsiLeader::Run packed binary map into plaintexts.");
    std::vector<Ciphertext> ctVec;
    encryptBatch(ptVec, ctVec);
    setTimePoint("OtMpPsiLeader::Run prepared ciphertext for voting.");

    {
        std::thread sender([&]
                           {
            std::string s;
            for (size_t i = 0; i < numPacks; ++i) {
                s.clear();
                SerializeToString(ctVec[i], s);
                coproto::sync_wait(chls[0].send(s));
            } });

        std::thread receiver([&]
                             {
            std::string s;
            for (size_t i = 0; i < numPacks; ++i) {
                coproto::sync_wait(chls[chls.size() - 1].recvResize(s));
                DeserializeFromString(s, ctVec[i], mKeyPair.second);
            } });

        if (sender.joinable())
            sender.join();
        if (receiver.joinable())
            receiver.join();
    }

    logger.log("Leader finished voting phase.");
    setTimePoint("OtMpPsiLeader::Run finished voting phase.");

    if (!traceableFlag)
    {
        // one-shot decrypt
        std::vector<std::string> ser;
        serializeBatch(ctVec, ser);
        broadcastToAllMembers(ser);
        setTimePoint("OtMpPsiLeader::Run sent ciphertexts to all members for decryption.");

        std::vector<std::vector<DoubleCRT>> shares(
            numPacks, std::vector<DoubleCRT>(mNumberOfParties, DoubleCRT(*mCc, ctVec[0].getPrimeSet())));

        leaderPartialDecrypt(ctVec, shares);
        setTimePoint("OtMpPsiLeader::Run completed partial decryption.");

        gatherMemberShares(shares);
        setTimePoint("OtMpPsiLeader::Run received partial decryptions from all members");

        const size_t fuseThreads = numMembers;
        parallel_for(std::min<size_t>(fuseThreads, numPacks), [&](size_t tid)
                     {
            const size_t step = std::min<size_t>(fuseThreads, numPacks);
            for (size_t i = tid; i < numPacks; i += step) {
                mKeyPair.first->DecryptFusion(ptVec[i], ctVec[i], shares[i]);
            } });

        logger.log("Leader completed multiparty decryption.");
        setTimePoint("OtMpPsiLeader::Run completed decryption fusion.");

        // masked inputs can collide
        const u64 plaintextModulus = static_cast<u64>(mKeyPair.second->getPtxtSpace());
        auto decodeBin = [&](u64 binIdx, u64 elementThreshold)
        {
            const u64 packIdx = binIdx / packingCapacity;
            const u64 ptIndex = binIdx % packingCapacity;
            u64 value = static_cast<u64>(long(ptVec[packIdx][ptIndex]));
            if (value == 0)
                return u64{0};

            const u64 maxShifts = mNumberOfParties - elementThreshold + 1;
            u64 shifts = 0;
            while (value % plaintextModulus != 0 && shifts < maxShifts)
            {
                value <<= 1;
                ++shifts;
            }
            if (value % plaintextModulus != 0 || shifts == 0)
                throw std::runtime_error("Invalid decrypted tally encoding");
            return shifts + elementThreshold - 1;
        };

        std::vector<u64> intersectionCount;
        if (mThreshold == 0)
        {
            intersectionCount.resize(uniqueLeaderBins.size(), 0);
            for (u64 i = 0; i < uniqueLeaderBins.size(); ++i)
            {
                const u64 binIdx = uniqueLeaderBins[i];
                intersectionCount[i] = decodeBin(binIdx, thresholdByBin[binIdx]);
            }
        }
        else
        {
            intersectionCount.resize(inputs.size(), 0);
            for (u64 i = 0; i < inputs.size(); ++i)
            {
                u64 binIdx;
                std::memcpy(&binIdx, &inputs[i], sizeof(u64));
                intersectionCount[i] = decodeBin(binIdx, mThreshold);
            }
        }

        if (mDebug)
        {
            int cnt = 0;
            for (auto v : intersectionCount)
                if (v != 0)
                    ++cnt;
            logger.log("Found ", cnt, " intersection elements");
        }
        logger.log(getTimer());
    }
    else
    {
        logger.log("Leader enter traceable procedure.");
        // trace by member
        std::vector<std::string> ser;
        serializeBatch(ctVec, ser);
        broadcastToAllMembers(ser);

        std::vector<std::vector<Ciphertext>> traceableCiphertexts(mNumberOfParties - 1,
                                                                  std::vector<Ciphertext>(numPacks, Ciphertext(*mKeyPair.second)));
        parallel_for(numMembers, [&](size_t memberIdx)
                     {
            std::string s;
            for (size_t packIdx = 0; packIdx < numPacks; ++packIdx) {
                coproto::sync_wait(chls[memberIdx].recvResize(s));
                DeserializeFromString(s, traceableCiphertexts[memberIdx][packIdx], mKeyPair.second);
            } });

        // private mode traces each bin once
        const u64 traceSize = (mThreshold == 0) ? uniqueLeaderBins.size() : inputs.size();
        std::vector<std::vector<u64>> traceable(traceSize);

        for (size_t round = 0; round < mNumberOfParties - 1; ++round)
        {
            std::vector<std::string> roundSer;
            roundSer.resize(numPacks);
            for (size_t i = 0; i < numPacks; ++i)
                SerializeToString(traceableCiphertexts[round][i], roundSer[i]);
            broadcastToAllMembers(roundSer);

            std::vector<std::vector<DoubleCRT>> shares(
                numPacks, std::vector<DoubleCRT>(mNumberOfParties, DoubleCRT(*mCc, traceableCiphertexts[round][0].getPrimeSet())));

            leaderPartialDecrypt(traceableCiphertexts[round], shares);

            gatherMemberShares(shares);

            const size_t fuseThreads = numMembers;
            parallel_for(std::min<size_t>(fuseThreads, numPacks), [&](size_t tid)
                         {
                const size_t step = std::min<size_t>(fuseThreads, numPacks);
                for (size_t i = tid; i < numPacks; i += step) {
                    mKeyPair.first->DecryptFusion(ptVec[i],  traceableCiphertexts[round][i], shares[i]);
                } });

            for (u64 i = 0; i < traceSize; ++i)
            {
                u64 binIdx;
                if (mThreshold == 0)
                    binIdx = uniqueLeaderBins[i];
                else
                    std::memcpy(&binIdx, &inputs[i], sizeof(u64));

                const u64 packIdx = binIdx / packingCapacity;
                const u64 ptIndex = binIdx % packingCapacity;
                const u64 value = static_cast<u64>(long(ptVec[packIdx][ptIndex]));
                if (value != 0)
                    traceable[i].emplace_back(round);
            }
        }

        if (mDebug)
        {
            int cnt = 0;
            for (const auto &v : traceable)
                if (!v.empty())
                {
                    ++cnt;
                }
            logger.log("Found ", cnt, " intersection elements");

            for (size_t i = 0; i < traceable.size(); ++i)
            {
                if (i > 255)
                    break;
                if (!traceable[i].empty())
                {
                    std::ostringstream oss;
                    const u64 elementLabel = (mThreshold == 0) ? uniqueLeaderBins[i] : i;
                    oss << "Element " << elementLabel << " trace : ";
                    for (const auto &round : traceable[i])
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
            << " CryptoContext Parameters (HElib)\n"
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
        for (size_t memberIdx = 0; memberIdx < mNumberOfParties - 1; ++memberIdx)
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
