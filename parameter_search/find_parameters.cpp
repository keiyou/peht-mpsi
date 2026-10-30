#include <helib/helib.h>
#include "../SecureNtlRandom.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using u64 = std::uint64_t;
using i64 = std::int64_t;
using Clock = std::chrono::steady_clock;
using Plaintext = helib::Ptxt<helib::BGV>;
using Ciphertext = helib::Ctxt;
using DoubleCRT = helib::DoubleCRT;

enum class SmokeMode
{
    Quick,
    NonTraceable,
    Traceable
};

const char *smokeModeName(SmokeMode mode)
{
    switch (mode)
    {
    case SmokeMode::Quick:
        return "quick";
    case SmokeMode::NonTraceable:
        return "nontraceable";
    case SmokeMode::Traceable:
        return "traceable";
    }
    return "unknown";
}

enum class ThresholdMode
{
    Majority,
    Half
};

const char *thresholdModeName(ThresholdMode mode)
{
    switch (mode)
    {
    case ThresholdMode::Majority:
        return "majority";
    case ThresholdMode::Half:
        return "half";
    }
    return "unknown";
}

u64 chooseThreshold(u64 parties, ThresholdMode mode)
{
    return mode == ThresholdMode::Half ? parties / 2 : parties / 2 + 1;
}

u64 defaultThreadCount()
{
    const unsigned int hc = std::thread::hardware_concurrency();
    if (hc == 0)
        return 4;
    return std::min<u64>(12, hc);
}

struct Options
{
    u64 nMin = 4;
    u64 nMax = 20;
    double minSecurity = 128.0;
    double targetCapacity = 1.0;
    u64 minSlots = 512;
    u64 domainBits = 20;
    u64 bitsStep = 8;
    u64 maxExtraBits = 128;
    u64 belowEstimateBits = 64;
    u64 smokePacks = 1;
    u64 maxSmokeCandidates = 0;
    u64 threads = defaultThreadCount();
    SmokeMode smokeMode = SmokeMode::Traceable;
    ThresholdMode thresholdMode = ThresholdMode::Majority;
    bool quiet = false;
    std::string format = "cpp";
    std::vector<u64> mCandidates{
        8191, 13107, 16383, 20485, 21845, 24929, 32767,
        42799, 43691, 49981, 53261, 54485, 55831, 60787,
        61455, 65535, 65537, 69905, 109655, 143395};
};

std::mutex gLogMutex;

void logProgress(const Options &opt, const std::string &message)
{
    if (opt.quiet)
        return;
    std::lock_guard<std::mutex> lock(gLogMutex);
    std::cerr << message << '\n';
}

void logAlways(const std::string &message)
{
    std::lock_guard<std::mutex> lock(gLogMutex);
    std::cerr << message << '\n';
}

struct MInfo
{
    u64 m = 0;
    u64 phi = 0;
    u64 ord = 0;
    u64 slots = 0;
    bool ok = false;
    std::string reason;
};

struct Attempt
{
    MInfo minfo;
    u64 startBits = 0;
    u64 endBits = 0;
    long double score = 0;
};

struct ResultRow
{
    u64 n = 0;
    u64 threshold = 0;
    u64 bits = 0;
    u64 m = 0;
    u64 phi = 0;
    u64 ord = 0;
    u64 slots = 0;
    double security = 0;
    double minCapacity = std::numeric_limits<double>::quiet_NaN();
    long double score = 0;
    double smokeMs = 0;
};

[[noreturn]] void usage(const std::string &error = "")
{
    if (!error.empty())
        std::cerr << "error: " << error << "\n\n";

    std::cerr
        << "Usage: find_parameters [options]\n\n"
        << "Options:\n"
        << "  --n-min N                    first party count (default 4)\n"
        << "  --n-max N                    last party count (default 20)\n"
        << "  --security X                 minimum HElib security (default 128)\n"
        << "  --target-capacity X          estimated remaining noise margin in bits (default 1)\n"
        << "  --min-slots N                minimum batching slots (default 512)\n"
        << "  --domain-bits N              cost-model domain size exponent (default 20)\n"
        << "  --bits-step N                coarse bits probe step before capacity-guided refinement (default 8)\n"
        << "  --max-extra-bits N           search limit above estimate (default 128)\n"
        << "  --below-estimate-bits N      search this far below the estimate (default 64)\n"
        << "  --packs N                    packed ciphertexts to smoke test (default 1)\n"
        << "  --max-smoke-candidates N     ranked candidates to smoke test per n; 0 means all (default 0)\n"
        << "  --threads N                  parallel n-search workers, 1..12 (default hardware capped at 12)\n"
        << "  --m-list CSV                 override candidate m list\n"
        << "  --mode quick|nontraceable|traceable\n"
        << "                                smoke workload to run (default traceable)\n"
        << "  --threshold-mode majority|half\n"
        << "                                threshold used by smoke/search (default majority = n/2+1)\n"
        << "  --format cpp|csv             output format (default cpp)\n"
        << "  --quick                      alias for --mode quick\n"
        << "  --quiet                      suppress progress logs\n"
        << "  --help                       show this help\n";
    std::exit(error.empty() ? EXIT_SUCCESS : EXIT_FAILURE);
}

u64 parseU64(const std::string &value, const std::string &name)
{
    char *end = nullptr;
    const unsigned long long parsed = std::strtoull(value.c_str(), &end, 10);
    if (end == value.c_str() || *end != '\0')
        usage("invalid integer for " + name + ": " + value);
    return static_cast<u64>(parsed);
}

double parseDouble(const std::string &value, const std::string &name)
{
    char *end = nullptr;
    const double parsed = std::strtod(value.c_str(), &end);
    if (end == value.c_str() || *end != '\0')
        usage("invalid number for " + name + ": " + value);
    return parsed;
}

std::vector<u64> parseCsvU64(const std::string &csv)
{
    std::vector<u64> values;
    std::stringstream ss(csv);
    std::string item;
    while (std::getline(ss, item, ','))
    {
        if (!item.empty())
            values.push_back(parseU64(item, "--m-list"));
    }
    if (values.empty())
        usage("--m-list must contain at least one value");
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    return values;
}

Options parseArgs(int argc, char **argv)
{
    Options opt;
    for (int i = 1; i < argc; ++i)
    {
        const std::string key = argv[i];
        auto needValue = [&](const std::string &name) -> std::string
        {
            if (i + 1 >= argc)
                usage("missing value for " + name);
            return argv[++i];
        };

        if (key == "--help")
            usage();
        else if (key == "--n-min")
            opt.nMin = parseU64(needValue(key), key);
        else if (key == "--n-max")
            opt.nMax = parseU64(needValue(key), key);
        else if (key == "--security")
            opt.minSecurity = parseDouble(needValue(key), key);
        else if (key == "--target-capacity")
            opt.targetCapacity = parseDouble(needValue(key), key);
        else if (key == "--min-slots")
            opt.minSlots = parseU64(needValue(key), key);
        else if (key == "--domain-bits")
            opt.domainBits = parseU64(needValue(key), key);
        else if (key == "--bits-step")
            opt.bitsStep = parseU64(needValue(key), key);
        else if (key == "--max-extra-bits")
            opt.maxExtraBits = parseU64(needValue(key), key);
        else if (key == "--below-estimate-bits")
            opt.belowEstimateBits = parseU64(needValue(key), key);
        else if (key == "--packs")
            opt.smokePacks = parseU64(needValue(key), key);
        else if (key == "--max-smoke-candidates")
            opt.maxSmokeCandidates = parseU64(needValue(key), key);
        else if (key == "--threads")
            opt.threads = parseU64(needValue(key), key);
        else if (key == "--m-list")
            opt.mCandidates = parseCsvU64(needValue(key));
        else if (key == "--mode")
        {
            const std::string mode = needValue(key);
            if (mode == "quick")
                opt.smokeMode = SmokeMode::Quick;
            else if (mode == "nontraceable" || mode == "non-traceable")
                opt.smokeMode = SmokeMode::NonTraceable;
            else if (mode == "traceable")
                opt.smokeMode = SmokeMode::Traceable;
            else
                usage("--mode must be quick, nontraceable, or traceable");
        }
        else if (key == "--threshold-mode")
        {
            const std::string mode = needValue(key);
            if (mode == "majority")
                opt.thresholdMode = ThresholdMode::Majority;
            else if (mode == "half" || mode == "floor-half")
                opt.thresholdMode = ThresholdMode::Half;
            else
                usage("--threshold-mode must be majority or half");
        }
        else if (key == "--format")
            opt.format = needValue(key);
        else if (key == "--quick")
            opt.smokeMode = SmokeMode::Quick;
        else if (key == "--quiet")
            opt.quiet = true;
        else
            usage("unknown option: " + key);
    }

    if (opt.nMin < 3 || opt.nMax < opt.nMin)
        usage("invalid n range; n must be at least 3");
    if (opt.domainBits >= 63)
        usage("--domain-bits must be below 63");
    if (opt.bitsStep == 0)
        usage("--bits-step must be positive");
    if (opt.targetCapacity < 0.0)
        usage("--target-capacity must be non-negative");
    if (opt.smokePacks == 0)
        usage("--packs must be positive");
    if (opt.threads == 0 || opt.threads > 12)
        usage("--threads must be between 1 and 12");
    if (opt.format != "cpp" && opt.format != "csv")
        usage("--format must be cpp or csv");

    std::sort(opt.mCandidates.begin(), opt.mCandidates.end());
    opt.mCandidates.erase(std::unique(opt.mCandidates.begin(), opt.mCandidates.end()), opt.mCandidates.end());
    return opt;
}

u64 mulMod(u64 a, u64 b, u64 mod)
{
    return static_cast<u64>((static_cast<__uint128_t>(a) * b) % mod);
}

u64 powMod(u64 a, u64 e, u64 mod)
{
    u64 r = 1 % mod;
    a %= mod;
    while (e)
    {
        if (e & 1)
            r = mulMod(r, a, mod);
        a = mulMod(a, a, mod);
        e >>= 1;
    }
    return r;
}

std::vector<u64> uniquePrimeFactors(u64 n)
{
    std::vector<u64> factors;
    for (u64 f = 2; f * f <= n; ++f)
    {
        if (n % f == 0)
        {
            factors.push_back(f);
            while (n % f == 0)
                n /= f;
        }
    }
    if (n > 1)
        factors.push_back(n);
    return factors;
}

u64 eulerPhi(u64 n)
{
    u64 result = n;
    u64 x = n;
    for (u64 f = 2; f * f <= x; ++f)
    {
        if (x % f == 0)
        {
            while (x % f == 0)
                x /= f;
            result -= result / f;
        }
    }
    if (x > 1)
        result -= result / x;
    return result;
}

std::optional<u64> multiplicativeOrder(u64 a, u64 m)
{
    if (std::gcd(a, m) != 1)
        return std::nullopt;

    u64 order = eulerPhi(m);
    for (u64 q : uniquePrimeFactors(order))
    {
        while (order % q == 0 && powMod(a, order / q, m) == 1)
            order /= q;
    }
    return order;
}

MInfo inspectM(u64 m, const Options &opt)
{
    MInfo info;
    info.m = m;

    if (m < 3 || (m % 2) == 0)
    {
        info.reason = "m must be odd and >= 3 for p=2";
        return info;
    }

    info.phi = eulerPhi(m);
    auto ord = multiplicativeOrder(2, m);
    if (!ord || *ord == 0)
    {
        info.reason = "ord_m(2) is undefined";
        return info;
    }

    info.ord = *ord;
    info.slots = info.phi / info.ord;
    if (info.slots < opt.minSlots)
    {
        info.reason = "not enough slots";
        return info;
    }

    info.ok = true;
    return info;
}

u64 estimateBits(u64 n, u64 m)
{
    const double raw = static_cast<double>(n + 1) *
                       (static_cast<double>(n) + 0.5 * std::log2(static_cast<double>(m)) + 2.0);
    return static_cast<u64>(std::ceil(raw));
}

long double scoreCandidate(u64 bits, const MInfo &info, const Options &opt)
{
    const u64 domainSize = 1ULL << opt.domainBits;
    const u64 packs = (domainSize + info.slots - 1) / info.slots;
    return static_cast<long double>(bits) *
           static_cast<long double>(info.phi) *
           static_cast<long double>(packs);
}

std::unique_ptr<helib::Context> buildContext(u64 n, u64 bits, u64 m)
{
    return std::unique_ptr<helib::Context>(helib::ContextBuilder<helib::BGV>()
        .m(static_cast<long>(m))
        .p(2)
        .r(static_cast<long>(n))
        .bits(static_cast<long>(bits))
        .c(2)
        .bootstrappable(false)
        .buildPtr());
}

u64 normalizeSlot(long value, u64 modulus)
{
    i64 v = static_cast<i64>(value);
    i64 mod = static_cast<i64>(modulus);
    i64 r = v % mod;
    if (r < 0)
        r += mod;
    return static_cast<u64>(r);
}

u64 normalizeConst(long value, u64 modulus)
{
    i64 mod = static_cast<i64>(modulus);
    i64 r = static_cast<i64>(value) % mod;
    if (r < 0)
        r += mod;
    return static_cast<u64>(r);
}

struct KeyMaterial
{
    std::vector<std::unique_ptr<helib::SecKey>> keys;
    std::unique_ptr<helib::PubKey> publicKey;
};

struct SmokeStats
{
    bool observedCapacity = false;
    double minCapacity = std::numeric_limits<double>::infinity();

    void observe(const Ciphertext &ciphertext)
    {
        observedCapacity = true;
        minCapacity = std::min(minCapacity, ciphertext.capacity());
    }

    double value() const
    {
        return observedCapacity ? minCapacity : std::numeric_limits<double>::quiet_NaN();
    }
};

KeyMaterial generateMultipartyKeys(const helib::Context &context, u64 parties)
{
    KeyMaterial material;
    material.keys.reserve(static_cast<size_t>(parties));

    for (u64 i = 0; i < parties; ++i)
        material.keys.push_back(std::make_unique<helib::SecKey>(context));

    material.keys[0]->GenSecKey(/*ptxtSpace=*/0, /*maxDegKswitch=*/1);
    for (u64 i = 1; i < parties; ++i)
        material.keys[i]->SequentialMultipartyGenSecKey(
            *material.keys[i - 1], /*ptxtSpace=*/0, /*maxDegKswitch=*/1);

    material.publicKey = std::make_unique<helib::PubKey>(*material.keys.back());
    return material;
}

bool decryptAndVerify(const helib::Context &context,
                      const std::vector<std::unique_ptr<helib::SecKey>> &keys,
                      const Ciphertext &ciphertext,
                      const std::vector<u64> &expected,
                      u64 plaintextModulus,
                      SmokeStats *stats,
                      std::string &reason)
{
    if (stats != nullptr)
        stats->observe(ciphertext);

    if (!ciphertext.isCorrect())
    {
        reason = "ciphertext noise bound exceeds HElib correctness limit";
        return false;
    }

    std::vector<DoubleCRT> shares;
    shares.reserve(keys.size());
    for (const auto &key : keys)
    {
        DoubleCRT share(context, ciphertext.getPrimeSet());
        key->PartialDecrypt(share, ciphertext);
        shares.emplace_back(std::move(share));
    }

    Plaintext decrypted(context);
    keys.back()->DecryptFusion(decrypted, ciphertext, shares);

    const long slots = context.getEA().size();
    for (long i = 0; i < slots; ++i)
    {
        const u64 got = normalizeSlot(static_cast<long>(decrypted[i]), plaintextModulus);
        if (got != expected[static_cast<size_t>(i)])
        {
            std::ostringstream oss;
            oss << "slot " << i << " mismatch: got " << got
                << ", expected " << expected[static_cast<size_t>(i)];
            reason = oss.str();
            return false;
        }
    }
    return true;
}

Plaintext zeroPlaintext(const helib::Context &context)
{
    Plaintext zero(context);
    const long slots = context.getEA().size();
    for (long i = 0; i < slots; ++i)
        zero[i] = 0;
    return zero;
}

bool runBitmapShapedVote(const helib::Context &context,
                         KeyMaterial &keys,
                         u64 parties,
                         u64 threshold,
                         u64 packs,
                         bool includeTraceableMask,
                         SmokeStats *stats,
                         std::string &reason)
{
    const long slots = context.getEA().size();
    const u64 plaintextModulus = 1ULL << parties;
    const u64 base = 1ULL << (threshold - 1);
    const Plaintext zeroPt = zeroPlaintext(context);

    for (u64 pack = 0; pack < packs; ++pack)
    {
        Plaintext leaderPt(context);
        std::vector<Plaintext> memberPts;
        memberPts.reserve(static_cast<size_t>(parties - 1));
        for (u64 j = 0; j + 1 < parties; ++j)
            memberPts.emplace_back(context);

        Plaintext traceMask(context);
        std::vector<u64> expected(static_cast<size_t>(slots), 0);
        std::vector<u64> traceExpected(static_cast<size_t>(slots), 0);
        const u64 traceMember = parties - 2;

        for (long s = 0; s < slots; ++s)
        {
            const u64 desiredCount = (static_cast<u64>(s) + 17 * pack) % (parties + 1);
            const bool leaderPresent = desiredCount > 0;
            const u64 presentMembers = leaderPresent ? desiredCount - 1 : 0;
            u64 value = leaderPresent ? base : 0;

            leaderPt[s] = leaderPresent ? static_cast<long>(base) : 0L;

            for (u64 j = 0; j + 1 < parties; ++j)
            {
                const bool memberPresent = j < presentMembers;
                memberPts[static_cast<size_t>(j)][s] = memberPresent ? 1L : 2L;
                if (leaderPresent && !memberPresent)
                    value = (value * 2) % plaintextModulus;
            }

            const bool tracePresent = traceMember < presentMembers;
            traceMask[s] = tracePresent ? 1L : 0L;
            expected[static_cast<size_t>(s)] = value % plaintextModulus;
            traceExpected[static_cast<size_t>(s)] = tracePresent ? expected[static_cast<size_t>(s)] : 0;
        }

        Ciphertext vote(*keys.publicKey);
        keys.publicKey->Encrypt(vote, leaderPt);

        for (u64 j = 0; j + 1 < parties; ++j)
        {
            Ciphertext encZero(*keys.publicKey);
            keys.publicKey->Encrypt(encZero, zeroPt);
            vote.multByConstant(memberPts[static_cast<size_t>(j)]);
            vote.addCtxt(encZero);
        }

        if (!decryptAndVerify(context, keys.keys, vote, expected, plaintextModulus, stats, reason))
        {
            reason = "bitmap-shaped vote failed: " + reason;
            return false;
        }

        if (includeTraceableMask)
        {
            Ciphertext masked = vote;
            Ciphertext encZero(*keys.publicKey);
            keys.publicKey->Encrypt(encZero, zeroPt);
            masked.multByConstant(traceMask);
            masked.addCtxt(encZero);

            if (!decryptAndVerify(context, keys.keys, masked, traceExpected, plaintextModulus, stats, reason))
            {
                reason = "traceable mask failed: " + reason;
                return false;
            }
        }
    }

    return true;
}


bool runCuckooShapedVote(const helib::Context &context,
                         KeyMaterial &keys,
                         u64 parties,
                         u64 threshold,
                         u64 packs,
                         bool includeTraceableChecks,
                         SmokeStats *stats,
                         std::string &reason)
{
    const long slots = context.getEA().size();
    const u64 plaintextModulus = 1ULL << parties;
    const u64 base = 1ULL << (threshold - 1);
    const Plaintext zeroPt = zeroPlaintext(context);

    for (u64 pack = 0; pack < packs; ++pack)
    {
        Plaintext initPt(context);
        std::vector<Plaintext> senderFactors;
        std::vector<Plaintext> senderMasks;
        std::vector<Plaintext> receiverFlags;
        senderFactors.reserve(static_cast<size_t>(parties - 1));
        senderMasks.reserve(static_cast<size_t>(parties - 1));
        receiverFlags.reserve(static_cast<size_t>(parties - 1));
        for (u64 j = 0; j + 1 < parties; ++j)
        {
            senderFactors.emplace_back(context);
            senderMasks.emplace_back(context);
            receiverFlags.emplace_back(context);
        }

        std::vector<u64> expected(static_cast<size_t>(slots), 0);
        for (long s = 0; s < slots; ++s)
        {
            const bool leaderPresent = ((static_cast<u64>(s) + pack) % 4) != 0;
            initPt[s] = leaderPresent ? static_cast<long>(base) : 0L;
            expected[static_cast<size_t>(s)] = leaderPresent ? base % plaintextModulus : 0;
            for (u64 j = 0; j + 1 < parties; ++j)
            {
                const bool senderPresent = ((static_cast<u64>(s) + 2 * j + pack) % 5) != 0;
                const bool receiverPresent = ((3 * static_cast<u64>(s) + j + pack) % 7) == 0;
                senderFactors[static_cast<size_t>(j)][s] = senderPresent ? 1L : -2L;
                senderMasks[static_cast<size_t>(j)][s] = senderPresent ? 1L : 0L;
                receiverFlags[static_cast<size_t>(j)][s] = receiverPresent ? 1L : 0L;
            }
        }

        Ciphertext state(*keys.publicKey);
        keys.publicKey->Encrypt(state, initPt);

        for (u64 j = 0; j + 1 < parties; ++j)
        {
            Ciphertext leaderContribution = state;
            leaderContribution.multByConstant(receiverFlags[static_cast<size_t>(j)]);
            Ciphertext leaderZero(*keys.publicKey);
            keys.publicKey->Encrypt(leaderZero, zeroPt);
            leaderContribution.addCtxt(leaderZero);

            Ciphertext memberZero(*keys.publicKey);
            keys.publicKey->Encrypt(memberZero, zeroPt);
            state.multByConstant(senderFactors[static_cast<size_t>(j)]);
            state.addCtxt(leaderContribution);
            state.addCtxt(memberZero);

            for (long s = 0; s < slots; ++s)
            {
                const bool senderPresent = ((static_cast<u64>(s) + 2 * j + pack) % 5) != 0;
                const bool receiverPresent = ((3 * static_cast<u64>(s) + j + pack) % 7) == 0;
                const u64 senderFactor = normalizeConst(senderPresent ? 1L : -2L, plaintextModulus);
                const u64 receiverFactor = receiverPresent ? 1ULL : 0ULL;
                const u64 factor = (senderFactor + receiverFactor) % plaintextModulus;
                expected[static_cast<size_t>(s)] =
                    static_cast<u64>((static_cast<__uint128_t>(expected[static_cast<size_t>(s)]) * factor) % plaintextModulus);
            }
        }

        if (!decryptAndVerify(context, keys.keys, state, expected, plaintextModulus, stats, reason))
        {
            reason = "cuckoo-shaped vote failed: " + reason;
            return false;
        }

        if (!includeTraceableChecks)
            continue;

        std::vector<u64> traceRounds{0, (parties - 2) / 2, parties - 2};
        std::sort(traceRounds.begin(), traceRounds.end());
        traceRounds.erase(std::unique(traceRounds.begin(), traceRounds.end()), traceRounds.end());

        for (u64 traceRound : traceRounds)
        {
            Ciphertext trace = state;
            trace.multByConstant(senderMasks[static_cast<size_t>(traceRound)]);

            Ciphertext subtractReceiver = state;
            subtractReceiver.multByConstant(receiverFlags[static_cast<size_t>(traceRound)]);
            subtractReceiver.negate();
            trace.addCtxt(subtractReceiver);

            Ciphertext traceZero(*keys.publicKey);
            keys.publicKey->Encrypt(traceZero, zeroPt);
            trace.addCtxt(traceZero);

            std::vector<u64> traceExpected(static_cast<size_t>(slots), 0);
            for (long s = 0; s < slots; ++s)
            {
                const bool senderPresent = ((static_cast<u64>(s) + 2 * traceRound + pack) % 5) != 0;
                const bool receiverPresent = ((3 * static_cast<u64>(s) + traceRound + pack) % 7) == 0;
                const long traceFactorLong = static_cast<long>(senderPresent ? 1 : 0) -
                                             static_cast<long>(receiverPresent ? 1 : 0);
                const u64 traceFactor = normalizeConst(traceFactorLong, plaintextModulus);
                traceExpected[static_cast<size_t>(s)] =
                    static_cast<u64>((static_cast<__uint128_t>(expected[static_cast<size_t>(s)]) * traceFactor) % plaintextModulus);
            }

            if (!decryptAndVerify(context, keys.keys, trace, traceExpected, plaintextModulus, stats, reason))
            {
                std::ostringstream oss;
                oss << "cuckoo traceable shape failed at round " << traceRound << ": " << reason;
                reason = oss.str();
                return false;
            }
        }
    }

    return true;
}

bool runMpsiSmoke(const helib::Context &context,
                  u64 parties,
                  u64 packs,
                  SmokeMode mode,
                  ThresholdMode thresholdMode,
                  SmokeStats *stats,
                  std::string &reason)
{
    if (parties >= 63)
    {
        reason = "plaintext modulus 2^n does not fit in u64";
        return false;
    }

    const u64 threshold = chooseThreshold(parties, thresholdMode);
    KeyMaterial keys = generateMultipartyKeys(context, parties);
    const bool includeTraceableChecks = mode == SmokeMode::Traceable;

    if (!runBitmapShapedVote(context, keys, parties, threshold, packs, includeTraceableChecks, stats, reason))
        return false;

    if (mode == SmokeMode::Quick)
        return true;

    if (!runCuckooShapedVote(context, keys, parties, threshold, packs, includeTraceableChecks, stats, reason))
        return false;

    return true;
}

std::vector<Attempt> rankedAttempts(u64 n, const Options &opt)
{
    std::vector<Attempt> attempts;
    for (u64 m : opt.mCandidates)
    {
        MInfo info = inspectM(m, opt);
        if (!info.ok)
        {
            std::ostringstream oss;
            oss << "[n=" << n << "] skip m=" << m << ": " << info.reason;
            logProgress(opt, oss.str());
            continue;
        }

        const u64 estimatedBits = estimateBits(n, m);
        const u64 startBits = estimatedBits > opt.belowEstimateBits
                                  ? estimatedBits - opt.belowEstimateBits
                                  : 1;
        const u64 endBits = estimatedBits + opt.maxExtraBits;
        attempts.push_back(Attempt{info, startBits, endBits, scoreCandidate(startBits, info, opt)});
    }

    std::sort(attempts.begin(), attempts.end(), [](const Attempt &a, const Attempt &b)
              {
                  if (a.score != b.score)
                      return a.score < b.score;
                  if (a.minfo.slots != b.minfo.slots)
                      return a.minfo.slots > b.minfo.slots;
                  return a.minfo.m < b.minfo.m;
              });

    if (opt.maxSmokeCandidates != 0 && attempts.size() > opt.maxSmokeCandidates)
        attempts.resize(static_cast<size_t>(opt.maxSmokeCandidates));

    return attempts;
}

std::optional<ResultRow> searchForN(u64 n, const Options &opt)
{
    enum class ProbeStatus
    {
        Pass,
        SmokeFail,
        SecurityFail
    };

    const u64 threshold = chooseThreshold(n, opt.thresholdMode);
    std::optional<ResultRow> best;
    std::vector<Attempt> attempts = rankedAttempts(n, opt);

    auto probe = [&](const Attempt &attempt, u64 bits, ResultRow &row) -> ProbeStatus
    {
        {
            std::ostringstream oss;
            oss << "[n=" << n << "] test m=" << attempt.minfo.m
                << " bits=" << bits << " slots=" << attempt.minfo.slots;
            logProgress(opt, oss.str());
        }

        try
        {
            auto context = buildContext(n, bits, attempt.minfo.m);
            const double security = context->securityLevel();
            row.n = n;
            row.threshold = threshold;
            row.bits = bits;
            row.m = attempt.minfo.m;
            row.phi = attempt.minfo.phi;
            row.ord = attempt.minfo.ord;
            row.slots = attempt.minfo.slots;
            row.security = security;
            row.score = scoreCandidate(bits, attempt.minfo, opt);

            if (security < opt.minSecurity)
            {
                std::ostringstream oss;
                oss << "[n=" << n << "] reject m=" << attempt.minfo.m
                    << " bits=" << bits << " security=" << security;
                logProgress(opt, oss.str());
                return ProbeStatus::SecurityFail;
            }

            std::string reason;
            SmokeStats stats;
            const auto start = Clock::now();
            const bool ok = runMpsiSmoke(*context, n, opt.smokePacks, opt.smokeMode, opt.thresholdMode, &stats, reason);
            const auto stop = Clock::now();
            const double smokeMs = std::chrono::duration<double, std::milli>(stop - start).count();
            row.smokeMs = smokeMs;
            row.minCapacity = stats.value();

            if (!ok)
            {
                std::ostringstream oss;
                oss << "[n=" << n << "] smoke failed m=" << attempt.minfo.m
                    << " bits=" << bits;
                if (std::isfinite(row.minCapacity))
                    oss << " cap=" << std::fixed << std::setprecision(2) << row.minCapacity;
                oss << ": " << reason;
                logProgress(opt, oss.str());
                return ProbeStatus::SmokeFail;
            }
            return ProbeStatus::Pass;
        }
        catch (const std::exception &e)
        {
            std::ostringstream oss;
            oss << "[n=" << n << "] failed m=" << attempt.minfo.m
                << " bits=" << bits << ": " << e.what();
            logProgress(opt, oss.str());
            return ProbeStatus::SmokeFail;
        }
    };

    for (const Attempt &attempt : attempts)
    {
        if (best && attempt.score >= best->score)
        {
            std::ostringstream oss;
            oss << "[n=" << n << "] stop after current best; next m=" << attempt.minfo.m
                << " cannot improve score";
            logProgress(opt, oss.str());
            break;
        }

        u64 lastFailedBits = attempt.startBits == 0 ? 0 : attempt.startBits - 1;
        for (u64 bits = attempt.startBits; bits <= attempt.endBits;)
        {
            ResultRow row;
            const ProbeStatus status = probe(attempt, bits, row);
            bool candidateDone = false;

            const bool shouldRefine = status == ProbeStatus::Pass ||
                                      status == ProbeStatus::SecurityFail;
            if (shouldRefine && lastFailedBits + 1 < bits)
            {
                u64 lo = lastFailedBits + 1;
                u64 hi = bits;
                std::optional<ResultRow> refinedBest;
                std::optional<ResultRow> upperPass;
                if (status == ProbeStatus::Pass)
                    upperPass = row;

                while (lo <= hi)
                {
                    u64 refineBits = lo + (hi - lo) / 2;
                    if (upperPass && std::isfinite(upperPass->minCapacity))
                    {
                        const double droppable = std::floor(upperPass->minCapacity - opt.targetCapacity);
                        if (droppable > 0.0 && upperPass->bits > static_cast<u64>(droppable))
                        {
                            const u64 guided = upperPass->bits - static_cast<u64>(droppable);
                            if (guided >= lo && guided <= hi)
                            {
                                refineBits = guided;
                                std::ostringstream oss;
                                oss << "[n=" << n << "] capacity-guided refine m=" << attempt.minfo.m
                                    << " range=" << lo << ".." << hi
                                    << " probe=" << refineBits
                                    << " from bits=" << upperPass->bits
                                    << " cap=" << std::fixed << std::setprecision(2) << upperPass->minCapacity;
                                logProgress(opt, oss.str());
                            }
                        }
                    }

                    ResultRow refined;
                    const ProbeStatus refinedStatus = probe(attempt, refineBits, refined);
                    if (refinedStatus == ProbeStatus::Pass)
                    {
                        refinedBest = refined;
                        upperPass = refined;
                        if (refineBits == 0)
                            break;
                        hi = refineBits - 1;
                    }
                    else if (refinedStatus == ProbeStatus::SmokeFail)
                    {
                        lo = refineBits + 1;
                    }
                    else
                    {
                        if (refineBits == 0)
                            break;
                        hi = refineBits - 1;
                    }
                }

                if (refinedBest)
                {
                    row = *refinedBest;
                    if (!best || row.score < best->score)
                        best = row;
                    candidateDone = true;
                }
            }

            if (candidateDone)
                break;

            if (status == ProbeStatus::Pass)
            {
                if (!best || row.score < best->score)
                    best = row;
                break;
            }

            if (status == ProbeStatus::SecurityFail)
                break;

            lastFailedBits = bits;
            if (bits == attempt.endBits)
                break;

            const u64 remaining = attempt.endBits - bits;
            u64 jump = opt.bitsStep;
            if (std::isfinite(row.minCapacity))
            {
                const double needed = opt.targetCapacity - row.minCapacity;
                if (needed > 0.0)
                    jump = std::max<u64>(jump, static_cast<u64>(std::ceil(needed)));
            }
            if (jump > opt.bitsStep)
            {
                std::ostringstream oss;
                oss << "[n=" << n << "] capacity estimate jumps m=" << attempt.minfo.m
                    << " from bits=" << bits
                    << " by " << jump;
                if (std::isfinite(row.minCapacity))
                    oss << " (cap=" << std::fixed << std::setprecision(2) << row.minCapacity << ")";
                logProgress(opt, oss.str());
            }
            bits += std::min<u64>(jump, remaining);
        }
    }

    return best;
}

void printCsv(const std::vector<ResultRow> &rows)
{
    std::cout << "n,threshold,bits,m,phi,ord,slots,security,min_capacity,score,smoke_ms\n";
    for (const auto &r : rows)
    {
        std::cout << r.n << ',' << r.threshold << ',' << r.bits << ',' << r.m << ','
                  << r.phi << ',' << r.ord << ',' << r.slots << ','
                  << std::fixed << std::setprecision(6) << r.security << ','
                  << std::fixed << std::setprecision(3) << r.minCapacity << ','
                  << std::fixed << std::setprecision(0) << r.score << ','
                  << std::fixed << std::setprecision(3) << r.smokeMs << '\n';
    }
}

void printCpp(const std::vector<ResultRow> &rows)
{
    std::cout << "static constexpr std::array<Param, " << rows.size() << "> table{{\n";
    for (const auto &r : rows)
    {
        std::cout << "    {" << r.n << ", " << r.bits << ", " << r.m << "},"
                  << " // threshold=" << r.threshold
                  << ", sec=" << std::fixed << std::setprecision(3) << r.security
                  << ", cap=" << std::fixed << std::setprecision(2) << r.minCapacity
                  << ", slots=" << r.slots
                  << ", phi=" << r.phi
                  << ", ord=" << r.ord
                  << "\n";
    }
    std::cout << "}};\n";
}

int main(int argc, char **argv)
{
    Options opt = parseArgs(argc, argv);

    std::vector<u64> nValues;
    for (u64 n = opt.nMin; n <= opt.nMax; ++n)
        nValues.push_back(n);

    std::vector<std::optional<ResultRow>> ordered(nValues.size());
    std::atomic<size_t> nextIndex{0};

    // helib logs here
    std::streambuf *originalCout = std::cout.rdbuf();
    std::cout.rdbuf(std::cerr.rdbuf());
    const size_t workerCount = static_cast<size_t>(std::min<u64>(opt.threads, nValues.size()));

    {
        std::ostringstream oss;
        oss << "[search] using " << workerCount << " worker thread(s)"
            << " mode=" << smokeModeName(opt.smokeMode)
            << " threshold-mode=" << thresholdModeName(opt.thresholdMode);
        logProgress(opt, oss.str());
    }

    std::vector<std::thread> workers;
    workers.reserve(workerCount);
    for (size_t worker = 0; worker < workerCount; ++worker)
    {
        workers.emplace_back([&]()
        {
            secure_ntl_random::seedCurrentThread();
            while (true)
            {
                const size_t idx = nextIndex.fetch_add(1);
                if (idx >= nValues.size())
                    break;

                const u64 n = nValues[idx];
                ordered[idx] = searchForN(n, opt);
                if (!ordered[idx])
                {
                    std::ostringstream oss;
                    oss << "[n=" << n << "] no passing parameter found";
                    logAlways(oss.str());
                }
            }
        });
    }

    for (auto &worker : workers)
        if (worker.joinable())
            worker.join();

    std::cout.rdbuf(originalCout);

    std::vector<ResultRow> rows;
    bool complete = true;
    for (const auto &row : ordered)
    {
        if (row)
            rows.push_back(*row);
        else
            complete = false;
    }

    if (opt.format == "csv")
        printCsv(rows);
    else
        printCpp(rows);

    if (!complete)
        logAlways("[search] incomplete result set; at least one requested n has no passing parameter");

    return complete ? EXIT_SUCCESS : EXIT_FAILURE;
}
