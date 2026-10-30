#include "CryptoUtils.h"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <chrono>
#include <filesystem>

void InitializeCryptoContext(CryptoContext &cc, u64 n, bool traceable)
{
    u64 bits = 0;
    u64 ring_dim = 0;
    if (!get_params(n, traceable, bits, ring_dim))
    {
        std::cerr << "Error: No parameters found for n = " << n
                  << " (mode=" << (traceable ? "traceable" : "non-traceable") << ")" << std::endl;
        exit(EXIT_FAILURE);
    }
    cc = CryptoContext(
        helib::ContextBuilder<helib::BGV>()
            .m(ring_dim)
            .p(PLAINTEXT_MODULUS_BASE)
            .r(n)
            .bits(bits)
            .c(2)
            .buildPtr());
}

std::vector<KeyPair> GenerateKeyPairs(CryptoContext &cc, size_t numParties)
{
    if (numParties < 3)
    {
        std::cerr << "Error: Number of parties must be at least 3." << std::endl;
        exit(EXIT_FAILURE);
    }

    std::vector<KeyPair> keyPairs;
    keyPairs.reserve(numParties);

    for (size_t i = 0; i < numParties; ++i)
    {
        auto ski = std::make_unique<helib::SecKey>(*cc);
        keyPairs.emplace_back(std::move(ski), nullptr);
    }

    keyPairs[0].first->GenSecKey(/*ptxtSpace=*/0, /*maxDegKswitch=*/1);

    for (size_t i = 1; i < numParties; ++i)
    {
        keyPairs[i].first->SequentialMultipartyGenSecKey(
            *keyPairs[i - 1].first, /*ptxtSpace=*/0, /*maxDegKswitch=*/1);
    }

    for (size_t i = 0; i < numParties; ++i)
    {
        keyPairs[i].second = std::make_unique<helib::PubKey>(*keyPairs.back().first);
    }

    return keyPairs;
}

void SaveCryptoContext(const CryptoContext &cc, const std::string &filename)
{
    if (!cc)
    {
        std::cerr << "Error: CryptoContext is null.\n";
        std::exit(EXIT_FAILURE);
    }
    std::ofstream out(filename, std::ios::binary);
    if (!out)
    {
        std::cerr << "Error opening " << filename << " for writing.\n";
        std::exit(EXIT_FAILURE);
    }
    cc->writeTo(out);
}

CryptoContext LoadCryptoContext(const std::string &filename)
{
    std::ifstream in(filename, std::ios::binary);
    if (!in)
    {
        std::cerr << "Error opening " << filename << " for reading.\n";
        std::exit(EXIT_FAILURE);
    }
    helib::Context *raw = helib::Context::readPtrFrom(in);
    if (!raw)
    {
        std::cerr << "Error deserializing Context from " << filename << "\n";
        std::exit(EXIT_FAILURE);
    }
    return CryptoContext(raw);
}

void SaveKeyPair(const KeyPair &keyPair,
                 const std::string &secretKeyFile,
                 const std::string &publicKeyFile)
{
    {
        std::ofstream out(secretKeyFile, std::ios::binary);
        if (!out)
        {
            std::cerr << "Error opening " << secretKeyFile << " for writing.\n";
            std::exit(EXIT_FAILURE);
        }

        std::error_code ec;
        std::filesystem::permissions(
            secretKeyFile,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            ec);
        if (ec)
        {
            std::cerr << "Error securing " << secretKeyFile << ": " << ec.message() << "\n";
            std::exit(EXIT_FAILURE);
        }
        keyPair.first->writeTo(out);
    }
    {
        std::ofstream out(publicKeyFile, std::ios::binary);
        if (!out)
        {
            std::cerr << "Error opening " << publicKeyFile << " for writing.\n";
            std::exit(EXIT_FAILURE);
        }
        keyPair.second->writeTo(out);
    }
}

KeyPair LoadKeyPair(const CryptoContext &cc,
                    const std::string &secretKeyFile,
                    const std::string &publicKeyFile)
{
    std::ifstream skIn(secretKeyFile, std::ios::binary);
    if (!skIn)
    {
        std::cerr << "Error opening " << secretKeyFile << " for reading.\n";
        std::exit(EXIT_FAILURE);
    }
    helib::SecKey sk = helib::SecKey::readFrom(skIn, *cc);
    auto secKey = std::make_unique<helib::SecKey>(std::move(sk));

    std::ifstream pkIn(publicKeyFile, std::ios::binary);
    if (!pkIn)
    {
        std::cerr << "Error opening " << publicKeyFile << " for reading.\n";
        std::exit(EXIT_FAILURE);
    }
    helib::PubKey pk = helib::PubKey::readFrom(pkIn, *cc);
    auto pubKey = std::make_unique<helib::PubKey>(std::move(pk));

    return {std::move(secKey), std::move(pubKey)};
}
