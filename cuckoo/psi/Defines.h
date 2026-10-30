#pragma once

#include <utility>

#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <helib/helib.h>

#include <memory>

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"

#include "coproto/coproto.h"
#include "volePSI/RsCpsi.h"

using u64 = oc::u64;
using u32 = oc::u32;
using u16 = oc::u16;
using u8 = oc::u8;

using i64 = oc::i64;
using i32 = oc::i32;
using i16 = oc::i16;
using i8 = oc::i8;

using block = oc::block;

template <typename T>
using span = oc::span<T>;

template <typename T>
using Matrix = oc::Matrix<T>;

template <typename T>
using MatrixView = oc::MatrixView<T>;

using OcPRNG = oc::PRNG;
using Socket = coproto::Socket;
using Proto = coproto::task<void>;
using RsCpsiSender = volePSI::RsCpsiSender;
using RsCpsiReceiver = volePSI::RsCpsiReceiver;
using SenderSharing = volePSI::RsCpsiSender::Sharing;
using ReceiverSharing = volePSI::RsCpsiReceiver::Sharing;

using CryptoContext = std::unique_ptr<helib::Context>;
using SecKey = std::unique_ptr<helib::SecKey>;
using PubKey = std::unique_ptr<helib::PubKey>;
using KeyPair = std::pair<SecKey, PubKey>;
using Ciphertext = helib::Ctxt;
using Plaintext = helib::Ptxt<helib::BGV>;
using DoubleCRT = helib::DoubleCRT;

using ZZ = NTL::ZZ;

enum class Mode : u8
{
    Leader = 1,
    Member = 2
};

struct RequiredBase
{
    u64 mNumSend{0};
    oc::BitVector mRecvChoiceBits{};
};

constexpr unsigned long PLAINTEXT_MODULUS_BASE = 2;
