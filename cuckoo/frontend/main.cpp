#include "../psi/OtMpsi.h"
#include "../psi/Logger.h"
#include "../psi/CryptoUtils.h"
#include "../../BenchmarkThresholds.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Timer.h"
#include "coproto/Socket/AsioSocket.h"
#include "coproto/Socket/BufferingSocket.h"
#include "coproto/coproto.h"
#include <thread>
#include <mutex>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <string>
#include <cmath>
#include <iomanip>
#include <filesystem>
#include <chrono>
#include <coroutine>

std::vector<block> generateInputSet(
    u64 setSize,
    u64 sharedSize,
    u64 partyID,
    bool isLeader,
    OcPRNG &sharedPrng,
    OcPRNG &uniquePrng,
    Logger &logger)
{
    if (sharedSize > setSize)
    {
        throw std::invalid_argument("sharedSize cannot exceed setSize.");
    }

    std::vector<block> inputs(setSize);

    for (u64 i = 0; i < sharedSize; ++i)
    {
        inputs[i] = sharedPrng.get<block>();
    }

    for (u64 i = sharedSize; i < setSize; ++i)
    {
        inputs[i] = uniquePrng.get<block>();
    }

    logger.log((isLeader ? "[Leader]" : "[Member (" + std::to_string(partyID) + ")]"),
               " has generated an input set with ",
               sharedSize, " shared items and ",
               (setSize - sharedSize), " unique items");

    return inputs;
}

std::vector<Socket> initializeLeaderSockets(u64 numMembers, Logger &logger)
{
    std::vector<Socket> sockets;
    sockets.reserve(numMembers);

    std::vector<std::thread> pThreads;
    {
        pThreads.clear();
        for (size_t memberIdx = 0; memberIdx < numMembers; ++memberIdx)
        {
            std::string address = "127.0.0.1:" + std::to_string(30081 + memberIdx);
            try
            {
                sockets.emplace_back(coproto::asioConnect(address, true));
            }
            catch (const std::exception &e)
            {
                logger.error("Leader failed to connect to member ", memberIdx, " at ", address, ": ", e.what());
                throw;
            }
        }

        for (auto &th : pThreads)
        {
            if (th.joinable())
                th.join();
        }
    }

    logger.log("[Leader] has completed network setup");
    return sockets;
}

std::vector<coproto::Socket> initializeMemberSocket(u64 partyID, u64 numParties, Logger &logger)
{
    std::vector<coproto::Socket> sockets(3);

    std::string address = "127.0.0.1:" + std::to_string(30081 + partyID);
    try
    {
        sockets[0] = coproto::asioConnect(address, false);
    }
    catch (const std::exception &e)
    {
        logger.error("Member ", partyID, " failed to connect to leader at ", address, ": ", e.what());
        throw;
    }

    if (partyID != 0)
    {
        address = "127.0.0.1:" + std::to_string(30081 + numParties + partyID);
        try
        {
            sockets[1] = coproto::asioConnect(address, true);
        }
        catch (const std::exception &e)
        {
            logger.error("Member ", partyID, " failed to connect to member", partyID - 1, "at ", address, ": ", e.what());
            throw;
        }
    }

    if (partyID != numParties - 2)
    {
        address = "127.0.0.1:" + std::to_string(30081 + numParties + partyID + 1);
        try
        {
            sockets[2] = coproto::asioConnect(address, false);
        }
        catch (const std::exception &e)
        {
            logger.error("Member ", partyID, " failed to connect to member", partyID + 1, " at ", address, ": ", e.what());
            throw;
        }
    }
    logger.log("[Member (", partyID, ")] has completed network setup");
    return sockets;
}

bool socketIsValid(Socket &s)
{
    if (!s.mImpl)
        return false;

    if (s.closed())
        return false;

    return true;
}

int main(int argc, char **argv)
{
    Logger &logger = Logger::getInstance();

    try
    {
        oc::CLP cmd;
        cmd.parse(argc, argv);

        u64 partyID = cmd.get<u64>("partyID");
        u64 numParties = cmd.get<u64>("numParties");
        u64 threshold = cmd.get<u64>("threshold");
        u64 senderSize = cmd.getOr("senderSize", 100);
        u64 receiverSize = cmd.getOr("receiverSize", 100);
        u64 statSecParam = cmd.getOr("ssp", 40);
        const u64 commonSeedVal = cmd.getOr<u64>("commonSeed", 0xDEADBEEFCAFEBABEULL);
        // bench inputs only
        const block syntheticInputSeed = oc::toBlock(commonSeedVal);
        bool debugFlag = cmd.isSet("debug");
        u64 sharedSize = cmd.getOr(
            "sharedSize",
            ((partyID == numParties - 1) ? receiverSize / 2 : senderSize / 2));
        bool traceableFlag = cmd.isSet("traceable");

        u64 numRuns = cmd.getOr("numRuns", 1);

        bool isLeader = (partyID == numParties - 1);

        logger.setEnabled(debugFlag);

        u64 parameterBits = 0;
        u64 parameterRingDimension = 0;
        if (!get_params(numParties, traceableFlag, parameterBits, parameterRingDimension))
            throw std::invalid_argument(
                traceableFlag ? "traceable mode supports numParties in [4, 36]"
                              : "non-traceable mode supports numParties in [4, 38]");

        if (threshold == 1 || threshold > numParties)
        {
            throw std::invalid_argument(
                "threshold must be 0 (private per-element mode) or in [2, numParties]");
        }

        if (partyID >= numParties)
            throw std::invalid_argument("partyID must be less than numParties");

        if (numRuns == 0)
            throw std::invalid_argument("numRuns must be positive");

        if (receiverSize < senderSize)
            throw std::invalid_argument("receiverSize must be at least senderSize");

        const u64 localSetSize = isLeader ? receiverSize : senderSize;
        if (sharedSize > localSetSize)
            throw std::invalid_argument("sharedSize cannot exceed the local set size");

        if (isLeader)
        {
            namespace fs = std::filesystem;
            const fs::path keysDir = fs::path("keys");
            std::error_code ec;
            if (fs::exists(keysDir, ec))
                fs::remove_all(keysDir, ec);
            fs::create_directories(keysDir, ec);
            if (ec)
                throw std::runtime_error("[Leader] Failed to create " + keysDir.string());
            fs::permissions(keysDir, fs::perms::owner_all,
                            fs::perm_options::replace, ec);
            if (ec)
                throw std::runtime_error("[Leader] Failed to secure " + keysDir.string());
        }
        else
        {
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }

        OtMpPsiLeader leader;
        OtMpPsiMember member;
        if (isLeader)
        {
            leader.init(numParties, threshold, partyID, senderSize, receiverSize, statSecParam,
                        traceableFlag, debugFlag);
        }
        else
        {
            member.init(numParties, threshold, partyID, senderSize, receiverSize, statSecParam,
                        traceableFlag, debugFlag);
        }

        std::vector<std::thread> thrds(numParties);
        std::vector<coproto::Socket> leaderSockets;
        std::vector<coproto::Socket> memberSockets;
        coproto::optional<boost::asio::io_context::work> w(coproto::global_io_context());
        if (isLeader)
        {
            for (auto &t : thrds)
            {
                t = std::thread([&]
                                { coproto::global_io_context().run(); });
            }
            leaderSockets = initializeLeaderSockets(numParties - 1, logger);
        }
        else
        {
            memberSockets = initializeMemberSocket(partyID, numParties, logger);
        }

        std::vector<double> runTimes;
        runTimes.reserve(numRuns);

        oc::Timer timer;
        if (isLeader)
        {
            leader.setTimer(timer);
        }
        else
        {
            member.setTimer(timer);
        }

        if (isLeader)
        {
            leader.Sync(leaderSockets);
        }
        else
        {
            member.Sync(memberSockets);
        }

        if (isLeader)
        {
            logger.log("============================[ SETUP DONE ]============================");
        }

        for (u64 runIdx = 0; runIdx < numRuns; ++runIdx)
        {
            std::vector<block> inputs;
            std::vector<u64> inputThresholds;
            const block runSeed = syntheticInputSeed ^ oc::toBlock(runIdx * 256);
            OcPRNG sharedPrng(runSeed);
            OcPRNG uniquePrng(runSeed ^ oc::toBlock(partyID + 1));
            if (isLeader)
            {
                inputs = generateInputSet(receiverSize, sharedSize, partyID, true, sharedPrng, uniquePrng, logger);
                if (threshold == 0)
                {
                    const auto generated = benchmark_thresholds::generateBalanced(
                        inputs.size(), numParties);
                    inputThresholds.assign(generated.begin(), generated.end());
                    logger.log("[Leader] generated balanced private per-element thresholds in [2, ",
                               numParties, "]");
                }
            }
            else
            {
                inputs = generateInputSet(senderSize, sharedSize, partyID, false, sharedPrng, uniquePrng, logger);
            }

            if (isLeader)
            {
                leader.Sync(leaderSockets);
            }
            else
            {
                member.Sync(memberSockets);
            }

            timer.reset();
            auto start = timer.setTimePoint("start");

            if (isLeader)
            {
                logger.log("[Leader] is running the protocol (Run ", runIdx + 1, " of ", numRuns, ")");
                coproto::sync_wait(leader.Run(inputs, inputThresholds, leaderSockets, traceableFlag));
                logger.log("[Leader] has completed run ", runIdx + 1);
            }
            else
            {
                logger.log("[Member (", partyID, ")] is running the protocol (Run ", runIdx + 1, " of ", numRuns, ")");
                coproto::sync_wait(member.Run(inputs, memberSockets, traceableFlag));
                logger.log("[Member (", partyID, ")] has completed run ", runIdx + 1);
            }

            auto end = timer.setTimePoint("end");
            double elapsedMs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
            double elapsedSec = elapsedMs / 1000.0;
            runTimes.push_back(elapsedSec);

            if (isLeader)
            {
                for (auto &socket : leaderSockets)
                {
                    if (socketIsValid(socket))
                    {
                        coproto::sync_wait(socket.flush());
                    }
                }
            }
            else
            {
                for (auto &socket : memberSockets)
                {
                    if (socketIsValid(socket))
                    {
                        coproto::sync_wait(socket.flush());
                    }
                }
            }
        }

        if (isLeader)
        {
            w.reset();

            for (auto &socket : leaderSockets)
            {
                if (socketIsValid(socket))
                {
                    coproto::sync_wait(socket.flush());
                    coproto::sync_wait(socket.close());
                }
            }

            coproto::global_io_context().stop();

            for (auto &t : thrds)
                t.join();
        }
        else
        {
            for (auto &socket : memberSockets)
            {
                if (socketIsValid(socket))
                {
                    coproto::sync_wait(socket.flush());
                    coproto::sync_wait(socket.close());
                }
            }
        }

        {
            double sum = 0.0;
            for (auto t : runTimes)
                sum += t;
            double average = sum / runTimes.size();

            double variance = 0.0;
            if (runTimes.size() > 1)
            {
                for (auto t : runTimes)
                {
                    double diff = t - average;
                    variance += diff * diff;
                }
                variance /= (runTimes.size() - 1);
            }
            double stddev = std::sqrt(variance);

            u64 totalSentBytes = 0;
            u64 totalRecvBytes = 0;
            if (isLeader)
            {
                for (auto &chl : leaderSockets)
                {
                    totalSentBytes += chl.bytesSent();
                    totalRecvBytes += chl.bytesReceived();
                }
            }
            else if (partyID == 1)
            {
                for (auto &chl : memberSockets)
                {
                    totalSentBytes += chl.bytesSent();
                    totalRecvBytes += chl.bytesReceived();
                }
            }

            double sentMB = static_cast<double>(totalSentBytes) / (1024.0 * 1024.0) / numRuns;
            double recvMB = static_cast<double>(totalRecvBytes) / (1024.0 * 1024.0) / numRuns;

            std::ostringstream oss;
            oss << std::fixed << std::setprecision(3);

            if (isLeader)
            {
                oss << "************************************************************\n";
                oss << "Benchmark Info:\n";
                oss << "------------------------------------------------------------\n"
                    << std::setw(18) << std::left << "Number of Parties:" << numParties << "\n"
                    << std::setw(18) << std::left << "Sender Size:" << senderSize << "\n"
                    << std::setw(18) << std::left << "Receiver Size:" << receiverSize << "\n"
                    << std::setw(18) << std::left << "Number of Runs:" << numRuns << "\n"
                    << std::setw(18) << std::left << "FHE Security Level:" << leader.getCryptoSecurityLevel() << "\n\n";

                oss << "Timing Results:\n";
                oss << "------------------------------------------------------------\n"
                    << std::setw(18) << std::left << "Average time:" << average << " s\n"
                    << std::setw(18) << std::left << "StdDev:" << stddev << " s\n\n";

                oss << "Network Costs:\n";
                oss << "------------------------------------------------------------\n"
                    << std::setw(18) << std::left << "Sent:" << sentMB << " MB\n"
                    << std::setw(18) << std::left << "Received:" << recvMB << " MB\n\n";

                oss << "Role:\n";
                oss << "------------------------------------------------------------\n"
                    << "[Leader] completed " << numRuns << " runs.\n";
            }
            else if (partyID == 1)
            {
                oss << "************************************************************\n";
                oss << "Communication Costs [Member]:\n";
                oss << "------------------------------------------------------------\n"
                    << std::setw(18) << std::left << "Sent:" << sentMB << " MB\n"
                    << std::setw(18) << std::left << "Received:" << recvMB << " MB\n\n"
                    << "[Member] completed " << numRuns << " runs.\n";
            }

            if (isLeader || partyID == 1)
            {
                std::cout << oss.str();
                std::cout.flush();
            }
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
