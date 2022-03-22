// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"
#include "netbase.h"


SeedSpec6 lookupDomain(const char *name,int port);


static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}


static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Reacoin";
    const CScript genesisOutputScript = CScript() << ParseHex("04be2821df8b3df6b2fdd39c7cd463b14205578edc6a302550f7fa96c55e3eff9899c7b9017ae5c7aa815702b0f0ac7ee3b8d091c0ef5815798a8e3f719a667f33") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 1000000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0xec3dfaefefc4423b71c726cfdb5fe06c54383453a50a82dcf0ab4080ec388ea4");  // Genesis block
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); 
        consensus.nPowTargetTimespan =  0.5 * 60;
        consensus.nPowTargetSpacing = 0.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 4;
        consensus.nMinerConfirmationWindow = 16;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1647053444;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1647056444;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1647053444;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1647056444;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1647053444;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1647056444;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000000000000d96c7");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0xa7d8933ad1bc523e581d8e929ac4007b328af63dfb2374c69ef7c2a6e3aa827d");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0]  = 0xee;
        pchMessageStart[1]  = 0x3b;
        pchMessageStart[2]  = 0x4f;
        pchMessageStart[3]  = 0x8c;
        nDefaultPort = 7997;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1647033333, 243, 0x20000fff, 1, 25 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xec3dfaefefc4423b71c726cfdb5fe06c54383453a50a82dcf0ab4080ec388ea4"));
        assert(genesis.hashMerkleRoot == uint256S("0x91a94061972898461a81f3b8df94e82266852e9b00647d2ac04cc807b6ac61a0"));

        // Note that of those with the service bits flag, most only support a subset of possible options

        vSeeds.push_back(CDNSSeedData("140.82.11.56", "140.82.11.56"));
        vSeeds.push_back(CDNSSeedData("66.135.0.156", "66.135.0.156"));
        vSeeds.push_back(CDNSSeedData("103.249.70.56", "103.249.70.56"));
        vSeeds.push_back(CDNSSeedData("45.77.150.151", "45.77.150.151"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,60);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,122);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,61);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,205);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0xad)(0xf2)(0x23).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0xad)(0xf2)(0xa8).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (  0, uint256S("0xec3dfaefefc4423b71c726cfdb5fe06c54383453a50a82dcf0ab4080ec388ea4"))  // Genesis block
            (  1, uint256S("0x93191173892d7770ef0543421698d71c726303fbe0becddbffa792ba7652d1de"))
            (  15, uint256S("0x252bc573ceae3bdbcec683f4d5c59dfd602c4f0bd18e562a20e2ef6cee478ea5"))
            (  48, uint256S("0xeedb6a9f08a77b0a4f8b3adaf7831ac3879b6695c5bd80ba800e5a18e7605e16")) // SegWit & CSV activation started
            (  64, uint256S("0xdd3d56ba8521bee73def1e85433a1bfd482592c3dd682eaf3688c94220106d6b")) // SegWit & CSV locked_in 
            (  80, uint256S("0x795135fc0240012d85b818b9b7e735ea562b77bd2f308e2d42d5c0f0401fd6da")) // SegWit & CSV active
            (  101, uint256S("0xa7d8933ad1bc523e581d8e929ac4007b328af63dfb2374c69ef7c2a6e3aa827d")),
        };

        chainTxData = ChainTxData{
            // Data as of block 0
            1647054807, // * UNIX timestamp of last known number of transactions
            102,  // * total number of transactions between genesis and that timestamp
                    //   (the tx=... number in the SetBestChain debug.log lines)
            1.000000  // * estimated number of transactions per second after that timestamp
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 200000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x2bdb49757dfca99f3898f9dd7dee6ee1f81100e5e5ff2b8c8c9a0404a16ff957");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        consensus.nPowTargetSpacing = 0.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 180;
        consensus.nMinerConfirmationWindow = 240;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000100010");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x2bdb49757dfca99f3898f9dd7dee6ee1f81100e5e5ff2b8c8c9a0404a16ff957");

        pchMessageStart[0]  = 0x84;
        pchMessageStart[1]  = 0xd8;
        pchMessageStart[2]  = 0x7a;
        pchMessageStart[3]  = 0x8b;
        nDefaultPort = 17997;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1647033332, 2455, 0x20000fff, 1, 25 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x2bdb49757dfca99f3898f9dd7dee6ee1f81100e5e5ff2b8c8c9a0404a16ff957"));
        assert(genesis.hashMerkleRoot == uint256S("0x91a94061972898461a81f3b8df94e82266852e9b00647d2ac04cc807b6ac61a0"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top

    //    vSeeds.push_back(CDNSSeedData("", ""));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,65);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,105);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,128);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,206);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0xb3)(0xae)(0x70).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0xb3)(0xae)(0xf4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, uint256S("0x2bdb49757dfca99f3898f9dd7dee6ee1f81100e5e5ff2b8c8c9a0404a16ff957")),
        };

        chainTxData = ChainTxData{
            // Data as of block 0
            1647033332,
            0,
            0.000000
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 0.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000100010");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0xbe86e3fe9aa44f7487778477f8b9770e249901991e143437675894fed5c1c476");

        pchMessageStart[0]  = 0xd9;
        pchMessageStart[1]  = 0x85;
        pchMessageStart[2]  = 0xa2;
        pchMessageStart[3]  = 0xf0;
        nDefaultPort = 27997;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1647033331, 20, 0x207fffff, 1, 25 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xbe86e3fe9aa44f7487778477f8b9770e249901991e143437675894fed5c1c476"));
        assert(genesis.hashMerkleRoot == uint256S("0x91a94061972898461a81f3b8df94e82266852e9b00647d2ac04cc807b6ac61a0"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true; 

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0xbe86e3fe9aa44f7487778477f8b9770e249901991e143437675894fed5c1c476"))
        };

        chainTxData = ChainTxData{
            1647033331,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,62);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,104);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,127);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,208);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0xb3)(0xae)(0x70).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0xb3)(0xae)(0xf4).convert_to_container<std::vector<unsigned char> >();
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}


SeedSpec6 lookupDomain(const char *name,int port){
  SeedSpec6 addrseed;
  CNetAddr addrss;
  LookupHost(name,addrss, true);
  for(int i = 0; i < 16;i++){
    addrseed.addr[15-i] = addrss.GetByte(i);
  }
  addrseed.port = port;
  return addrseed;
}

