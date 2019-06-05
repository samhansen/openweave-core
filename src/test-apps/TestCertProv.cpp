/*
 *
 *    Copyright (c) 2019 Google LLC.
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/**
 *    @file
 *      Unit tests for the WeaveCertProvClient class.
 *
 */

#include <stdio.h>
#include <string.h>

#include "ToolCommon.h"
#include "MockCAService.h"
#include "TestWeaveCertData.h"
#include <Weave/Support/ErrorStr.h>
#include <Weave/Core/WeaveTLV.h>
#include <Weave/Profiles/security/WeaveSecurity.h>
#include <Weave/Profiles/security/WeaveCertProvisioning.h>
#include <Weave/Profiles/security/WeaveSig.h>
#include <Weave/Support/crypto/EllipticCurve.h>
#include <Weave/Support/NestCerts.h>
#include <Weave/Support/RandUtils.h>

#if WEAVE_SYSTEM_CONFIG_USE_LWIP
#include "lwip/tcpip.h"
#endif // WEAVE_SYSTEM_CONFIG_USE_LWIP

using namespace nl::Weave::TLV;
using namespace nl::Weave::Profiles::Security;
using namespace nl::Weave::Profiles::Security::CertProvisioning;
using namespace nl::Weave::ASN1;

using nl::Weave::Crypto::EncodedECPublicKey;
using nl::Weave::Crypto::EncodedECPrivateKey;
using nl::Weave::Profiles::Security::CertProvisioning::WeaveCertProvEngine;

#define DEBUG_PRINT_ENABLE 0

#if DEBUG_PRINT_ENABLE
uint32_t debugPrintCount = 0;
#endif

#define TOOL_NAME "TestCertProv"

static bool HandleOption(const char *progName, OptionSet *optSet, int id, const char *name, const char *arg);

const char *gCurTest = NULL;

#define VerifyOrQuit(TST, MSG) \
do { \
    if (!(TST)) \
    { \
        fprintf(stdout, "%s FAILED: ", (gCurTest != NULL) ? gCurTest : __FUNCTION__); \
        fputs(MSG, stdout); \
        fputs("\n", stdout); \
        exit(-1); \
    } \
} while (0)

#define SuccessOrQuit(ERR, MSG) \
do { \
    if ((ERR) != WEAVE_NO_ERROR) \
    { \
        fprintf(stdout, "%s FAILED: ", (gCurTest != NULL) ? gCurTest : __FUNCTION__); \
        fputs(MSG, stdout); \
        fputs(": ", stdout); \
        fputs(ErrorStr(ERR), stdout); \
        fputs("\n", stdout); \
        exit(-1); \
    } \
} while (0)

extern WEAVE_ERROR MakeCertInfo(uint8_t *buf, uint16_t bufSize, uint16_t& certInfoLen,
                                const uint8_t *entityCert, uint16_t entityCertLen,
                                const uint8_t *intermediateCert, uint16_t intermediateCertLen);

static bool sIncludeAuthorizeInfo;

static const uint8_t sDummyPairingToken[] =
{
    0x4d, 0x59, 0x2d, 0x41, 0x43, 0x43, 0x4f, 0x55, 0x4e, 0x54, 0x2d, 0x49, 0x44, 0x18, 0x26, 0x04,
    0xcb, 0xa8, 0xfa, 0x1b, 0x26, 0x05, 0x4b, 0x35, 0x4f, 0x42, 0x37, 0x06, 0x2c, 0x81, 0x10, 0x44,
    0x55, 0x4d, 0x4d, 0x59, 0x2d, 0x41, 0x43, 0x43, 0x4f, 0x55, 0x4e, 0x54, 0x2d, 0x49, 0x44, 0x18,
    0x24, 0x07, 0x02, 0x26, 0x08, 0x25, 0x00, 0x5a, 0x23, 0x30, 0x0a, 0x39, 0x04, 0x2b, 0xd9, 0xdb,
    0x5a, 0x62, 0xef, 0xba,
};
static const uint16_t sDummyPairingTokenLength = sizeof(sDummyPairingToken);

static const uint8_t sDummyPairingInitData[] =
{
    0x6E, 0x3C, 0x71, 0x5B, 0xE0, 0x19, 0xD4, 0x35, 0x83, 0x29, 0x01, 0x18, 0x35, 0x82, 0x29, 0x01,
    0x24, 0x02, 0x05, 0x18, 0x35, 0x84, 0x29, 0x01, 0x36, 0x02, 0x04, 0x02, 0x04, 0x01,
};
static const uint16_t sDummyPairingInitDataLength = sizeof(sDummyPairingInitData);

static uint8_t sDeviceOperationalCert[nl::TestCerts::kTestCertBufSize];
static uint16_t sDeviceOperationalCertLength = 0;

static uint8_t sDeviceOperationalRelatedCerts[nl::TestCerts::kTestCertBufSize];
static uint16_t sDeviceOperationalRelatedCertsLength = 0;

enum ManufAttestType
{
    kManufAttestType_WeaveCert                    = 1,
    kManufAttestType_X509Cert                     = 2,
};

class OpAuthCertProvDelegate : public WeaveNodeOpAuthDelegate
{
public:
    OpAuthCertProvDelegate(uint8_t reqType, bool includeRelatedCerts)
    : mRequestType(reqType),
      mIncludeOpAuthRelatedCerts(includeRelatedCerts)
    {
    }

    // ===== Methods that implement the OpAuthCertProvDelegate interface.

    WEAVE_ERROR EncodeCert(TLVWriter & writer, uint64_t tag) __OVERRIDE
    {
        WEAVE_ERROR err;

        if (IsInitialOpCertRequest())
        {
            // Copy the test device operational certificate into supplied TLV writer.
            err = writer.CopyContainer(tag, TestDevice1_OperationalCert, TestDevice1_OperationalCertLength);
            SuccessOrExit(err);
        }
        else
        {
            if (sDeviceOperationalCertLength > 0)
            {
                // Copy the test device operational certificate into supplied TLV writer.
                err = writer.CopyContainer(tag, sDeviceOperationalCert, sDeviceOperationalCertLength);
                SuccessOrExit(err);
            }
            else
            {
                // Copy the test device operational certificate into supplied TLV writer.
                err = writer.CopyContainer(tag, TestDevice1_Cert, TestDevice1_CertLength);
                SuccessOrExit(err);
            }
        }

    exit:
        return err;
    }

    WEAVE_ERROR EncodeRelatedCerts(TLVWriter & writer, uint64_t tag) __OVERRIDE
    {
        WEAVE_ERROR err = WEAVE_NO_ERROR;
        TLVType containerType;

        if (mIncludeOpAuthRelatedCerts)
        {
            if (sDeviceOperationalRelatedCertsLength > 0)
            {
                // Copy the intermediate test device CA certificate.
                err = writer.CopyContainer(tag, sDeviceOperationalRelatedCerts, sDeviceOperationalRelatedCertsLength);
                SuccessOrExit(err);
            }
            else
            {
                // Start the RelatedCertificates array. This contains the list of certificates the signature verifier
                // will need to verify the signature.
                err = writer.StartContainer(tag, kTLVType_Array, containerType);
                SuccessOrExit(err);

                // Copy the intermediate test device CA certificate.
                err = writer.CopyContainer(AnonymousTag, nl::NestCerts::Development::DeviceCA::Cert, nl::NestCerts::Development::DeviceCA::CertLength);
                SuccessOrExit(err);

                err = writer.EndContainer(containerType);
                SuccessOrExit(err);
            }
        }

    exit:
        return err;
    }

    WEAVE_ERROR EncodeSig(const uint8_t * hash, uint8_t hashLen, TLVWriter & writer, uint64_t tag) __OVERRIDE
    {
        return GenerateAndEncodeWeaveECDSASignature(writer, tag, hash, hashLen, TestDevice1_OperationalPrivateKey, TestDevice1_OperationalPrivateKeyLength);
    }

private:
    uint8_t mRequestType;
    bool mIncludeOpAuthRelatedCerts;

    inline bool IsInitialOpCertRequest(void) { return (mRequestType == WeaveCertProvEngine::kReqType_GetInitialOpDeviceCert); }
};

class ManufAttestCertProvDelegate : public WeaveNodeManufAttestDelegate
{
public:
    ManufAttestCertProvDelegate(uint8_t manufAttestType, bool includeRelatedCerts)
    : mManufAttestType(manufAttestType),
      mIncludeManufAttestRelatedCerts(includeRelatedCerts)
    {
    }

    // ===== Methods that implement the ManufAttestCertProvDelegate interface.

    WEAVE_ERROR EncodeInfo(TLVWriter & writer) __OVERRIDE
    {
        WEAVE_ERROR err;
        TLVType containerType;

        if (IsWeaveProvisionedDevice())
        {
            err = writer.StartContainer(ProfileTag(kWeaveProfile_Security, kTag_ManufAttestInfo_Weave), kTLVType_Structure, containerType);
            SuccessOrExit(err);

            // Copy the test device manufacturer attestation (factory provisioned) certificate into supplied TLV writer.
            err = writer.CopyContainer(ContextTag(kTag_ManufAttestInfo_Weave_DeviceCert), TestDevice1_Cert, TestDevice1_CertLength);
            SuccessOrExit(err);

            if (mIncludeManufAttestRelatedCerts)
            {
                TLVType containerType2;

                // Start the RelatedCertificates array. This contains the list of certificates the signature verifier
                // will need to verify the signature.
                err = writer.StartContainer(ContextTag(kTag_ManufAttestInfo_Weave_RelatedCerts), kTLVType_Array, containerType2);
                SuccessOrExit(err);

                // Copy the intermediate test device CA certificate.
                err = writer.CopyContainer(AnonymousTag, nl::NestCerts::Development::DeviceCA::Cert, nl::NestCerts::Development::DeviceCA::CertLength);
                SuccessOrExit(err);

                err = writer.EndContainer(containerType2);
                SuccessOrExit(err);
            }

            err = writer.EndContainer(containerType);
            SuccessOrExit(err);
        }
        else
        {
            // TODO: Support X509 ASN1 encoded certificate (kTag_ManufAttestInfo_X509)
            ExitNow(err = WEAVE_ERROR_NOT_IMPLEMENTED);
        }

    exit:
        return err;
    }

    WEAVE_ERROR EncodeSig(const uint8_t * hash, uint8_t hashLen, TLVWriter & writer) __OVERRIDE
    {
        WEAVE_ERROR err;

        err = writer.Put(ContextTag(kTag_GetCertReqMsg_ManufAttestSigAlgo), static_cast<uint16_t>(ASN1::kOID_SigAlgo_ECDSAWithSHA256));
        SuccessOrExit(err);

        if (IsWeaveProvisionedDevice())
        {
            err = GenerateAndEncodeWeaveECDSASignature(writer, ContextTag(kTag_GetCertReqMsg_ManufAttestSig_ECDSA), hash, hashLen,
                                                       TestDevice1_PrivateKey, TestDevice1_PrivateKeyLength);
            SuccessOrExit(err);
        }
        else
        {
            // TODO: Support RSA Signature (kTag_GetCertReqMsg_ManufAttestSig_RSA)
            ExitNow(err = WEAVE_ERROR_NOT_IMPLEMENTED);
        }

    exit:
        return err;
    }

private:
    uint8_t mManufAttestType;
    bool mIncludeManufAttestRelatedCerts;

    inline bool IsWeaveProvisionedDevice(void) { return (mManufAttestType == kManufAttestType_WeaveCert); }
};

/**
 *  Handler for Certificate Provisioning Client API events.
 *
 *  @param[in]  appState    A pointer to application-defined state information associated with the client object.
 *  @param[in]  eventType   Event ID passed by the event callback.
 *  @param[in]  inParam     Reference of input event parameters passed by the event callback.
 *  @param[in]  outParam    Reference of output event parameters passed by the event callback.
 *
 */
static void CertProvEventCallback(void * appState, WeaveCertProvEngine::EventType eventType, const WeaveCertProvEngine::InEventParam & inParam, WeaveCertProvEngine::OutEventParam & outParam)
{
    WEAVE_ERROR err = WEAVE_NO_ERROR;
    WeaveCertificateSet certSet;
    bool certSetInitialized = false;

    switch (eventType)
    {
    case WeaveCertProvEngine::kEvent_PrepareAuthorizeInfo:
    {
        WeaveLogDetail(SecurityManager, "WeaveCertProvEngine::kEvent_PrepareAuthorizeInfo");

        TLVWriter * writer = inParam.PrepareAuthorizeInfo.Writer;

        if (sIncludeAuthorizeInfo)
        {
            TLVType containerType;

            err = writer->StartContainer(ProfileTag(kWeaveProfile_Security, kTag_GetCertAuthorizeInfo), kTLVType_Structure, containerType);
            SuccessOrExit(err);

            // Pairing Token.
            err = writer->PutBytes(ContextTag(kTag_GetCertAuthorizeInfo_PairingToken), sDummyPairingToken, sDummyPairingTokenLength);
            SuccessOrExit(err);

            // Pairing Initialization Data.
            err = writer->PutBytes(ContextTag(kTag_GetCertAuthorizeInfo_PairingInitData), sDummyPairingInitData, sDummyPairingInitDataLength);
            SuccessOrExit(err);

            err = writer->EndContainer(containerType);
            SuccessOrExit(err);
        }
        break;
    }

    case WeaveCertProvEngine::kEvent_ResponseReceived:
    {
        WeaveLogDetail(SecurityManager, "WeaveCertProvEngine::kEvent_ResponseReceived");

        if (inParam.ResponseReceived.ReplaceCert)
        {
            WeaveCertificateData *certData;
            const uint8_t * cert = inParam.ResponseReceived.Cert;
            uint16_t certLen = inParam.ResponseReceived.CertLen;
            const uint8_t * relatedCerts = inParam.ResponseReceived.RelatedCerts;
            uint16_t relatedCertsLen = inParam.ResponseReceived.RelatedCertsLen;

            err = certSet.Init(4, nl::TestCerts::kTestCertBufSize);
            SuccessOrExit(err);

            certSetInitialized = true;

            // Load service assigned operational certificate.
            // Even when callback function doesn't do certificate validation this step is recommended
            // to make sure that message wasn't corrupted in transmission.
            err = certSet.LoadCert(cert, certLen, kDecodeFlag_GenerateTBSHash, certData);
            SuccessOrExit(err);

            if (relatedCerts != NULL)
            {
                // Load intermediate certificate.
                // Even when callback function doesn't do certificate validation this step is recommended
                // to make sure that message wasn't corrupted in transmission.
              err = certSet.LoadCerts(relatedCerts, relatedCertsLen, kDecodeFlag_GenerateTBSHash);
              SuccessOrExit(err);
            }

            // This certificate validation step is added for testing purposes only.
            // In reality, device doesn't have to validate certificate issued by the CA service.
            err = ValidateWeaveDeviceCert(certSet);
            SuccessOrExit(err);

            // Store service issued operational device certificate.
            VerifyOrExit(certLen <= sizeof(sDeviceOperationalCert), err = WEAVE_ERROR_BUFFER_TOO_SMALL);
            memcpy(sDeviceOperationalCert, cert, certLen);
            sDeviceOperationalCertLength = certLen;

            // Store device intermediate certificates related to the device certificate.
            VerifyOrExit(relatedCertsLen <= sizeof(sDeviceOperationalRelatedCerts), err = WEAVE_ERROR_BUFFER_TOO_SMALL);
            memcpy(sDeviceOperationalRelatedCerts, relatedCerts, relatedCertsLen);
            sDeviceOperationalRelatedCertsLength = relatedCertsLen;

            WeaveLogDetail(SecurityManager, "Replaced Operational Device Certificate");
        }
        else
        {
            WeaveLogDetail(SecurityManager, "No Need to Replace Operational Device Certificate");
        }

        inParam.Source->AbortCertificateProvisioning();

        break;
    }

    case WeaveCertProvEngine::kEvent_CommunicationError:
    {
        if (inParam.CommunicationError.Reason == WEAVE_ERROR_STATUS_REPORT_RECEIVED)
        {
            WeaveLogError(SecurityManager, "WeaveCertProvEngine::kEvent_CommunicationError, Received StatusReport = %s",
                          nl::StatusReportStr(inParam.CommunicationError.RcvdStatusReport->mProfileId, inParam.CommunicationError.RcvdStatusReport->mStatusCode));
        }
        else
        {
            WeaveLogError(SecurityManager, "WeaveCertProvEngine::kEvent_CommunicationError, err = %s", ErrorStr(inParam.CommunicationError.Reason));
        }

        inParam.Source->AbortCertificateProvisioning();

        break;
    }

    default:
        WeaveLogError(SecurityManager, "WeaveCertProvEngine: unrecognized API event");
        break;
    }

exit:
    if (eventType == WeaveCertProvEngine::kEvent_PrepareAuthorizeInfo)
        outParam.PrepareAuthorizeInfo.Error = err;
    else if (eventType == WeaveCertProvEngine::kEvent_ResponseReceived)
        outParam.ResponseReceived.Error = err;

    if (certSetInitialized)
        certSet.Release();
}

class MessageMutator
{
public:
    virtual ~MessageMutator() { }
    virtual void Reset() = 0;
    virtual void MutateMessage(const char *msgType, PacketBuffer *msgBuf, WeaveCertProvEngine& clientEng, MockCAService& serviceEng) = 0;
    virtual bool IsComplete() = 0;
};

class NullMutator : public MessageMutator
{
public:
    virtual void Reset() { }
    virtual void MutateMessage(const char *msgType, PacketBuffer *msgBuf, WeaveCertProvEngine& clientEng, MockCAService& serviceEng) { };
    virtual bool IsComplete() { return true; }
};

static NullMutator gNullMutator;

class MessageFuzzer : public MessageMutator
{
public:
    MessageFuzzer(const char *msgType)
    {
        mMsgType = msgType;
        mIndex = 0;
        mSkipStart = 0;
        mSkipLen = 0;
        mComplete = false;
        mTimeLimit = 0;
    }

    virtual void Reset() { mIndex = 0; mComplete = false; }

    virtual void MutateMessage(const char *msgType, PacketBuffer *msgBuf, WeaveCertProvEngine& clientEng, MockCAService& serviceEng)
    {
        if (strcmp(msgType, mMsgType) == 0)
        {
            uint8_t *msgStart = msgBuf->Start();
            uint16_t msgLen = msgBuf->DataLength();
            uint8_t fuzzMask;

            VerifyOrQuit(msgLen > 0, "Unexpected packet length");

            if (mIndex == mSkipStart)
                mIndex += mSkipLen;

            if (mIndex >= msgLen)
                mIndex = msgLen - 1;

            do
                fuzzMask = GetRandU8();
            while (fuzzMask == 0 ||
                   // Make sure the EndOfContainer element modifies its Type field - otherwize it might still be interpreted as EndOfContainer element.
                   ((msgStart[mIndex] == kTLVElementType_EndOfContainer) && ((fuzzMask & kTLVTypeMask) == 0)));

            printf("MessageFuzzer: %s message mutated (offset %u, fuzz mask 0x%02X, orig value 0x%02X)\n", msgType, mIndex, fuzzMask, msgStart[mIndex]);

            msgStart[mIndex] ^= fuzzMask;

            mIndex++;

            mComplete = (mIndex >= msgLen);
        }
    }

    virtual bool IsComplete()
    {
        if (mComplete)
            return true;

        if (mTimeLimit != 0)
        {
            time_t now;
            time(&now);
            if (now >= mTimeLimit)
                return true;
        }

        return false;
    }

    MessageFuzzer& Skip(uint16_t start, uint16_t len) { mSkipStart = start; mSkipLen = len; return *this; }

    MessageFuzzer& TimeLimit(time_t timeLimit) { mTimeLimit = timeLimit; return *this; }

private:
    const char *mMsgType;
    uint16_t mIndex;
    uint16_t mSkipStart;
    uint16_t mSkipLen;
    bool mComplete;
    time_t mTimeLimit;
};

class CertProvEngineTest
{
public:
    CertProvEngineTest(const char *testName)
    {
        mTestName = testName;
        memset(mExpectedErrors, 0, sizeof(mExpectedErrors));
        mMutator = &gNullMutator;
        mManufAttestType = kManufAttestType_WeaveCert;
        mReqType = WeaveCertProvEngine::kReqType_GetInitialOpDeviceCert;
        mLogMessageData = false;
        mClientIncludeAuthorizeInfo = false;
        mClientIncludeOpAuthRelatedCerts = false;
        mClientIncludeManufAttestInfo = true;
        mClientIncludeManufAttestRelatedCerts = false;
        mServerIncludeDeviceCACert = false;
    }

    const char *TestName() const { return mTestName; }

    uint8_t RequestType() const { return mReqType; }
    CertProvEngineTest& RequestType (uint8_t val) { mReqType = val; return *this; }

    uint8_t ManufAttestType() const { return mManufAttestType; }
    CertProvEngineTest& ManufAttestType (uint8_t val) { mManufAttestType = val; return *this; }

    bool LogMessageData() const { return mLogMessageData; }
    CertProvEngineTest& LogMessageData(bool val) { mLogMessageData = val; return *this; }

    bool ClientIncludeAuthorizeInfo() const { return mClientIncludeAuthorizeInfo; }
    CertProvEngineTest& ClientIncludeAuthorizeInfo(bool val) { mClientIncludeAuthorizeInfo = val; return *this; }

    bool ClientIncludeOpAuthRelatedCerts() const { return mClientIncludeOpAuthRelatedCerts; }
    CertProvEngineTest& ClientIncludeOpAuthRelatedCerts(bool val) { mClientIncludeOpAuthRelatedCerts = val; return *this; }

    bool ClientIncludeManufAttestInfo() const { return mClientIncludeManufAttestInfo; }
    CertProvEngineTest& ClientIncludeManufAttestInfo(bool val) { mClientIncludeManufAttestInfo = val; return *this; }

    bool ClientIncludeManufAttestRelatedCerts() const { return mClientIncludeManufAttestRelatedCerts; }
    CertProvEngineTest& ClientIncludeManufAttestRelatedCerts(bool val) { mClientIncludeManufAttestRelatedCerts = val; return *this; }

    bool ServerIncludeRelatedCerts() const { return mServerIncludeDeviceCACert; }
    CertProvEngineTest& ServerIncludeRelatedCerts(bool val) { mServerIncludeDeviceCACert = val; return *this; }

    CertProvEngineTest& ExpectError(WEAVE_ERROR err)
    {
        return ExpectError(NULL, err);
    }

    CertProvEngineTest& ExpectError(const char *opName, WEAVE_ERROR err)
    {
        for (size_t i = 0; i < kMaxExpectedErrors; i++)
        {
            if (mExpectedErrors[i].Error == WEAVE_NO_ERROR)
            {
                mExpectedErrors[i].Error = err;
                mExpectedErrors[i].OpName = opName;
                break;
            }
        }

        return *this;
    }

    bool IsExpectedError(const char *opName, WEAVE_ERROR err) const
    {
        for (size_t i = 0; i < kMaxExpectedErrors && mExpectedErrors[i].Error != WEAVE_NO_ERROR; i++)
        {
            if (mExpectedErrors[i].Error == err &&
                (mExpectedErrors[i].OpName == NULL || strcmp(mExpectedErrors[i].OpName, opName) == 0))
                return true;
        }
        return false;
    }

    bool IsSuccessExpected() const { return mExpectedErrors[0].Error == WEAVE_NO_ERROR; }

    CertProvEngineTest& Mutator(MessageMutator *mutator) { mMutator = mutator; return *this; }

    void Run() const;

private:
    enum
    {
        kMaxExpectedErrors = 32
    };

    struct ExpectedError
    {
        const char *OpName;
        WEAVE_ERROR Error;
    };

    const char *mTestName;
    uint8_t mReqType;
    uint8_t mManufAttestType;
    bool mLogMessageData;
    bool mClientIncludeAuthorizeInfo;
    bool mClientIncludeOpAuthRelatedCerts;
    bool mClientIncludeManufAttestInfo;
    bool mClientIncludeManufAttestRelatedCerts;
    bool mServerIncludeDeviceCACert;
    ExpectedError mExpectedErrors[kMaxExpectedErrors];
    MessageMutator *mMutator;
};

void CertProvEngineTest::Run() const
{
    WEAVE_ERROR err;
    WeaveCertProvEngine clientEng;
    MockCAService serviceEng;
    PacketBuffer *msgBuf = NULL;
    PacketBuffer *msgBuf2 = NULL;
    OpAuthCertProvDelegate opAuthDelegate(RequestType(), ClientIncludeOpAuthRelatedCerts());
    ManufAttestCertProvDelegate manufAttestDelegate(ManufAttestType(), ClientIncludeManufAttestRelatedCerts());
    WeaveExchangeManager exchangeMgr;

    printf("========== Starting Test: %s\n", TestName());
    printf("    Manufacturer Attestation Type             : %s\n", (ManufAttestType() == kManufAttestType_WeaveCert) ? "Weave Certificate" : "X509 Certificate");
    printf("    Request Type                              : %s\n", (RequestType() == WeaveCertProvEngine::kReqType_GetInitialOpDeviceCert) ? "GetInitialOpDeviceCert" : "RotateCert");
    printf("    Client Include Authorization Info         : %s\n", ClientIncludeAuthorizeInfo() ? "Yes" : "No");
    printf("    Client Include Op Related Certs           : %s\n", ClientIncludeOpAuthRelatedCerts() ? "Yes" : "No");
    printf("    Client Include Manufacturer Attest Info   : %s\n", ClientIncludeManufAttestInfo() ? "Yes" : "No");
    printf("    Client Include Manuf Attest Related Certs : %s\n", ClientIncludeManufAttestRelatedCerts() ? "Yes" : "No");
    printf("    Server Include Op Related Certs           : %s\n", ServerIncludeRelatedCerts() ? "Yes" : "No");
    printf("    Expected Error                            : %s\n", IsSuccessExpected() ? "No" : "Yes");
    printf("==========\n");

    gCurTest = TestName();

    mMutator->Reset();

    sIncludeAuthorizeInfo = ClientIncludeAuthorizeInfo();

    do
    {
        clientEng.Init(NULL, &opAuthDelegate, &manufAttestDelegate, CertProvEventCallback, NULL);
        serviceEng.Init(&exchangeMgr);
        serviceEng.LogMessageData(LogMessageData());
        serviceEng.IncludeRelatedCerts(ServerIncludeRelatedCerts());

        // ========== Client Forms GetCertificateRequest ==========

        {
            msgBuf = PacketBuffer::New();
            VerifyOrQuit(msgBuf != NULL, "PacketBuffer::New() failed");

            printf("Calling WeaveCertProvEngine::GenerateGetCertificateRequest\n");

            err = clientEng.GenerateGetCertificateRequest(msgBuf, RequestType(), ClientIncludeManufAttestInfo());

#if DEBUG_PRINT_ENABLE
        {
            debugPrintCount++;
            printf("// ------------------- GET CERTIFICATE REQUEST MESSAGE EXAMPLE %02d --------------------------\n", debugPrintCount);
            printf("// GetCertReqMsg_ReqType                : %s\n", (RequestType() == WeaveCertProvEngine::kReqType_GetInitialOpDeviceCert) ? "Get Initial Operational Device Certificate" :
                                                                                                                                               "Rotate Operational Device Certificate");
            printf("// GetCertAuthorizeInfo                 : %s\n", ClientIncludeAuthorizeInfo() ? "Yes" : "---");
            printf("// GetCertReqMsg_OpDeviceCert           : TestDevice1_OperationalCert\n");
            printf("// GetCertReqMsg_OpRelatedCerts         : %s\n", ClientIncludeOpAuthRelatedCerts() ? "nl::NestCerts::Development::DeviceCA::Cert" : "---");
            printf("// ManufAttestInfo_Weave_DeviceCert     : %s\n", ClientIncludeManufAttestInfo() ? "TestDevice1_Cert" : "---");
            printf("// ManufAttestInfo_Weave_RelatedCerts   : %s\n", ClientIncludeManufAttestRelatedCerts() ? "nl::NestCerts::Development::DeviceCA::Cert" : "---");
            printf("// GetCertReqMsg_OpDeviceSigAlgo        : ECDSAWithSHA256\n");
            printf("// GetCertReqMsg_OpDeviceSig_ECDSA      : Signature\n");
            printf("// GetCertReqMsg_ManufAttestSigAlgo     : %s\n", ClientIncludeManufAttestInfo() ? "ECDSAWithSHA256" : "---");
            printf("// GetCertReqMsg_ManufAttestSig_ECDSA   : %s\n", ClientIncludeManufAttestInfo() ? "Signature" : "---");
            printf("// -----------------------------------------------------------------------------------------\n");

            uint8_t * data = msgBuf->Start();
            uint16_t dataLen = msgBuf->DataLength();

            printf("\nextern const uint8_t sGetCertRequestMsg_Example%02d[] =\n{", debugPrintCount);

            for (int i = 0; i < dataLen; i++)
            {
                if (i % 16 == 0)
                    printf("\n    ");
                printf("0x%02X, ", data[i]);
            }

            printf("\n}\n\n");
        }
#endif // DEBUG_PRINT_ENABLE

            if (IsExpectedError("WeaveCertProvEngine::GenerateGetCertificateRequest", err))
                goto onExpectedError;

            SuccessOrQuit(err, "WeaveCertProvEngine::GenerateGetCertificateRequest() failed");
        }

        // ========== Client Sends GetCertificateRequest to the CA Service ==========

        mMutator->MutateMessage("GetCertificateRequest", msgBuf, clientEng, serviceEng);

        printf("Client->Service: GetCertificateRequest Message (%d bytes)\n", msgBuf->DataLength());
        if (LogMessageData())
            DumpMemory(msgBuf->Start(), msgBuf->DataLength(), "    ", 16);

        // ========== CA Service Processes GetCertificateRequest ==========

        {
            printf("Service: Calling ProcessGetCertificateRequest\n");

            GetCertificateRequestMessage msg;

            err = serviceEng.ProcessGetCertificateRequest(msgBuf, msg);

            if (IsExpectedError("Service:ProcessGetCertificateRequest", err))
                goto onExpectedError;

            SuccessOrQuit(err, "MockCAService::ProcessGetCertificateRequest() failed");

            // ========== CA Service Forms GetCertificateResponse ==========

            msgBuf2 = PacketBuffer::New();
            VerifyOrQuit(msgBuf2 != NULL, "PacketBuffer::New() failed");

            printf("Service: Calling GenerateGetCertificateResponse\n");

            err = serviceEng.GenerateGetCertificateResponse(msgBuf2, *msg.mOperationalCertSet.Certs);

            PacketBuffer::Free(msgBuf);
            msgBuf = NULL;

            if (IsExpectedError("Service:GenerateGetCertificateResponse", err))
                goto onExpectedError;

            SuccessOrQuit(err, "MockCAService::GenerateGetCertificateResponse() failed");
        }

        // ========== CA Service Sends GetCertificateResponse to Client ==========

        mMutator->MutateMessage("GetCertificateResponse", msgBuf2, clientEng, serviceEng);

        printf("Service->Client: GetCertificateResponse Message (%d bytes)\n", msgBuf2->DataLength());
        if (LogMessageData())
            DumpMemory(msgBuf2->Start(), msgBuf2->DataLength(), "    ", 16);

        // ========== Client Processes GetCertificateResponse ==========

        {
            printf("Client: Calling ProcessGetCertificateResponse\n");

            err = clientEng.ProcessGetCertificateResponse(msgBuf2);

            PacketBuffer::Free(msgBuf2);
            msgBuf2 = NULL;

            if (IsExpectedError("Client:ProcessGetCertificateResponse", err))
                goto onExpectedError;

            SuccessOrQuit(err, "CertProvisioningClient::ProcessGetCertificateResponse() failed");
        }

        VerifyOrQuit(clientEng.GetState() == WeaveCertProvEngine::kState_Idle, "Client not in Idle state");

        // TODO: Check the result here.

        VerifyOrQuit(IsSuccessExpected(), "Test succeeded unexpectedly");

    onExpectedError:

        if (msgBuf != NULL)
        {
            PacketBuffer::Free(msgBuf);
            msgBuf = NULL;
        }

        if (msgBuf2 != NULL)
        {
            PacketBuffer::Free(msgBuf2);
            msgBuf2 = NULL;
        }

        clientEng.Shutdown();
        serviceEng.Shutdown();

    } while (!mMutator->IsComplete());

    printf("Test Complete: %s\n", TestName());

    gCurTest = NULL;
}

void CertProvEngineTests_GetInitialCertTests()
{
    bool logData = true;

    struct TestCase
    {
        uint8_t maType;             // Manufacturer Attestation Type.
        uint8_t reqType;            // Request Type.
        bool cIncludeAI;            // Client Includes Request Authorization Information.
        bool cIncludeOpRC;          // Client Includes Operational Device Related Certificates.
        bool cIncludeMA;            // Client Includes Manufacturer Attestation Information.
        bool cIncludeMARC;          // Client Includes Manufacturer Attestation Related Certificates.
        bool sIncludeSOpRC;         // Server Includes Operational Device Related Certificates.
        struct
        {
            WEAVE_ERROR err;        // Expected error.
            const char * opName;    // Function name.
        } ExpectedResult;
    };

    enum
    {
        // Short-hand names to make the test cases table more concise.
        WeaveCert             = kManufAttestType_WeaveCert,
        X509Cert              = kManufAttestType_X509Cert,
        InitReq               = WeaveCertProvEngine::kReqType_GetInitialOpDeviceCert,
        RotateReq             = WeaveCertProvEngine::kReqType_RotateOpDeviceCert,
    };

    static const TestCase sTestCases[] =
    {
        // Manuf                 Client     Client     Client     Client     Server
        // Attest     Req        Includes   Includes   Includes   Includes   Includes
        // Type       Type       AuthInfo   OpRCerts   ManufAtt   MARCerts   OpRCerts    Expected Result
        // ==============================================================================================================

        // Basic testing of certificate provisioning protocol with different load orders.
        {  WeaveCert, InitReq,   false,     false,     false,     false,     false,      { WEAVE_ERROR_INVALID_ARGUMENT, "Service:ProcessGetCertificateRequest" } },
        {  WeaveCert, InitReq,   false,     false,     true,      false,     false,      { WEAVE_NO_ERROR, NULL } },
        {  WeaveCert, InitReq,   false,     false,     true,      true,      true,       { WEAVE_NO_ERROR, NULL } },
        {  WeaveCert, InitReq,   false,     true,      true,      true,      false,      { WEAVE_ERROR_UNEXPECTED_TLV_ELEMENT, "Service:ProcessGetCertificateRequest" } },

        {  WeaveCert, InitReq,   true,      false,     false,     false,     false,      { WEAVE_ERROR_INVALID_ARGUMENT, "Service:ProcessGetCertificateRequest" } },
        {  WeaveCert, InitReq,   true,      false,     true,      false,     false,      { WEAVE_NO_ERROR, NULL } },
        {  WeaveCert, InitReq,   true,      false,     true,      true,      true,       { WEAVE_NO_ERROR, NULL } },
        {  WeaveCert, InitReq,   true,      true,      true,      true,      false,      { WEAVE_ERROR_UNEXPECTED_TLV_ELEMENT, "Service:ProcessGetCertificateRequest" } },

        {  WeaveCert, RotateReq, false,     false,     false,     false,     false,      { WEAVE_NO_ERROR, NULL } },
        {  WeaveCert, RotateReq, false,     false,     true,      false,     false,      { WEAVE_NO_ERROR, NULL } },
        {  WeaveCert, RotateReq, false,     false,     true,      true,      true,       { WEAVE_NO_ERROR, NULL } },
        {  WeaveCert, RotateReq, false,     true,      true,      true,      false,      { WEAVE_NO_ERROR, NULL } },

        {  WeaveCert, RotateReq, true,      false,     false,     false,     false,      { WEAVE_NO_ERROR, NULL } },
        {  WeaveCert, RotateReq, true,      false,     true,      false,     false,      { WEAVE_NO_ERROR, NULL } },
        {  WeaveCert, RotateReq, true,      false,     true,      true,      true,       { WEAVE_NO_ERROR, NULL } },
        {  WeaveCert, RotateReq, true,      true,      true,      true,      false,      { WEAVE_NO_ERROR, NULL } },
    };

    static const size_t sNumTestCases = sizeof(sTestCases) / sizeof(sTestCases[0]);

    for (unsigned i = 0; i < sNumTestCases; i++)
    {
        const TestCase& testCase = sTestCases[i];

        // Basic sanity test
        CertProvEngineTest("Basic")
            .ManufAttestType(testCase.maType)
            .RequestType(testCase.reqType)
            .ClientIncludeAuthorizeInfo(testCase.cIncludeAI)
            .ClientIncludeOpAuthRelatedCerts(testCase.cIncludeOpRC)
            .ClientIncludeManufAttestInfo(testCase.cIncludeMA)
            .ClientIncludeManufAttestRelatedCerts(testCase.cIncludeMARC)
            .ServerIncludeRelatedCerts(testCase.sIncludeSOpRC)
            .ExpectError(testCase.ExpectedResult.opName, testCase.ExpectedResult.err)
            .LogMessageData(logData)
            .Run();
    }
}

uint32_t gFuzzTestDurationSecs = 5;

void CertProvEngineTests_FuzzTests()
{
    time_t now, endTime;

    time(&now);
    endTime = now + gFuzzTestDurationSecs;

    while (true)
    {
        time(&now);
        if (now >= endTime)
            break;

        // Fuzz contents of GetCertificateRequest message, verify protocol error.
        {
            MessageFuzzer fuzzer = MessageFuzzer("GetCertificateRequest")
                // .Skip(8, 8)
                .TimeLimit(endTime);
            CertProvEngineTest("Mutate GetCertificateRequest")
                .Mutator(&fuzzer)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_WRONG_TLV_TYPE)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_UNEXPECTED_TLV_ELEMENT)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_INVALID_TLV_TAG)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_INVALID_TLV_ELEMENT)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_END_OF_TLV)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_TLV_UNDERRUN)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_UNKNOWN_IMPLICIT_TLV_TAG)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_UNSUPPORTED_ELLIPTIC_CURVE)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_UNSUPPORTED_SIGNATURE_TYPE)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_INVALID_SIGNATURE)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_INVALID_ARGUMENT)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_CA_CERT_NOT_FOUND)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_UNSUPPORTED_CERT_FORMAT)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_WRONG_CERT_SUBJECT)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_WRONG_CERT_TYPE)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_INCORRECT_STATE)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_CERT_NOT_VALID_YET)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_CERT_EXPIRED)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_CERT_USAGE_NOT_ALLOWED)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_WRONG_CERT_SIGNATURE_ALGORITHM)
                .ExpectError("Service:ProcessGetCertificateRequest", ASN1_ERROR_UNKNOWN_OBJECT_ID)
                .ExpectError("Service:ProcessGetCertificateRequest", ASN1_ERROR_OVERFLOW)
                .ExpectError("Service:ProcessGetCertificateRequest", ASN1_ERROR_UNSUPPORTED_ENCODING)
                .ExpectError("Service:ProcessGetCertificateRequest", WEAVE_ERROR_NOT_IMPLEMENTED)  // TODO: Remove once X509 RSA Certificates are Supported
                .Run();
        }

        // Fuzz contents of GetCertificateResponse message, verify protocol error.
        {
            MessageFuzzer fuzzer = MessageFuzzer("GetCertificateResponse")
                .TimeLimit(endTime);
            CertProvEngineTest("Mutate GetCertificateResponse")
                .Mutator(&fuzzer)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_WRONG_TLV_TYPE)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_UNEXPECTED_TLV_ELEMENT)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_INVALID_TLV_TAG)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_INVALID_TLV_ELEMENT)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_END_OF_TLV)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_TLV_UNDERRUN)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_UNKNOWN_IMPLICIT_TLV_TAG)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_UNSUPPORTED_ELLIPTIC_CURVE)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_UNSUPPORTED_SIGNATURE_TYPE)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_INVALID_SIGNATURE)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_INVALID_ARGUMENT)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_CA_CERT_NOT_FOUND)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_UNSUPPORTED_CERT_FORMAT)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_WRONG_CERT_SUBJECT)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_WRONG_CERT_TYPE)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_INCORRECT_STATE)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_CERT_NOT_VALID_YET)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_CERT_EXPIRED)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_CERT_USAGE_NOT_ALLOWED)
                .ExpectError("Client:ProcessGetCertificateResponse", ASN1_ERROR_UNKNOWN_OBJECT_ID)
                .ExpectError("Client:ProcessGetCertificateResponse", ASN1_ERROR_OVERFLOW)
                .ExpectError("Client:ProcessGetCertificateResponse", ASN1_ERROR_UNSUPPORTED_ENCODING)
                .ExpectError("Client:ProcessGetCertificateResponse", WEAVE_ERROR_NOT_IMPLEMENTED)  // TODO: Remove once X509 RSA Certificates are Supported
                .LogMessageData(false)
                .Run();
        }
    }

}

static OptionDef gToolOptionDefs[] =
{
    { "fuzz-duration", kArgumentRequired, 'f' },
    { NULL }
};

static const char *const gToolOptionHelp =
    "  -f, --fuzz-duration <seconds>\n"
    "       Fuzzing duration in seconds.\n"
    "\n";

static OptionSet gToolOptions =
{
    HandleOption,
    gToolOptionDefs,
    "GENERAL OPTIONS",
    gToolOptionHelp
};

static HelpOptions gHelpOptions(
    TOOL_NAME,
    "Usage: " TOOL_NAME " [<options...>]\n",
    WEAVE_VERSION_STRING "\n" WEAVE_TOOL_COPYRIGHT,
    "Unit tests for Weave CASE engine.\n"
);

static OptionSet *gToolOptionSets[] =
{
    &gToolOptions,
    &gHelpOptions,
    NULL
};

int main(int argc, char *argv[])
{
    WEAVE_ERROR err;

#if WEAVE_SYSTEM_CONFIG_USE_LWIP
    tcpip_init(NULL, NULL);
#endif // WEAVE_SYSTEM_CONFIG_USE_LWIP

    err = nl::Weave::Platform::Security::InitSecureRandomDataSource(NULL, 64, NULL, 0);
    FAIL_ERROR(err, "InitSecureRandomDataSource() failed");

    if (!ParseArgs(TOOL_NAME, argc, argv, gToolOptionSets))
    {
        exit(EXIT_FAILURE);
    }

    CertProvEngineTests_GetInitialCertTests();
    CertProvEngineTests_FuzzTests();

    printf("All tests succeeded\n");

    exit(EXIT_SUCCESS);
}

static bool HandleOption(const char *progName, OptionSet *optSet, int id, const char *name, const char *arg)
{
    switch (id)
    {
    case 'f':
        if (!ParseInt(arg, gFuzzTestDurationSecs))
        {
            PrintArgError("%s: Invalid value specified for fuzz duration: %s\n", progName, arg);
            return false;
        }
        break;
    default:
        PrintArgError("%s: INTERNAL ERROR: Unhandled option: %s\n", progName, name);
        return false;
    }

    return true;
}
