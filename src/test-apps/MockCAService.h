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
 *      This file defines a derived unsolicited responder
 *      (i.e., server) for the Certificate Provisioned protocol of the
 *      Weave Security profile used for the Weave mock
 *      device command line functional testing tool.
 *
 */

#ifndef MOCKCASERVICE_H_
#define MOCKCASERVICE_H_

#include <Weave/Core/WeaveCore.h>
#include <Weave/Profiles/security/WeaveCertProvisioning.h>

using ::nl::Weave::System::PacketBuffer;

extern WEAVE_ERROR ValidateWeaveDeviceCert(WeaveCertificateSet & certSet);

class GetCertificateRequestMessage
{
public:
    enum { kMaxCerts = 4 };

    GetCertificateRequestMessage();

    WeaveCertificateSet mOperationalCertSet;
    WeaveCertificateSet mManufAttestCertSet;

    OID OperationalSigAlgo;
    EncodedECDSASignature OperationalSig;
    OID ManufAttestSigAlgo;
    EncodedECDSASignature ManufAttestSig;

    bool IsInitialReq() const { return (ReqType == nl::Weave::Profiles::Security::CertProvisioning::WeaveCertProvEngine::kReqType_GetInitialOpDeviceCert); }
    bool ManufAttestRequired() const { return (ReqType == nl::Weave::Profiles::Security::CertProvisioning::WeaveCertProvEngine::kReqType_GetInitialOpDeviceCert); }
    bool ManufAttestInfoPresent() const { return mManufAttestCertSetInitialized; }

    WEAVE_ERROR Decode(PacketBuffer *msgBuf);
    WEAVE_ERROR GenerateTBSHash(uint8_t *tbsHash);

private:
    uint8_t ReqType;

    bool mOperationalCertSetInitialized;
    bool mManufAttestCertSetInitialized;

    const uint8_t *mTBSDataStart;
    uint16_t mTBSDataLen;
};

class MockCAService
{
public:
    MockCAService();

    WEAVE_ERROR Init(nl::Weave::WeaveExchangeManager *exchangeMgr);
    WEAVE_ERROR Shutdown();

    WEAVE_ERROR ProcessGetCertificateRequest(PacketBuffer *msgBuf, GetCertificateRequestMessage & msg);
    WEAVE_ERROR GenerateGetCertificateResponse(PacketBuffer *msgBuf, WeaveCertificateData& currentOpDeviceCert);

    bool LogMessageData() const { return mLogMessageData; }
    MockCAService& LogMessageData(bool val) { mLogMessageData = val; return *this; }

    bool IncludeRelatedCerts() const { return mIncludeRelatedCerts; }
    MockCAService& IncludeRelatedCerts(bool val) { mIncludeRelatedCerts = val; return *this; }

private:
    nl::Weave::WeaveExchangeManager *mExchangeMgr;
    bool mLogMessageData;
    bool mIncludeRelatedCerts;

    WEAVE_ERROR SendStatusReport(nl::Weave::ExchangeContext *ec);

    static void HandleClientRequest(nl::Weave::ExchangeContext *ec, const nl::Inet::IPPacketInfo *addrInfo,
                                    const nl::Weave::WeaveMessageInfo *msgInfo, uint32_t profileId,
                                    uint8_t msgType, PacketBuffer *payload);

    WEAVE_ERROR GenerateServiceAssignedDeviceCert(WeaveCertificateData& certData, uint8_t *cert, uint16_t certBufSize, uint16_t& certLen);
};

#endif /* MOCKCASERVICE_H_ */
