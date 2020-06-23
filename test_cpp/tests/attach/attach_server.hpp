#pragma once

#include <fixtures/dtls_server/dtls_server.hpp>
#include <boost/asio/io_service.hpp>
//#include <util/test_future.hpp>
#include <fixtures/dtls_server/mbedtls_util.hpp>

#include <nlohmann/json.hpp>

#include <cbor.h>

namespace nabto {
namespace test {

std::string certChain = R"(
-----BEGIN CERTIFICATE-----
MIICMzCCAdqgAwIBAgIURu94ep36BTXqJOcOq6L142ReZtEwCgYIKoZIzj0EAwIw
PjELMAkGA1UEBhMCREsxDjAMBgNVBAoMBU5hYnRvMR8wHQYDVQQDDBZOYWJ0byBU
ZXN0IFNlcnZlciBDQSAxMB4XDTIwMDYyMzEyMDQ0MFoXDTIxMDcwMzEyMDQ0MFow
OzELMAkGA1UEBhMCREsxDjAMBgNVBAoMBU5hYnRvMRwwGgYDVQQDDBNsb2NhbGhv
c3QubmFidG8ubmV0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhIa2qC2rPyvh
NhPKKi+E6ygXF9OB80Vdcl6uRoRZnTAxaZaPs/cEkNwOg7Rh6AbztudvwepnTNm5
UdYfDMquUKOBuDCBtTAJBgNVHRMEAjAAMB0GA1UdDgQWBBTJfqidoIXeMhLJKQRs
gCKqwDUtPDAfBgNVHSMEGDAWgBRvrsA1Am7NlGBuynzd4DICRsbTCDAOBgNVHQ8B
Af8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwQwYIKwYBBQUHAQEENzA1MDMG
CCsGAQUFBzABhidodHRwOi8vb2NzcC5zZXJ2ZXJjYTEucGtpLmRldi5uYWJ0by5j
b20wCgYIKoZIzj0EAwIDRwAwRAIgciIubkkxWCL7PkCWRep98lowxqKzB/4LoJ4Z
LYg9coUCIBJPNm8JqXoGPXVgfz5/0ysq2M6gesSUyYM5M8xzilsD
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICKDCCAc2gAwIBAgIUGG+y7EGtGfMSDKi2ZVpsZeAfFWAwCgYIKoZIzj0EAwIw
PDELMAkGA1UEBhMCREsxDjAMBgNVBAoMBU5hYnRvMR0wGwYDVQQDDBROYWJ0byBU
ZXN0IFJvb3QgQ0EgMTAeFw0yMDA2MjIxMTMxMDVaFw0zMDA2MjAxMTMxMDVaMD4x
CzAJBgNVBAYTAkRLMQ4wDAYDVQQKDAVOYWJ0bzEfMB0GA1UEAwwWTmFidG8gVGVz
dCBTZXJ2ZXIgQ0EgMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDfMT+dnMwrs
z44+yczSzgMeUQqzSj6msA0AosN3DZP4U6BEUJOk2ZSqF9FXrhx+9eHRNfGLcEpp
/eNW7eOmfwKjgaowgacwHQYDVR0OBBYEFG+uwDUCbs2UYG7KfN3gMgJGxtMIMB8G
A1UdIwQYMBaAFG/mZCUc2tUvj6DZOwuxkqDNcwqJMBIGA1UdEwEB/wQIMAYBAf8C
AQAwDgYDVR0PAQH/BAQDAgGGMEEGCCsGAQUFBwEBBDUwMzAxBggrBgEFBQcwAYYl
aHR0cDovL29jc3Aucm9vdGNhMS5wa2kuZGV2Lm5hYnRvLmNvbTAKBggqhkjOPQQD
AgNJADBGAiEA+J+HaYOSdhWZ5MLoHtybZkAswr6QzDmc7U5VFY50g5sCIQCSp3vd
8GeuhkjSERuP3hU7nUkmb3nJ8Gxa+XmkPmRpkw==
-----END CERTIFICATE-----
)";

std::string rootCert = R"(-----BEGIN CERTIFICATE-----
MIIBvDCCAWKgAwIBAgIUG+Bt71g3QqS36/jNxVcmQLzoZkwwCgYIKoZIzj0EAwIw
PDELMAkGA1UEBhMCREsxDjAMBgNVBAoMBU5hYnRvMR0wGwYDVQQDDBROYWJ0byBU
ZXN0IFJvb3QgQ0EgMTAeFw0yMDA2MjIwOTA4MzhaFw00OTEyMzEyMzU5NTlaMDwx
CzAJBgNVBAYTAkRLMQ4wDAYDVQQKDAVOYWJ0bzEdMBsGA1UEAwwUTmFidG8gVGVz
dCBSb290IENBIDEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASxCXWqC54B+HCe
FkdxlfHhtqXpvc6P0A8km3ii1savQJmrbdgnu263AQxuf9rSvC3pO6UC81zNIFli
cdkErvnpo0IwQDAdBgNVHQ4EFgQUb+ZkJRza1S+PoNk7C7GSoM1zCokwDwYDVR0T
AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwIDSAAwRQIgG2tw
se2/BxmDOs20B120QoGerlYgmfQlGnQtEdeyPsACIQC19A9QR/l/pO9ftOYWrrHL
mdCg5Sam+dxRWc3+vGMCSA==
-----END CERTIFICATE-----
)";

std::string privateKey = R"(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9b2pAZawStfrB+77
HAGga0ktbJ6kqjN5ISiF4Rjh0fChRANCAASEhraoLas/K+E2E8oqL4TrKBcX04Hz
RV1yXq5GhFmdMDFplo+z9wSQ3A6DtGHoBvO252/B6mdM2blR1h8Myq5Q
-----END PRIVATE KEY-----
)";

class AttachCoapServer {
 public:
    AttachCoapServer(boost::asio::io_context& io)
        : io_(io), dtlsServer_(io)
    {
    }
    virtual ~AttachCoapServer() {}

    bool init() {
        lib::error_code ec;
        dtlsServer_.setPort(0);
        dtlsServer_.setAlpnProtocols({"n5"});
        if (!dtlsServer_.setRootCert(rootCert)) {
            return false;
        }
        if (!dtlsServer_.setCertChain(certChain)) {
            return false;
        }
        if (!dtlsServer_.setPrivateKey(privateKey)) {
            return false;
        }

        ec = dtlsServer_.init();
        initCoapHandlers();
        return true;
    }

    void stop() {
        // TODO: Was this defferrence only needed in BS ?
        //nabto::TestFuture tf;
        io_.post([this](){
            dtlsServer_.stop();
        });
        //dtlsServer_.stop();
    }

    virtual void initCoapHandlers() = 0;

    uint16_t getPort()
    {
        return dtlsServer_.getPort();
    }

    std::array<uint8_t, 16> getFingerprint()
    {
        auto fp = getFingerprintFromPem(test::serverPublicKey);
        std::array<uint8_t, 16> ret;
        memcpy(ret.data(), fp->data(), 16);
        return ret;
    }
 protected:
    boost::asio::io_context& io_;
    DtlsServer dtlsServer_;

};

class AttachServer : public AttachCoapServer, public std::enable_shared_from_this<AttachServer>
{
 public:

    AttachServer(boost::asio::io_context& io)
        : AttachCoapServer(io)
    {
    }

    static std::shared_ptr<AttachServer> create(boost::asio::io_context& io)
    {
        auto ptr = std::make_shared<AttachServer>(io);
        if (!ptr->init()) {
            return nullptr;
        }
        return ptr;
    }

    void initCoapHandlers() {
        auto self = shared_from_this();
        dtlsServer_.addResourceHandler(NABTO_COAP_CODE_POST, "/device/attach-start", [self](DtlsConnectionPtr connection, std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response) {
                if (self->attachCount_ == self->invalidAttach_) {
                    self->handleDeviceAttachWrongResponse(connection, request, response);
                } else {
                    self->handleDeviceAttach(connection, request, response);
                }
                self->attachCount_ += 1;
            });
        dtlsServer_.addResourceHandler(NABTO_COAP_CODE_POST, "/device/attach-end", [self](DtlsConnectionPtr connection, std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response) {
                response->setCode(201);
                //self->attachCount_ += 1;
                return;
            });
    }

    void handleDeviceAttach(DtlsConnectionPtr connection,  std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response)
    {
        nlohmann::json root;
        root["Status"] = 0;
        nlohmann::json ka;
        ka["Interval"] = keepAliveInterval_;
        ka["RetryInterval"] = keepAliveRetryInterval_;
        ka["MaxRetries"] = keepAliveMaxRetries_;
        root["KeepAlive"] = ka;
        nlohmann::json stun;
        stun["Host"] = "stun.nabto.net";
        stun["Port"] = 3478;
        root["Stun"] = stun;

        std::vector<uint8_t> cbor = nlohmann::json::to_cbor(root);

        response->setContentFormat(NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        response->setPayload(cbor);
        response->setCode(201);
    }

    void handleDeviceAttachWrongResponse(DtlsConnectionPtr connection,  std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response)
    {
        nlohmann::json root;
        root["FOOBAR"] = "BAZ";

        std::vector<uint8_t> cbor = nlohmann::json::to_cbor(root);

        response->setContentFormat(NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        response->setPayload(cbor);
        response->setCode(201);
    }

    void setKeepAliveSettings(uint64_t interval, uint64_t retryInterval, uint64_t maxRetries)
    {
        keepAliveInterval_ = interval;
        keepAliveRetryInterval_ = retryInterval;
        keepAliveMaxRetries_ = maxRetries;
    }

    void niceClose() {
        dtlsServer_.asyncNiceClose([](const lib::error_code& ec){
                // all current connections is closed nicely.
            });
    }

    uint64_t keepAliveInterval_ = 30000;
    uint64_t keepAliveRetryInterval_ = 2000;
    uint64_t keepAliveMaxRetries_ = 15;

    std::atomic<uint64_t> attachCount_ = { 0 };
    uint64_t invalidAttach_ = 42;
};


class RedirectServer : public AttachCoapServer, public std::enable_shared_from_this<RedirectServer>
{
 public:

    RedirectServer(boost::asio::io_context& io)
        : AttachCoapServer(io)
    {
    }

    static std::shared_ptr<RedirectServer> create(boost::asio::io_context& io)
    {
        auto ptr = std::make_shared<RedirectServer>(io);
        ptr->init();
        return ptr;
    }

    void initCoapHandlers() {
        auto self = shared_from_this();
        dtlsServer_.addResourceHandler(NABTO_COAP_CODE_POST, "/device/attach-start", [self](DtlsConnectionPtr connection, std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response) {
                if (self->invalidRedirect_ == self->redirectCount_) {
                    self->handleDeviceRedirectInvalidResponse(connection, response);
                } else {
                    self->handleDeviceRedirect(connection, response);
                }
                self->redirectCount_++;
            });
    }

    void handleDeviceRedirectInvalidResponse(DtlsConnectionPtr connection, std::shared_ptr<CoapServerResponse> response)
    {
        response->setContentFormat(NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        response->setCode(201);
    }

    void handleDeviceRedirect(DtlsConnectionPtr connection, std::shared_ptr<CoapServerResponse> response)
    {
        uint8_t buffer[128];

        CborEncoder encoder;
        CborEncoder map;
        cbor_encoder_init(&encoder, buffer, 128, 0);
        cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

        cbor_encode_text_stringz(&map, "Status");
        uint8_t redirect = 1;
        cbor_encode_uint(&map, redirect);

        cbor_encode_text_stringz(&map, "Host");
        cbor_encode_text_stringz(&map, host_.c_str());

        cbor_encode_text_stringz(&map, "Port");
        cbor_encode_uint(&map, port_);

        cbor_encode_text_stringz(&map, "Fingerprint");
        cbor_encode_byte_string(&map, fingerprint_.data(), fingerprint_.size());

        cbor_encoder_close_container(&encoder, &map);

        BOOST_TEST(cbor_encoder_get_extra_bytes_needed(&encoder) == (size_t)0);

        size_t length = cbor_encoder_get_buffer_size(&encoder, buffer);

        response->setContentFormat(NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        response->setPayload(lib::span<const uint8_t>(buffer, length));
        response->setCode(201);
    }

    void setRedirect(const std::string& host, uint16_t port, std::array<uint8_t, 16> fingerprint)
    {
        host_ = host;
        port_ = port;
        fingerprint_ = fingerprint;
    }

    std::atomic<uint64_t> redirectCount_ = { 0 };

    // if the count matches this number send an invalid redirect
    uint64_t invalidRedirect_ = 42;
 private:
    std::string host_;
    uint16_t port_;
    std::array<uint8_t, 16> fingerprint_;


};

class AccessDeniedServer : public AttachCoapServer, public std::enable_shared_from_this<AccessDeniedServer>
{
 public:

    AccessDeniedServer(boost::asio::io_context& io)
        : AttachCoapServer(io)
    {
    }

    static std::shared_ptr<AccessDeniedServer> create(boost::asio::io_context& io)
    {
        auto ptr = std::make_shared<AccessDeniedServer>(io);
        ptr->init();
        return ptr;
    }

    void initCoapHandlers() {
        auto self = shared_from_this();
        dtlsServer_.addResourceHandler(NABTO_COAP_CODE_POST, "/device/attach-start", [self](DtlsConnectionPtr connection,  std::shared_ptr<CoapServerRequest> request, std::shared_ptr<CoapServerResponse> response) {
                connection->accessDenied();
                self->coapRequestCount_++;
            });
    }

    std::atomic<uint64_t> coapRequestCount_ = { 0 };
};

} }
