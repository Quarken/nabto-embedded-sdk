#pragma once

#include <dtls/dtls_server.hpp>
#include <boost/asio/io_service.hpp>
#include <util/logger.hpp>
#include <dtls/mbedtls_util.hpp>

#include <nlohmann/json.hpp>

#include <cbor.h>

namespace nabto {
namespace test {

class AttachCoapServer {
 public:
    AttachCoapServer(boost::asio::io_context& io, log::LoggerPtr logger)
        : io_(io), logger_(logger), dtlsServer_(io, logger)
    {
    }

    void init() {
        lib::error_code ec;
        dtlsServer_.setPort(0);
        dtlsServer_.setAlpnProtocols({"n5"});
        dtlsServer_.setSniCallback([](const std::string& sni){
                return DtlsServer::createCertificateContext(test::serverPrivateKey, test::serverPublicKey);
            });

        ec = dtlsServer_.init();
        initCoapHandlers();
    }

    void stop() {
        dtlsServer_.stop();
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
        memcpy(ret.data(), fp.data(), 16);
        return ret;
    }
 protected:
    boost::asio::io_context& io_;
    log::LoggerPtr logger_;
    DtlsServer dtlsServer_;

};

class AttachServer : public AttachCoapServer, public std::enable_shared_from_this<AttachServer>
{
 public:

    AttachServer(boost::asio::io_context& io, log::LoggerPtr logger)
        : AttachCoapServer(io, logger)
    {
    }

    static std::shared_ptr<AttachServer> create(boost::asio::io_context& io, log::LoggerPtr logger)
    {
        auto ptr = std::make_shared<AttachServer>(io, logger);
        ptr->init();
        return ptr;
    }

    void initCoapHandlers() {
        auto self = shared_from_this();
        dtlsServer_.addResourceHandler(NABTO_COAP_CODE_POST, "/device/attach", [self](DtlsConnectionPtr connection, struct nabto_coap_server_request* request) {
                self->handleDeviceAttach(connection, request);
            });
    }

    void handleDeviceAttach(DtlsConnectionPtr connection, struct nabto_coap_server_request* request)
    {
        nlohmann::json root;
        root["Status"] = 0;
        auto ka = root["KeepAlive"];
        ka["Interval"] = 30000;
        ka["RetryInterval"] = 2000;
        ka["MaxRetries"] = 15;

        std::vector<uint8_t> cbor = nlohmann::json::to_cbor(root);

        nabto_coap_server_response_set_content_format(request, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        nabto_coap_server_response_set_payload(request, cbor.data(), cbor.size());
        nabto_coap_server_response_set_code(request, NABTO_COAP_CODE_CREATED);
        nabto_coap_server_response_ready(request);
        nabto_coap_server_request_free(request);

        attachCount_ += 1;
    }

    std::atomic<uint64_t> attachCount_ = { 0 };
};


class RedirectServer : public AttachCoapServer, public std::enable_shared_from_this<RedirectServer>
{
 public:

    RedirectServer(boost::asio::io_context& io, log::LoggerPtr logger)
        : AttachCoapServer(io, logger)
    {
    }

    static std::shared_ptr<RedirectServer> create(boost::asio::io_context& io, log::LoggerPtr logger)
    {
        auto ptr = std::make_shared<RedirectServer>(io, logger);
        ptr->init();
        return ptr;
    }

    void initCoapHandlers() {
        auto self = shared_from_this();
        dtlsServer_.addResourceHandler(NABTO_COAP_CODE_POST, "/device/attach", [self](DtlsConnectionPtr connection, struct nabto_coap_server_request* request) {
                self->handleDeviceRedirect(connection, request);
            });
    }

    void handleDeviceRedirect(DtlsConnectionPtr connection, struct nabto_coap_server_request* request)
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

        nabto_coap_server_response_set_content_format(request, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);
        nabto_coap_server_response_set_payload(request, buffer, length);
        nabto_coap_server_response_set_code(request, NABTO_COAP_CODE_CREATED);
        nabto_coap_server_response_ready(request);
        nabto_coap_server_request_free(request);

        redirectCount_ += 1;
    }

    void setRedirect(const std::string& host, uint16_t port, std::array<uint8_t, 16> fingerprint)
    {
        host_ = host;
        port_ = port;
        fingerprint_ = fingerprint;
    }

    std::atomic<uint64_t> redirectCount_ = { 0 };

 private:
    std::string host_;
    uint16_t port_;
    std::array<uint8_t, 16> fingerprint_;

};
} }
