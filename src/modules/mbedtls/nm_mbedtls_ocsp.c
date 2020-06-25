
#include "nm_mbedtls_ocsp.h"

#include <mbedtls/sha256.h>
#include <mbedtls/asn1.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

#include <string.h>

#define ASN1_ENUMERATED 0x0a

// oid 1.3.6.1.5.5.7.48.1.1 encoded in asn1.
const char encodedOcspBasicResponseOid[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
                                             0x01, 0x01 };

struct ocsp_response {
    enum certificate_ocsp_status certStatus;
    mbedtls_x509_time producedAt;
    mbedtls_x509_time thisUpdate;
    mbedtls_x509_time nextUpdate;
};


static int parse_ocsp_response(uint8_t* responseData, size_t responseDataSize, uint8_t* serialStart, size_t serialSize, struct ocsp_response* out)
{
    uint8_t* ptr = responseData;
    uint8_t* end = responseData + responseDataSize;
    size_t len;
    int ret;

    // responseData is a sequence
    ret = mbedtls_asn1_get_tag(&ptr, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        return ret;
    }

    // read version
    ret = mbedtls_asn1_get_tag(&ptr, end, &len, 0xA0);
    if (ret == 0) {
        // version is default 0
        return -1;
    }

    // ignore responder id which is either a name or a hash
    if (mbedtls_asn1_get_tag(&ptr, end, &len, 0xA1) == 0) {
        // responder id is a name.
        ptr += len;
    }

    if (mbedtls_asn1_get_tag(&ptr, end, &len, 0xA2) == 0) {
        // responder id is a key hash
        ptr += len;
    }

    ret = mbedtls_x509_get_time(&ptr, end, &out->producedAt);
    if (ret != 0) {
        return ret;
    }

    // parse sequence of single responses to find serial in question
    ret = mbedtls_asn1_get_tag(&ptr, end, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        return ret;
    }

    uint8_t* tmpEnd = ptr + len;

    // parse first single response
    ret = mbedtls_asn1_get_tag(&ptr, tmpEnd, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        return ret;
    }

    tmpEnd = ptr + len;

    // parse certid
    ret = mbedtls_asn1_get_tag(&ptr, tmpEnd, &len, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
    if (ret != 0) {
        return ret;
    }

    mbedtls_asn1_buf alg;
    mbedtls_asn1_buf params;
    ret = mbedtls_asn1_get_alg(&ptr, tmpEnd, &alg, &params);
    if (ret != 0) {
        return ret;
    }

    // but ignore hash alg

    // ignore name hash
    ret = mbedtls_asn1_get_tag(&ptr, tmpEnd, &len, MBEDTLS_ASN1_OCTET_STRING);
    if (ret != 0) {
        return ret;
    }
    ptr += len;

    // ignore key hash
    ret = mbedtls_asn1_get_tag(&ptr, tmpEnd, &len, MBEDTLS_ASN1_OCTET_STRING);
    if (ret != 0) {
        return ret;
    }
    ptr += len;

    ret = mbedtls_asn1_get_tag(&ptr, tmpEnd, &len, MBEDTLS_ASN1_INTEGER);
    if (ret != 0) {
        return ret;
    }

    if (len != serialSize) {
        return -1;
    }
    if (memcmp(ptr, serialStart, serialSize) != 0) {
        // the serial of the respinse does not match that of the request.
        return -1;
    }

    ptr += len;

    // read cert status
    if (mbedtls_asn1_get_tag(&ptr, tmpEnd, &len, 0x80) == 0) {
        // good
        out->certStatus = OCSP_STATUS_OK;
    } else if (mbedtls_asn1_get_tag(&ptr, tmpEnd, &len, 0x81) == 0) {
        // revoked
        out->certStatus = OCSP_STATUS_REVOKED;
    } else if (mbedtls_asn1_get_tag(&ptr, tmpEnd, &len, 0x82) == 0) {
        // unknown
        out->certStatus = OCSP_STATUS_UNKNOWN;
    } else {
        return -1;
    }
    ptr += len;

    // read this update
    ret = mbedtls_x509_get_time(&ptr, tmpEnd, &out->thisUpdate);
    if (ret != 0) {
        return ret;
    }

    // read optional next update
    // require explicit nextUpdate
    ret = mbedtls_asn1_get_tag(&ptr, tmpEnd, &len, 0xA0);
    if (ret != 0) {
        return ret;
    }

    ret = mbedtls_x509_get_time(&ptr, tmpEnd, &out->nextUpdate);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

static int validate_ocsp_response_signature(uint8_t* data, size_t dataSize, uint8_t* signature, size_t signatureSize, mbedtls_md_type_t md_alg, mbedtls_pk_type_t pk_alg, mbedtls_x509_crt* parent )
{
    if (md_alg != MBEDTLS_MD_SHA256) {
        return MBEDTLS_ERR_PK_INVALID_ALG;
    }

    uint8_t hash[32];
    mbedtls_sha256_ret(data, dataSize, hash, 0);

    int status = mbedtls_pk_verify(&parent->pk, MBEDTLS_MD_NONE, hash, 32, signature, signatureSize);
    return status;
}

int validate_ocsp_response(uint8_t* response, size_t responseSize, mbedtls_x509_crt* child, mbedtls_x509_crt* parent, enum certificate_ocsp_status* status)
{
    uint8_t* ptr = response;
    uint8_t* end = response + responseSize;
    size_t len;
    mbedtls_x509_crt* signingCertificate = parent;

    int ret;
    ret = mbedtls_asn1_get_tag(&ptr, end, &len, MBEDTLS_ASN1_CONSTRUCTED |  MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return ret;
    }

    ret = mbedtls_asn1_get_tag(&ptr, end, &len, ASN1_ENUMERATED);
    if (ret != 0) {
        return ret;
    }

    if (len != 1) {
        return -1;
    }

    int responseStatus = *ptr;
    ptr++;

    if (responseStatus != 0) {
        return -1;
    }

    // read explicit tagged response bytes [0]
    ret = mbedtls_asn1_get_tag(&ptr, end, &len, 0xA0);
    if (ret != 0) {
        return ret;
    }

    // find a basic ocsp response and the corresponding bytes for it.
    mbedtls_asn1_buf alg;
    mbedtls_asn1_buf params;
    ret = mbedtls_asn1_get_alg(&ptr, end, &alg, &params);
    if (ret != 0) {
        return ret;
    }

    if (alg.len != sizeof(encodedOcspBasicResponseOid)) {
        return -1;
    }

    if (memcmp(alg.p, encodedOcspBasicResponseOid, sizeof(encodedOcspBasicResponseOid)) != 0) {
        return -1;
    }

    // The octet string is inside the params.
    ptr = params.p;

    // the rest of the buffer is a basic ocsp response

    // sequence of tbsresponsedata, signing algorithm and signature.

    ret = mbedtls_asn1_get_tag(&ptr, end, &len, MBEDTLS_ASN1_CONSTRUCTED |  MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return ret;
    }

    uint8_t* tbsDataStart;
    size_t tbsDataSize;
    mbedtls_md_type_t md_alg;
    mbedtls_pk_type_t pk_alg;

    tbsDataStart = ptr;

    ret = mbedtls_asn1_get_tag(&ptr, end, &len, MBEDTLS_ASN1_CONSTRUCTED |  MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return ret;
    }


    ptr = ptr + len;
    tbsDataSize = ptr - tbsDataStart;

    ret = mbedtls_asn1_get_alg(&ptr,end, &alg, &params);
    if (ret != 0) {
        return ret;
    }

    ret = mbedtls_oid_get_sig_alg(&alg, &md_alg, &pk_alg);
    if (ret != 0) {
        return ret;
    }
    mbedtls_asn1_bitstring bitstring;
    ret = mbedtls_asn1_get_bitstring(&ptr, end, &bitstring);
    if (ret != 0) {
        return ret;
    }

    // get sequence of certificates
    mbedtls_x509_crt extraCert;
    if (mbedtls_asn1_get_tag(&ptr, end, &len, 0xA0) == 0) {
        // get first certuificate of the sequence
        ret = mbedtls_asn1_get_tag(&ptr, end, &len, MBEDTLS_ASN1_CONSTRUCTED |  MBEDTLS_ASN1_SEQUENCE);
        if (ret != 0) {
            return ret;
        }


        mbedtls_x509_crt_init(&extraCert);
        ret = mbedtls_x509_crt_parse_der(&extraCert, ptr, len);
        if (ret != 0) {
            return ret;
        }

        uint32_t flags = 0;
        ret = mbedtls_x509_crt_verify(&extraCert, parent, NULL, NULL, &flags, NULL, NULL );
        if (ret != 0) {
            return ret;
        }

        // verify that the key usage is ocsp signing
        ret = mbedtls_x509_crt_check_extended_key_usage(&extraCert, MBEDTLS_OID_OCSP_SIGNING,  MBEDTLS_OID_SIZE(MBEDTLS_OID_OCSP_SIGNING));
        if (ret != 0) {
            return ret;
        }

        signingCertificate = &extraCert;
    }

    struct ocsp_response parsed;
    ret = parse_ocsp_response(tbsDataStart, tbsDataSize, child->serial.p, child->serial.len, &parsed);
    if (ret != 0) {
        return ret;
    }

    ret = validate_ocsp_response_signature(tbsDataStart, tbsDataSize, bitstring.p, bitstring.len, md_alg, pk_alg, signingCertificate);
    if (ret != 0) {
        return ret;
    }

    // 1. The certificate identified in a received response corresponds to
    // the certificate that was identified in the corresponding request;

    // we check that the serial number matches.

    // 3. The identity of the signer matches the intended recipient of the
    // request;
    // we check that the parent has signed the ocsp response

    // 4. The signer is currently authorized to provide a response for the
    // certificate in question;
    // the parent is by definition authorized

    // 5. The time at which the status being indicated is known to be
    // correct (thisUpdate) is sufficiently recent;

    // 6. When available, the time at or before which newer information will
    //  be available about the status of the certificate (nextUpdate) is
    //  greater than the current time.


    // next update should be in the future

    if (mbedtls_x509_time_is_past(&parsed.nextUpdate) != 0) {
        return -1;
    }
    if (mbedtls_x509_time_is_future(&parsed.thisUpdate) != 0) {
        return -1;
    }

    *status = parsed.certStatus;
    return 0;
}
