#ifndef _NM_MBEDTLS_OCSP_H_
#define _NM_MBEDTLS_OCSP_H_

#include <stdint.h>
#include <mbedtls/x509_crt.h>

enum certificate_ocsp_status {
    OCSP_STATUS_OK = 0,
    OCSP_STATUS_REVOKED = 1,
    OCSP_STATUS_UNKNOWN = 2
};

int validate_ocsp_response(uint8_t* response, size_t responseSize, mbedtls_x509_crt* child, mbedtls_x509_crt* parent, enum certificate_ocsp_status* status);

#endif
