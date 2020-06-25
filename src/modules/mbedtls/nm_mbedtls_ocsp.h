#ifndef _NM_MBEDTLS_OCSP_H_
#define _NM_MBEDTLS_OCSP_H_

#include <stdint.h>
#include <mbedtls/x509_crt.h>

int validate_ocsp_response(uint8_t* response, size_t responseSize, mbedtls_x509_crt* child, mbedtls_x509_crt* parent);

#endif
