set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(dtls_common_src
  nm_mbedtls_timer.c
  nm_mbedtls_util.c
  )

set(dtls_cli_src
  ${dtls_common_src}
  nm_mbedtls_cli.c
  )

set(dtls_srv_src
  ${dtls_common_src}
  nm_mbedtls_srv.c
  )

set(mbedtls_random_src
  nm_mbedtls_random.c
  )


add_library( nm_mbedtls_cli STATIC ${dtls_cli_src})
add_library( nm_mbedtls_srv STATIC ${dtls_srv_src})
add_library( nm_mbedtls_random STATIC ${mbedtls_random_src})


target_link_libraries(nm_mbedtls_cli 3rdparty_mbedtls nn np_platform)
target_link_libraries(nm_mbedtls_srv 3rdparty_mbedtls np_platform)
target_link_libraries(nm_mbedtls_random 3rdparty_mbedtls np_platform)
