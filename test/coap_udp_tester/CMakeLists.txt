cmake_minimum_required(VERSION 3.0)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(coap_udp_server_tester_src
  ${src_dir}/main.c
  )

set(coap_udp_client_tester_src
  ${src_dir}/client_main.c
  )

add_executable(coap_udp_server_tester "${coap_udp_server_tester_src}")
add_executable(coap_udp_client_tester "${coap_udp_client_tester_src}")

target_link_libraries(coap_udp_server_tester
  test_platform
  np_platform
  nm_logging_unix
  nm_communication_buffer
  nm_timestamp
  )

target_link_libraries(coap_udp_client_tester
  test_platform
  np_platform
  nm_logging_unix
  nm_communication_buffer
  nm_timestamp
  )
