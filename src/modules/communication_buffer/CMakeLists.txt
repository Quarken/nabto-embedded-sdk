set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(unix_src
  ${src_dir}/nm_communication_buffer.c
  )

add_library( nm_communication_buffer STATIC ${unix_src})

target_link_libraries(nm_communication_buffer np_platform)
