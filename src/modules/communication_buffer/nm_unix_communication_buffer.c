#include "nm_unix_communication_buffer.h"
#include <stdlib.h>


struct np_communication_buffer {
    uint8_t* buf;
    uint16_t size;
};


void nm_unix_comm_buf_init(struct np_platform* pl)
{
    pl->buf.allocate = &nm_unix_comm_buf_allocate;
    pl->buf.free     = &nm_unix_comm_buf_free;
    pl->buf.start    = &nm_unix_comm_buf_start;
    pl->buf.size     = &nm_unix_comm_buf_size;
}

np_communication_buffer* nm_unix_comm_buf_allocate()
{
    np_communication_buffer* buf = (np_communication_buffer*)malloc(sizeof(np_communication_buffer));
    buf->buf = (uint8_t*)malloc(NABTO_COMMUNICATION_BUFFER_LENGTH);
    buf->size = NABTO_COMMUNICATION_BUFFER_LENGTH;
    return buf;
}

void nm_unix_comm_buf_free(np_communication_buffer* buf)
{
    free(buf->buf);
    free(buf);
}

uint8_t* nm_unix_comm_buf_start(np_communication_buffer* buf)
{
    return buf->buf;
}

uint16_t nm_unix_comm_buf_size(np_communication_buffer* buf)
{
    return buf->size;
}