#include "nc_iam_util.h"
#include <string.h>
#include <stdlib.h>

// LISTS
void nc_iam_list_init(struct nc_iam_list* list) {
    list->sentinel.next = &list->sentinel;
    list->sentinel.prev = &list->sentinel;
    list->sentinel.item = NULL;
}

void nc_iam_list_clear(struct nc_iam_list* list)
{
    struct nc_iam_list_entry* iterator = list->sentinel.next;
    while (iterator != &list->sentinel) {
        struct nc_iam_list_entry* entry = iterator;
        iterator = iterator->next;
        nc_iam_list_entry_free(entry);
    }

    list->sentinel.next = &list->sentinel;
    list->sentinel.prev = &list->sentinel;
}

void nc_iam_list_clear_and_free_items(struct nc_iam_list* list)
{
    struct nc_iam_list_entry* iterator = list->sentinel.next;
    while (iterator != &list->sentinel) {
        struct nc_iam_list_entry* entry = iterator;
        iterator = iterator->next;
        free(entry->item);
        nc_iam_list_entry_free(entry);
    }

    list->sentinel.next = &list->sentinel;
    list->sentinel.prev = &list->sentinel;
}

void nc_iam_list_insert(struct nc_iam_list* list, void* item)
{
    struct nc_iam_list_entry* entry = nc_iam_list_entry_new();
    entry->item = item;
    struct nc_iam_list_entry* before = list->sentinel.prev;
    struct nc_iam_list_entry* after = &list->sentinel;

    before->next = entry;
    entry->next = after;
    after->prev = entry;
    entry->prev = before;
}

void nc_iam_list_remove(struct nc_iam_list_entry* entry)
{
    struct nc_iam_list_entry* before = entry->prev;
    struct nc_iam_list_entry* after = entry->next;

    before->next = after;
    after->prev = before;

    nc_iam_list_entry_free(entry);
}

void nc_iam_list_remove_item(struct nc_iam_list* list, void* item)
{
    struct nc_iam_list_entry* iterator = list->sentinel.next;
    while(iterator != &list->sentinel) {
        if (iterator->item == item) {
            nc_iam_list_remove(iterator);
            return;
        }
        iterator = iterator->next;
    }
}

struct nc_iam_list_entry* nc_iam_list_entry_new()
{
    return calloc(1, sizeof(struct nc_iam_list_entry));
}

void nc_iam_list_entry_free(struct nc_iam_list_entry* entry)
{
    free(entry);
}

bool nc_iam_hex_to_data(const char* hex, uint8_t* data, size_t dataLength)
{
    size_t hexLength = strlen(hex);
    if (strlen(hex) != dataLength * 2) {
        return false;
    }
    memset(data, 0, dataLength);

    size_t index = 0;
    while (index < hexLength) {
        char c = hex[index];
        int value = 0;
        if(c >= '0' && c <= '9')
          value = (c - '0');
        else if (c >= 'A' && c <= 'F')
          value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
          value = (10 + (c - 'a'));
        else {
            return false;
        }

        // shift each even hex byte 4 up
        data[(index/2)] += value << (((index + 1) % 2) * 4);

        index++;
    }

    return true;
}