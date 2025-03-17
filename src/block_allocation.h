#pragma once

#include <stdio.h>
#include <stdlib.h>
#include "block_meta.h"
#include "utils.h"

void fill_block_meta(void *block, size_t size, int status);
void attach_block(void *block);
void insert_block(block_meta *b_meta, size_t position);
size_t get_heap_alloc();
void heap_prealloc(void *block);
void *extract_payload(void *block);
void deattach_block(void *block);
block_meta *split_block(block_meta *b_meta, size_t size);
void *find_block(size_t threshold);
void *search_in_memory(size_t size);
void coalesce(void);
int is_block_tail(void *block);
int coalesce_right(block_meta *b_meta);
void *extend_last_block(size_t size);
