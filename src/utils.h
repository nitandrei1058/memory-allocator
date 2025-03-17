#pragma once

#include <block_meta.h>

typedef struct block_meta block_meta;
#define PAD(size) ((size + 7) & ~7) // Urmatorul multiplu de 8
#define META_BLOCK_PADDED PAD(sizeof(struct block_meta))
#define MMAP_THRESHOLD 128 * 1024
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#define MAP_ANON MAP_ANONYMOUS
#endif
