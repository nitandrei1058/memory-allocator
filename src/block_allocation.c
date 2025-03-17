// SPDX-License-Identifier: BSD-3-Clause

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include "block_allocation.h"
#include "block_meta.h"
#include "utils.h"

typedef struct blocks_list_t {
	block_meta *head;
	block_meta *tail;
	size_t size;
	int has_heap_alloc;
} blocks_list_t;

blocks_list_t blocks_list;

void fill_block_meta(void *block, size_t size, int status)
{
	block_meta *meta = (block_meta *)block;

	meta->size = size;
	meta->status = status;
	meta->prev = NULL;
	meta->next = NULL;
}

void insert_block(block_meta *b_meta, size_t position)
{
	if (blocks_list.size == 0) {
		blocks_list.head = b_meta;
		blocks_list.tail = b_meta;
		blocks_list.size++;
		return;
	}
	if (position == 0) {
		b_meta->next = blocks_list.head;
		blocks_list.head->prev = b_meta;
		blocks_list.head = b_meta;
		blocks_list.size++;
		return;
	}
	if (blocks_list.size <= position) {
		b_meta->prev = blocks_list.tail;
		blocks_list.tail->next = b_meta;
		blocks_list.tail = b_meta;
		blocks_list.size++;
		return;
	}
	// 0 < position < blocks_list.size
	block_meta *current = blocks_list.head;

	for (size_t i = 0; i < position - 1; i++)
		current = current->next;
	b_meta->next = current->next;
	b_meta->prev = current;
	current->next->prev = b_meta;
	current->next = b_meta;
	blocks_list.size++;
}

void attach_block(void *block)
{
	block_meta *b_meta = (block_meta *)block;

	if (blocks_list.size == 0) {
		blocks_list.head = b_meta;
		blocks_list.tail = b_meta;
		blocks_list.size++;
		return;
	}

	insert_block(block, blocks_list.size);
}

void *extract_payload(void *block) { return block + META_BLOCK_PADDED; }

size_t get_heap_alloc(void) { return blocks_list.has_heap_alloc; }

void heap_prealloc(void *block)
{
	blocks_list.has_heap_alloc = 1;
	attach_block(block);
}

void remove_block(block_meta *b_meta)
{
	if (b_meta == blocks_list.head) {
		blocks_list.head = b_meta->next;
		blocks_list.head->prev = NULL;
		blocks_list.size--;
		return;
	}
	if (b_meta == blocks_list.tail) {
		blocks_list.tail = b_meta->prev;
		blocks_list.tail->next = NULL;
		blocks_list.size--;
		return;
	}
	// e in interior
	b_meta->prev->next = b_meta->next;
	b_meta->next->prev = b_meta->prev;
	blocks_list.size--;
}

void deattach_block(void *block)
{
	block_meta *b_meta = (block_meta *)block;

	if (blocks_list.size == 1) {
		blocks_list.head = NULL;
		blocks_list.tail = NULL;
		blocks_list.size = 0;
		return;
	}
	remove_block(b_meta);
}

void add_after(block_meta *b_meta, block_meta *new_block)
{
	if (is_block_tail(b_meta))
		blocks_list.tail = new_block;
	else
		b_meta->next->prev = new_block;
	new_block->next = b_meta->next;
	new_block->prev = b_meta;
	b_meta->next = new_block;
	blocks_list.size++;
}

block_meta *split_block(block_meta *b_meta, size_t size)
{
	if (b_meta->size + META_BLOCK_PADDED <
		META_BLOCK_PADDED + 8 + META_BLOCK_PADDED + size)
		return NULL;

	void *new_addr = (void *)b_meta + META_BLOCK_PADDED + size;
	size_t new_size = b_meta->size - size - META_BLOCK_PADDED;

	fill_block_meta(new_addr, new_size, STATUS_FREE);
	b_meta->status = STATUS_ALLOC;
	b_meta->size = size;
	add_after(b_meta, new_addr);

	return new_addr;
}

void *find_block(size_t size)
{
	block_meta *current = blocks_list.head;
	block_meta *min_block = NULL;
	size_t min = __SIZE_MAX__;

	while (current != NULL) {
		if (current->status == STATUS_FREE && current->size >= size)
			if (min > current->size) {
				min = current->size;
				min_block = current;
			}
		current = current->next;
	}
	if (min_block != NULL) {
		if (split_block(min_block, size))
			coalesce();
	}

	return (void *)min_block;
}

void *extend_last_block(size_t size)
{
	size_t new_size = size - blocks_list.tail->size;
	void *block = sbrk(new_size);

	DIE(block == NULL, "Extending last block error when calling sbrk");
	blocks_list.tail->size = size;
	blocks_list.tail->status = STATUS_ALLOC;
	return blocks_list.tail;
}

void *search_in_memory(size_t size)
{
	void *block_in_list = find_block(size);

	if (block_in_list == NULL && blocks_list.tail->size < size &&
		blocks_list.tail->status == STATUS_FREE)
		block_in_list = extend_last_block(size);

	return block_in_list;
}

// returneaza 1 daca s-a facut coalesce
int coalesce_right(block_meta *b_meta)
{
	if (b_meta->next != NULL && b_meta->next->status == STATUS_FREE) {
		if (is_block_tail(b_meta->next))
			blocks_list.tail = b_meta;
		b_meta->size += b_meta->next->size + META_BLOCK_PADDED;
		b_meta->next = b_meta->next->next;

		if (b_meta->next)
			b_meta->next->prev = b_meta;
		blocks_list.size--;
		return 1;
	}
	return 0;
}

void coalesce(void)
{
	block_meta *current = blocks_list.head;

	while (current != NULL) {
		if (current->status == STATUS_FREE && coalesce_right(current))
			continue;
		current = current->next;
	}
}

int is_block_tail(void *block)
{
	block_meta *b_meta = (block_meta *)block;

	return b_meta == blocks_list.tail;
}
