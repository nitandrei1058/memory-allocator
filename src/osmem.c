// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "osmem.h"
#include "block_allocation.h"
#include "block_meta.h"
#include "utils.h"

void *allocate_memory(size_t size, size_t threshold)
{
	if (size == 0)
		return NULL;

	void *block = NULL;

	size = PAD(size);
	size_t b_size = size + META_BLOCK_PADDED;

	if (b_size < threshold) {
		if (!get_heap_alloc()) {
			block = sbrk(MMAP_THRESHOLD);
			DIE(block == NULL, "Malloc error when calling sbrk");
			fill_block_meta(block, MMAP_THRESHOLD - META_BLOCK_PADDED,
							STATUS_FREE);
			heap_prealloc(block);
		}
		block = search_in_memory(size);
		if (block == NULL) {
			block = sbrk(b_size);
			DIE(block == NULL, "Malloc error when calling sbrk");
			fill_block_meta(block, size, STATUS_ALLOC);
			attach_block(block);
		} else {
			((block_meta *)block)->status = STATUS_ALLOC;
		}
	} else {
		block = mmap(NULL, b_size, PROT_READ | PROT_WRITE,
					 MAP_PRIVATE | MAP_ANON, -1, 0);
		DIE(block == NULL, "Malloc error when calling mmap");
		fill_block_meta(block, size, STATUS_MAPPED);
	}
	return extract_payload(block);
}

void *os_malloc(size_t size) { return allocate_memory(size, MMAP_THRESHOLD); }
void os_free(void *ptr)
{
	if (ptr == NULL)
		return;
	// trebuie sa readuc ptr la adresa de inceput a blocului
	block_meta *block = (block_meta *)(ptr - META_BLOCK_PADDED);

	if (block->status == STATUS_MAPPED) {
		int res = munmap(block, block->size + META_BLOCK_PADDED);

		DIE(res == -1, "Free error when calling munmap");
	} else if (block->status == STATUS_ALLOC) {
		block->status = STATUS_FREE;
		coalesce();
	} // daca blocul este deja free, nu facem nimic
}

void set_memory_zero(void *data, size_t size)
{
	for (size_t i = 0; i < size; i++)
		*(((char *)data) + i) = 0;
}

void *os_calloc(size_t nmemb, size_t size)
{
	void *block = allocate_memory(nmemb * size, getpagesize());

	if (block) {
		set_memory_zero(block, nmemb * size);
		return block;
	}
	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	if (ptr == NULL)
		return os_malloc(size);

	block_meta *b_meta = (block_meta *)(ptr - META_BLOCK_PADDED);

	if (b_meta->status == STATUS_MAPPED) {
		void *new_block = os_malloc(size);

		memcpy(new_block, ptr, b_meta->size < size ? b_meta->size : size);
		os_free(ptr);
		return new_block;
	}

	if (b_meta->status == STATUS_ALLOC) {
		// verifica daca putem sa-l extindem
		if (PAD(b_meta->size) < PAD(size)) {
			if (is_block_tail(b_meta))
				extend_last_block(PAD(size));
			while (!is_block_tail(b_meta) &&
				   b_meta->next->status == STATUS_FREE) {
				coalesce_right(b_meta);
				if (PAD(b_meta->size) >=
					PAD(size)) { // daca am reusit sa extindem blocul
					split_block(b_meta, PAD(size));
					break;
				}
			}
			// daca nu a mers extinderea
			if (PAD(b_meta->size) < PAD(size)) {
				void *new_block = os_malloc(size);

				memcpy(new_block, ptr,
					   b_meta->size < size ? b_meta->size : size);
				os_free(ptr);
				return new_block;
			}
			// mai e nevoie de realocare bruta
		} else {
			split_block(b_meta, PAD(size)); // PAD(b_meta->size) >= PAD(size),
											// deci trebuie micsorat
		}
		return ptr;
	}
	return NULL; // b_meta->status == STATUS_FREE
}
