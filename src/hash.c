#include <stdint.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/evp.h>

#include "hash.h"

#define KEEP 16
#define ALGORITHM_COUNT 4
#define WORKER_COUNT 4
#define NO_INDEX ((size_t)-1)

typedef struct
{
	char *text;
	unsigned int length;
} Password;

typedef struct
{
	char hex[2 * KEEP + 1];
	const char *password;
	const char *algorithm;
	size_t next_duplicate;
} Target;

typedef struct
{
	unsigned char digest[KEEP];
	size_t last_target;
	size_t next_unmatched;
	size_t target_count;
} TargetGroup;

typedef struct
{
	size_t password_index;
	size_t group_index;
	unsigned char algorithm_index;
} MatchEvent;

typedef struct
{
	const Password *passwords;
	const TargetGroup *groups;
	const size_t *slots;
	size_t slot_mask;
	size_t group_count;
	size_t begin;
	size_t end;
	const EVP_MD *algorithms[ALGORITHM_COUNT];
	MatchEvent *events;
	size_t event_count;
	size_t event_capacity;
} Worker;

/* Always fail explicitly rather than silently producing incomplete results. */
static void failure(const char *message)
{
	fprintf(stderr, "project2: %s\n", message);
	exit(EXIT_FAILURE);
}

static void *checked_realloc(void *ptr, size_t size)
{
	void *new_ptr = realloc(ptr, size);
	if (new_ptr == NULL)
		failure("memory allocation failed");
	return new_ptr;
}

/* Read in bulk, then tokenize in place according to fscanf("%s") rules.
 * One shared storage block avoids a million tiny allocations and frees. */
static Password *load_passwords(const char *path, size_t *count, char **storage)
{
	FILE *fp = fopen(path, "rb");
	if (fp == NULL)
		failure("cannot open password file");

	size_t buffer_capacity = 1 << 20;
	char *data = checked_realloc(NULL, buffer_capacity + 1);
	size_t used = 0;

	for (;;)
	{
		if (used == buffer_capacity)
		{
			buffer_capacity *= 2;
			data = checked_realloc(data, buffer_capacity + 1);
		}
		size_t bytes = fread(data + used, 1, buffer_capacity - used, fp);
		used += bytes;
		if (bytes == 0)
		{
			if (ferror(fp))
				failure("cannot read password file");
			break;
		}
	}
	fclose(fp);
	data[used] = '\0';

	size_t capacity = 65536;
	Password *passwords = checked_realloc(NULL, capacity * sizeof(*passwords));
	*count = 0;

	for (size_t pos = 0; pos < used;)
	{
		while (pos < used && isspace((unsigned char)data[pos]))
			pos++;
		if (pos == used)
			break;

		size_t begin = pos;
		while (pos < used && !isspace((unsigned char)data[pos]))
			pos++;
		if (pos < used)
			data[pos++] = '\0';

		if (*count == capacity)
		{
			capacity *= 2;
			passwords = checked_realloc(passwords, capacity * sizeof(*passwords));
		}
		passwords[*count].text = data + begin;
		passwords[*count].length = (unsigned int)strlen(data + begin);
		(*count)++;
	}
	*storage = data;
	return passwords;
}

static Target *load_targets(const char *path, size_t *count)
{
	FILE *fp = fopen(path, "r");
	if (fp == NULL)
		failure("cannot open hash file");

	size_t capacity = 32;
	Target *targets = checked_realloc(NULL, capacity * sizeof(*targets));
	char hex[2 * KEEP + 1];
	*count = 0;

	while (fscanf(fp, "%32s", hex) == 1)
	{
		if (*count == capacity)
		{
			capacity *= 2;
			targets = checked_realloc(targets, capacity * sizeof(*targets));
		}

		Target *target = &targets[*count];
		strcpy(target->hex, hex);
		target->password = NULL;
		target->algorithm = NULL;
		target->next_duplicate = NO_INDEX;
		(*count)++;
	}

	fclose(fp);
	return targets;
}

/* Only lowercase hex can match the baseline's lowercase digest formatting. */
static int hex_to_bytes(const char *hex, unsigned char bytes[KEEP])
{
	if (strlen(hex) != 2 * KEEP)
		return 0;

	for (size_t i = 0; i < KEEP; i++)
	{
		unsigned int nibbles[2];
		for (int j = 0; j < 2; j++)
		{
			unsigned char c = (unsigned char)hex[2 * i + j];
			if (c >= '0' && c <= '9')
				nibbles[j] = c - '0';
			else if (c >= 'a' && c <= 'f')
				nibbles[j] = c - 'a' + 10;
			else
				return 0;
		}
		bytes[i] = (unsigned char)((nibbles[0] << 4) | nibbles[1]);
	}
	return 1;
}

/* A fast table index; full 16-byte equality is still checked after probing. */
static uint64_t digest_hash(const unsigned char digest[KEEP])
{
	uint64_t a, b;
	memcpy(&a, digest, sizeof(a));
	memcpy(&b, digest + sizeof(a), sizeof(b));
	uint64_t value = a ^ (b * UINT64_C(0x9e3779b97f4a7c15));
	value ^= value >> 33;
	value *= UINT64_C(0xff51afd7ed558ccd);
	value ^= value >> 33;
	return value;
}

/* Each distinct target hash owns a linked list of its original input slots. */
static size_t *build_index(Target *targets, size_t target_count,
						   TargetGroup **groups_out, size_t *group_count_out,
						   size_t *slot_mask_out)
{
	size_t slot_count = 32;
	while (slot_count < 2 * target_count)
		slot_count *= 2;

	size_t *slots = calloc(slot_count, sizeof(*slots));
	if (slots == NULL)
		failure("cannot allocate digest index");

	TargetGroup *groups = checked_realloc(NULL,
										  (target_count ? target_count : 1) * sizeof(*groups));
	size_t group_count = 0;
	size_t mask = slot_count - 1;

	for (size_t i = 0; i < target_count; i++)
	{
		unsigned char digest[KEEP];
		if (!hex_to_bytes(targets[i].hex, digest))
			continue;

		size_t slot = (size_t)digest_hash(digest) & mask;
		while (slots[slot] != 0 &&
			   memcmp(groups[slots[slot] - 1].digest, digest, KEEP) != 0)
			slot = (slot + 1) & mask;

		if (slots[slot] == 0)
		{
			size_t index = group_count++;
			memcpy(groups[index].digest, digest, KEEP);
			groups[index].last_target = i;
			groups[index].next_unmatched = i;
			groups[index].target_count = 1;
			slots[slot] = index + 1;
		}
		else
		{
			TargetGroup *group = &groups[slots[slot] - 1];
			targets[group->last_target].next_duplicate = i;
			group->last_target = i;
			group->target_count++;
		}
	}

	*groups_out = groups;
	*group_count_out = group_count;
	*slot_mask_out = mask;
	return slots;
}

static size_t find_target(const Worker *worker, const unsigned char digest[KEEP])
{
	size_t slot = (size_t)digest_hash(digest) & worker->slot_mask;
	while (worker->slots[slot] != 0)
	{
		size_t index = worker->slots[slot] - 1;
		if (memcmp(worker->groups[index].digest, digest, KEEP) == 0)
			return index;
		slot = (slot + 1) & worker->slot_mask;
	}
	return NO_INDEX;
}

static void add_event(Worker *worker, size_t password_index,
					  size_t group_index, unsigned int algorithm_index)
{
	if (worker->event_count == worker->event_capacity)
	{
		size_t capacity = worker->event_capacity ? worker->event_capacity * 2 : 64;
		worker->events = checked_realloc(worker->events,
										 capacity * sizeof(*worker->events));
		worker->event_capacity = capacity;
	}
	MatchEvent *event = &worker->events[worker->event_count++];
	event->password_index = password_index;
	event->group_index = group_index;
	event->algorithm_index = (unsigned char)algorithm_index;
}

/* Every worker owns its contexts and event list; target lookup is read-only. */
static void *hash_password_range(void *arg)
{
	Worker *worker = arg;
	EVP_MD_CTX *contexts[ALGORITHM_COUNT];
	size_t *recorded = calloc(worker->group_count, sizeof(*recorded));
	if (recorded == NULL)
		failure("cannot allocate per-worker match counts");

	for (int i = 0; i < ALGORITHM_COUNT; i++)
	{
		contexts[i] = EVP_MD_CTX_new();
		if (contexts[i] == NULL)
			failure("cannot create OpenSSL context");
	}

	for (size_t i = worker->begin; i < worker->end; i++)
	{
		const Password *password = &worker->passwords[i];

		/* Preserve MD5, SHA1, SHA256, SHA512 ordering for each password. */
		for (int a = 0; a < ALGORITHM_COUNT; a++)
		{
			unsigned char digest[EVP_MAX_MD_SIZE];
			unsigned int digest_length = 0;
			if (!EVP_DigestInit_ex(contexts[a], worker->algorithms[a], NULL) ||
				!EVP_DigestUpdate(contexts[a], password->text, password->length) ||
				!EVP_DigestFinal_ex(contexts[a], digest, &digest_length) ||
				digest_length < KEEP)
				failure("OpenSSL digest computation failed");

			size_t group = find_target(worker, digest);
			/* A worker needs at most one event per target slot per digest.
			 * Discard later matches locally without changing merge order. */
			if (group != NO_INDEX &&
				recorded[group] < worker->groups[group].target_count)
			{
				add_event(worker, i, group, (unsigned int)a);
				recorded[group]++;
			}
		}
	}

	for (int i = 0; i < ALGORITHM_COUNT; i++)
		EVP_MD_CTX_free(contexts[i]);
	free(recorded);
	return NULL;
}

void crack_hashed_passwords(char *password_list, char *hashed_list, char *output)
{
	size_t target_count = 0;
	Target *targets = load_targets(hashed_list, &target_count);

	TargetGroup *groups;
	size_t group_count, slot_mask;
	size_t *slots = build_index(targets, target_count, &groups,
								&group_count, &slot_mask);

	/* Empty or nonmatching-format target files need no digest computations. */
	if (group_count != 0)
	{
		size_t password_count = 0;
		char *password_storage = NULL;
		Password *passwords = load_passwords(password_list, &password_count,
											 &password_storage);
		const EVP_MD *algorithms[ALGORITHM_COUNT] = {
			EVP_md5(), EVP_sha1(), EVP_sha256(), EVP_sha512()};
		const char *algorithm_names[ALGORITHM_COUNT] = {
			"MD5", "SHA1", "SHA256", "SHA512"};
		/* A sequential path avoids thread overhead for small dictionaries. */
		int worker_count = password_count < 8192 ? 1 : WORKER_COUNT;
		Worker workers[WORKER_COUNT] = {0};
		pthread_t threads[WORKER_COUNT - 1];
		int started[WORKER_COUNT - 1] = {0};

		/* Contiguous ranges make each worker's events already dictionary-sorted. */
		for (int i = 0; i < worker_count; i++)
		{
			Worker *worker = &workers[i];
			worker->passwords = passwords;
			worker->groups = groups;
			worker->slots = slots;
			worker->slot_mask = slot_mask;
			worker->group_count = group_count;
			worker->begin = password_count * (size_t)i / (size_t)worker_count;
			worker->end = password_count * (size_t)(i + 1) / (size_t)worker_count;
			memcpy(worker->algorithms, algorithms, sizeof(algorithms));
		}

		/* Three pthreads plus the main thread: four concurrent threads total. */
		for (int i = 1; i < worker_count; i++)
		{
			if (pthread_create(&threads[i - 1], NULL,
							   hash_password_range, &workers[i]) == 0)
				started[i - 1] = 1;
			else
				hash_password_range(&workers[i]);
		}
		hash_password_range(&workers[0]);
		for (int i = 1; i < worker_count; i++)
		{
			if (started[i - 1] && pthread_join(threads[i - 1], NULL) != 0)
				failure("cannot join worker thread");
		}

		/* Replaying matches in (password, algorithm) order preserves the
		 * baseline's first-unmatched-target rule, even with duplicates. */
		for (int i = 0; i < worker_count; i++)
		{
			Worker *worker = &workers[i];
			for (size_t j = 0; j < worker->event_count; j++)
			{
				const MatchEvent *event = &worker->events[j];
				TargetGroup *group = &groups[event->group_index];
				size_t target_index = group->next_unmatched;
				if (target_index == NO_INDEX)
					continue;

				targets[target_index].password = passwords[event->password_index].text;
				targets[target_index].algorithm = algorithm_names[event->algorithm_index];
				group->next_unmatched = targets[target_index].next_duplicate;
			}
			free(worker->events);
		}

		/* Matched password storage remains valid until after output is written. */
		FILE *fp = fopen(output, "w");
		if (fp == NULL)
			failure("cannot open output file");
		for (size_t i = 0; i < target_count; i++)
		{
			if (targets[i].password == NULL)
				fprintf(fp, "not found\n");
			else
				fprintf(fp, "%s:%s\n", targets[i].password, targets[i].algorithm);
		}
		fclose(fp);

		free(passwords);
		free(password_storage);
	}
	else
	{
		FILE *fp = fopen(output, "w");
		if (fp == NULL)
			failure("cannot open output file");
		for (size_t i = 0; i < target_count; i++)
			fprintf(fp, "not found\n");
		fclose(fp);
	}

	free(slots);
	free(groups);
	free(targets);
}
