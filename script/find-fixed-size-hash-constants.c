#include <inttypes.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define DEBUG(format, ...) do {                                 \
    fprintf (stderr, (format),## __VA_ARGS__);                  \
    fputc('\n', stderr);                                         \
    fflush(stderr);                                             \
    } while (0)


//const uint32_t INIT_A = 5381;
const uint32_t INIT_A = 1296;
const uint32_t INIT_B = 0;
const uint32_t INIT_C = 20;
const uint32_t INIT_D = 0;
const uint32_t INIT_E = 6;

//const uint32_t LIMIT_A = 0;
const uint32_t LIMIT_A = 1294;
const uint32_t LIMIT_B = 20;
const uint32_t LIMIT_C = 0;
const uint32_t LIMIT_D = 10000;
const uint32_t LIMIT_E = 3;


struct hash {
	uint32_t A, B, C, D, E;
};

static uint32_t case_hash(struct hash hash, const char *s)
{
	uint32_t h = hash.A;
	while (*s != '\0') {
		uint8_t c = (uint8_t)*s | 32;
		h = ((h << hash.E) + h) ^ c;
		s++;
	}
	return (h >> hash.B) ^ ((h >> hash.C) + hash.D);
}

struct strings {
	int n_strings;
	char *mem;
	char **strings;
};

static struct strings load_strings(const char *filename)
{
	int i, j;
	int len;
	size_t read;

	struct strings s = {0, 0, 0};

	FILE *f = fopen(filename, "r");
	if (f == NULL) {
		printf("could not open %s\n", filename);
		return s;
	}
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	rewind(f);

	s.mem = malloc(len + 1);
	if (s.mem == NULL) {
		printf("could not allocate %d bytes?!\n", len + 1);
		return s;
	}
	read = fread(s.mem, 1, len, f);
	if (read != len) {
		printf("gah, C file handling, wanted %d, got %lu\n",
		       len, read);
		free(s.mem);
		return s;
	}
	for (i = 0; i < len; i++) {
		if (s.mem[i] == '\n') {
			s.mem[i] = '\0';
			s.n_strings++;
		}
	}
	s.strings = malloc(len * sizeof(char*));

	s.strings[0] = s.mem;
	j = 1;
	for (i = 0; i < len; i++) {
		if (s.mem[i] == '\0' && j < s.n_strings) {
			s.strings[j] = s.mem + i + 1;
			j++;
		}
	}
	return s;
}

static bool change_constants(struct hash *hash)
{
	if (hash->E != LIMIT_E) {
		hash->E--;
		return true;
	}
	hash->E = INIT_E;
	if (hash->C != LIMIT_C) {
		hash->C--;
		return true;
	}
	hash->C = INIT_C;
	if (hash->B != LIMIT_B) {
		hash->B++;
		return true;
	}
	hash->B = INIT_B;
	if (hash->A != LIMIT_A) {
		hash->A--;
		return true;
	}
	hash->A = INIT_A;
	if (hash->D != LIMIT_D) {
		hash->D++;
		return true;
	}
	return false;
}


int main(int argc, char *argv[])
{
	uint32_t mask;
	int *hits;

	int best_run = 0;
	uint64_t count = 0;
	struct timespec start, end, mid;
	struct hash hash = { INIT_A, INIT_B, INIT_C, INIT_D, INIT_E};
	struct hash best_hash = hash;
	int64_t cycle_length = ((1 + INIT_A - LIMIT_A) *
				(1 + LIMIT_B - INIT_B) *
				(1 + INIT_C - LIMIT_C) *
				(1 + LIMIT_D - INIT_D) *
				(1 + INIT_E - LIMIT_E));
	if (argc < 3) {
		printf("usage: %s <string list> <hash bits>\n\n",
		       argv[0]);
		printf("string list is one string per line.\n");
	}
	printf("got %s %s %s\n",
	       argv[0], argv[1], argv[2]);

	struct strings s = load_strings(argv[1]);

	mask = (1 << strtoul(argv[2], NULL, 10)) - 1;

	hits = malloc((mask + 1) * sizeof(hits[0]));

	printf("mask %u n_strings %d cycle %ld\n", mask, s.n_strings,
	       cycle_length);
	clock_gettime(CLOCK_MONOTONIC, &start);
	mid = start;
	while (true) {
		int i;
		uint32_t h = 0;
		memset(hits, 0, (mask + 1) * sizeof(hits[0]));
		for (i = 0; i < s.n_strings; i++) {
			h = case_hash(hash, s.strings[i]) & mask;
			if (hits[h]) {
				break;
			}
			hits[h] = i;
		}

		if (i > best_run){
			printf("A %u B %u C %u D %u E %u run %d\n",
			       hash.A, hash.B, hash.C, hash.D, hash.E,
			       i);
			printf("collision: %s  %s\n",
			       s.strings[hits[h]],  s.strings[i]);


			best_run = i;
			best_hash = hash;
			if (i == s.n_strings) {
				break;
			}
		}
		count++;
		if (count % (1024 * 1024) == 0) {
			int64_t secs, nano, total;
			clock_gettime(CLOCK_MONOTONIC, &end);
			total = end.tv_sec - start.tv_sec;
			secs = end.tv_sec - mid.tv_sec;
			nano = end.tv_nsec - mid.tv_nsec;
			printf("%luM (%lu%%) in %lds [+%.2fs]; "
			       "(A %u B %u C %u D %u E %u)\n",
			       count >> 20, count * 100 / cycle_length,
			       total, secs + nano * 1e-9,
			       hash.A, hash.B, hash.C, hash.D, hash.E);
			mid = end;
		}
		if (change_constants(&hash) == false) {
			break;
		}
	}

	printf("final best results\n");
	printf("run %d A %u B %u C %u D %u E %u\n", best_run,
	       best_hash.A, best_hash.B,
	       best_hash.C, best_hash.D,
	       best_hash.E);
	return 0;
}
