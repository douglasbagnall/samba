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


const uint32_t INIT_A = 5381;
//const uint32_t INIT_A = 1296;
const uint32_t INIT_B = 0;
const uint32_t INIT_C = 16;
const uint32_t INIT_D = 0;
const uint32_t INIT_E = 24;

//const uint32_t LIMIT_A = 0;
const uint32_t LIMIT_A = 0;
const uint32_t LIMIT_B = 10;
const uint32_t LIMIT_C = 0;
const uint32_t LIMIT_D = 200;
const uint32_t LIMIT_E = 10;


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
	return (h >> hash.B) ^ (h >> hash.E) ^ ((h >> hash.C) + hash.D);
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
	uint8_t *hits;

	int best_collisions;
	int best_compares;
	uint64_t count = 0;
	struct timespec start, end, mid;
	struct hash hash = { INIT_A, INIT_B, INIT_C, INIT_D, INIT_E};
	struct hash best_collisions_hash = hash;
	struct hash best_compares_hash = hash;
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

	hits = malloc(mask + 1);

	best_collisions = mask + 1;
	best_compares = mask + 1;
	printf("mask %u n_strings %d cycle %ld\n", mask, s.n_strings,
	       cycle_length);
	clock_gettime(CLOCK_MONOTONIC, &start);
	mid = start;
	while (true) {
		int i;
		int collisions = 0;
		int compares = 0;
		uint32_t g;
		memset(hits, 0, mask + 1);
		for (i = 0; i < s.n_strings; i++) {
			uint32_t h = case_hash(hash, s.strings[i]) & mask;
			if (hits[h]) {
				if (hits[h] == 1) {
					collisions++;
				}
				compares++;
				for (g = (h + 1) & mask;
				     hits[g] && g != h;
				     g = (g + 1) & mask) {
					compares++;
				}
				hits[g] = 2; /* the first available space */
			}
			if (compares >= best_compares &&
			    collisions >= best_collisions) {
				//DEBUG("breaking after %d\n", i);
				break;
			}
			hits[h] = 1;
		}
		//DEBUG("collisions %d compares %d\n", collisions, compares);

		if (compares < best_compares || collisions < best_collisions) {
			printf("A %u B %u C %u D %u E %u collisions %d compares %d\n",
			       hash.A, hash.B, hash.C, hash.D, hash.E,
			       collisions, compares);
			if (compares < best_compares) {
				best_compares = compares;
				best_compares_hash = hash;
			}
			if (collisions < best_collisions) {
				best_collisions = collisions;
				best_collisions_hash = hash;
			}
		}
		if (compares == 0 && collisions == 0) {
			break;
		}
		count++;
		if (count % (1024 * 1024) == 0) {
			int64_t secs, nano, total;
			clock_gettime(CLOCK_MONOTONIC, &end);
			total = end.tv_sec - start.tv_sec;
			secs = end.tv_sec - mid.tv_sec;
			nano = end.tv_nsec - mid.tv_nsec;
			printf("\033[00;37m%luM (%lu%%) in %2ld:%02ld:%02ld "
			       "[+%.2fs]; (A %u B %u C %u D %u E %u)\033[00m\n",
			       count >> 20, count * 100 / cycle_length,
			       total / 3600, (total / 60) % 60,
			       total % 60, secs + nano * 1e-9,
			       hash.A, hash.B, hash.C, hash.D, hash.E);
			mid = end;
		}
		if (change_constants(&hash) == false) {
			break;
		}
	}

	printf("final best results\n");
	printf("collisions %d A %u B %u C %u D %u E %u\n", best_collisions,
	       best_collisions_hash.A, best_collisions_hash.B,
	       best_collisions_hash.C, best_collisions_hash.D,
	       best_collisions_hash.E);
	printf("compares %d   A %u B %u C %u D %u E %u\n", best_compares,
	       best_compares_hash.A, best_compares_hash.B,
	       best_compares_hash.C, best_compares_hash.D,
	       best_collisions_hash.E);
	return 0;
}
