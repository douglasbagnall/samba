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

#ifndef MAX
#define MAX(a, b)  (((a) >= (b)) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))
#endif


const uint32_t MIN_A = 0;
const uint32_t MIN_B = 0;
const uint32_t MIN_C = 0;
const uint32_t MIN_D = 0;
uint32_t MIN_E;

const uint32_t MAX_A = 10000;
const uint32_t MAX_B = 24;
const uint32_t MAX_C = 24;
const uint32_t MAX_D = 1025;
uint32_t MAX_E;


#define POP 500


struct hash {
	uint32_t A, B, C, D, E;
	uint16_t lut[256];
	int score;
};

struct rng {
	uint64_t a;
	uint64_t b;
	uint64_t c;
	uint64_t d;
};

#define ROTATE(x, k) (((x) << (k)) | ((x) >> (sizeof(x) * 8 - (k))))

static uint64_t rand64(struct rng *x)
{
	uint64_t e = x->a - ROTATE(x->b, 7);
	x->a = x->b ^ ROTATE(x->c, 13);
	x->b = x->c + ROTATE(x->d, 37);
	x->c = x->d + e;
	x->d = e + x->a;
	return x->d;
}

static void rng_init(struct rng *x, uint64_t seed)
{
	int i;
	x->a = 0xf1ea5eed;
	x->b = x->c = x->d = seed;
	for (i = 0; i < 20; ++i) {
		(void)rand64(x);
	}
}

static void rng_random_init(struct rng *rng)
{
	/* random enough for this */
	struct timespec t;
	uint64_t seed;
	clock_gettime(CLOCK_REALTIME, &t);
	seed = ((uint64_t)t.tv_nsec << 20) + t.tv_sec;
	seed ^= (uintptr_t)rng;
	seed += (uintptr_t)&MIN_A;
	printf("seeding with %lu\n", seed);
	rng_init(rng, seed);
}

static uint32_t casefold_hash(struct hash *hash, const char *s)
{
	uint32_t h = hash->A;
	uint32_t h2 = 0;
	while (*s != '\0') {
		uint8_t c = (uint8_t)*s | 32;
		h2 ^= hash->lut[c];
		h = ((h << 5) + h) ^ c;
		s++;
	}
	h ^= h2;
	h %= hash->E;
	//return h + hash->D;
	return (h >> hash->B) ^ ((h >> hash->C) + hash->D);
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

static inline uint32_t rand_range(struct rng *rng, uint32_t low, uint32_t high)
{
	uint64_t r = rand64(rng);
	return low + r % (high - low + 1);
}



static void init_hash(struct hash *hash, struct rng *rng)
{
	unsigned int i;
	hash->A = rand_range(rng, MIN_A, MAX_A);
	hash->B = rand_range(rng, MIN_B, MAX_B);
	hash->C = rand_range(rng, MIN_C, MAX_C);
	hash->D = rand_range(rng, MIN_D, MAX_D);
	hash->E = rand_range(rng, MIN_E, MAX_E);
	for (i = 0; i < 256; i++) {
		hash->lut[i] = i;
	}
	for (i = 0; i < 256; i++) {
		uint8_t c = hash->lut[i];
		int b = rand_range(rng, i, 255);
		hash->lut[i] = hash->lut[b];
		hash->lut[b] = c;
	}
	for (i = 0; i < 256; i++) {
		hash->lut[i] |= i << 8;
	}
	for (i = 0; i < 256; i++) {
		uint8_t c = hash->lut[i];
		int b = rand_range(rng, i, 255);
		hash->lut[i] = hash->lut[b];
		hash->lut[b] = c;
	}
	hash->score = 0;
}

static uint32_t test_one_hash(struct hash *hash, struct strings *s,
			      uint8_t *hits, uint32_t mask)
{
	if (hash->score == 0) {
		int i;
		uint32_t h = 0;
		uint32_t collisions = 0;
		memset(hits, 0, (mask + 1) * sizeof(hits[0]));
		for (i = 0; i < s->n_strings; i++) {
			uint32_t raw = casefold_hash(hash, s->strings[i]);
			h = raw & mask;
			if (hits[h]) {
				collisions++;
			}
			hits[h] = 1;
		}
		hash->score = s->n_strings - collisions;
	}
	return hash->score;
}

static void mutate_hash(struct hash *hash, struct rng *rng, uint r)
{
	int i;
	switch (r) {
	case 0:
		hash->A += rand_range(rng, MIN_A, MAX_A);
		hash->A /= 2;
		break;
	case 1:
		hash->B += rand_range(rng, MIN_B, MAX_B);
		hash->B /= 2;
		break;
	case 2:
		hash->C += rand_range(rng, MIN_C, MAX_C);
		hash->C /= 2;
		break;
	case 3:
		hash->D += rand_range(rng, MIN_D, MAX_D);
		hash->D /= 2;
		break;
	case 4:
		hash->E += rand_range(rng, MIN_E, MAX_E);
		hash->E /= 2;
		break;
	case 5:
		for (i = 0; i < 2; i++) {
			int a = rand_range(rng, 0, 255);
			int b = rand_range(rng, 0, 255);
			uint16_t al = hash->lut[a] & 0x00ff;
			uint16_t ah = hash->lut[a] & 0xff00;
			uint16_t bl = hash->lut[b] & 0x00ff;
			uint16_t bh = hash->lut[b] & 0xff00;
			hash->lut[a] = bh | al;
			hash->lut[b] = ah | bl;
		}
	}
	hash->score = 0;
}

static void refresh_pool(struct hash *hashpool, int *defeats, struct rng *rng)
{
	int i;
	int victims = 0;
	int mutations = 0;
	int inbreds = 0;
	for (i = 0; i < POP; i++) {
		bool inbred = false;

		struct hash *hash = &hashpool[i];
		uint64_t r = rand64(rng);
		if (defeats[i] > 1) {
			int a = rand_range(rng, 0, POP - 1);
			int b = rand_range(rng, 0, POP - 1);
			if (hashpool[a].A == hashpool[b].A &&
			    hashpool[a].B == hashpool[b].B &&
			    hashpool[a].C == hashpool[b].C &&
			    hashpool[a].D == hashpool[b].D &&
			    hashpool[a].E == hashpool[b].E &&
			    memcmp(hashpool[a].lut, hashpool[b].lut,
				   sizeof(hash->lut[0]) * 256) == 0) {
				hashpool[i] = hashpool[a];
				inbred = true; /* inbreeding causes mutations */
				inbreds++;
			}
			else {
				hashpool[i].A = hashpool[r &  1 ? a : b].A;
				hashpool[i].B = hashpool[r &  2 ? a : b].B;
				hashpool[i].C = hashpool[r &  4 ? a : b].C;
				hashpool[i].D = hashpool[r &  8 ? a : b].D;
				hashpool[i].E = hashpool[r & 16 ? a : b].E;
				memcpy(hash->lut, hashpool[r & 32 ? a : b].lut,
				       sizeof(hash->lut[0]) * 256);
			}
			hash->score = 0;
			victims++;
		}
		r >>= 7;
		// mutation
		if ((r & 127) < 6 || inbred) {
			mutations++;
			mutate_hash(hash, rng, r);
			hash->score = 0;
		}
	}
	//printf("victims %d mutations %d inbreds %d\n", victims, mutations, inbreds);
}

static void print_collisions(struct hash *hash, struct strings *s,
			     uint32_t mask)
{
	uint32_t hits[s->n_strings];
	int collisions = 0;
	int i;
	memset(hits, 0, s->n_strings * sizeof(hits[0]));
	for (i = 0; i < s->n_strings; i++) {
		uint32_t h = casefold_hash(hash, s->strings[i]) & mask;
		if (hits[h]) {
			collisions++;
			printf("collision %4x %s %s\n", h,
			       s->strings[i], s->strings[hits[h]]);
		}
		else {
			hits[h] = h;
		}
	}
	printf("%d collisions\n", collisions);
}


int main(int argc, char *argv[])
{
	uint32_t mask;
	struct rng rng;
	uint8_t *hits;
	int i;
	int best_run = 0;
	uint64_t count = 0;
	struct timespec start, end, mid;
	struct hash hashpool[POP];
	int defeats[POP];

	struct hash best_hash;

	if (argc < 3) {
		printf("usage: %s <string list> <hash bits>\n\n",
		       argv[0]);
		printf("string list is one string per line.\n");
	}
	printf("got %s %s %s\n",
	       argv[0], argv[1], argv[2]);

	struct strings strings = load_strings(argv[1]);

	mask = (1 << strtoul(argv[2], NULL, 10)) - 1;

	MAX_E = mask;
	MIN_E = mask - mask / 10;

#if 0
	rng_init(&rng, 12345);
#else
	rng_random_init(&rng);
#endif

	for (i = 0; i < POP; i++) {
		init_hash(&hashpool[i], &rng);
	}

	hits = malloc((mask + 1) * sizeof(hits[0]));

	printf("mask %u n_strings %d\n", mask, strings.n_strings);
	clock_gettime(CLOCK_MONOTONIC, &start);
	mid = start;
	while (true) {
		int i;
		uint32_t s;
		uint32_t cs = 0;
		uint32_t hs = 0;
		uint32_t ls = mask + 2;
		for (i = 0; i < POP; i++) {
			struct hash *hash = &hashpool[i];
			s = test_one_hash(hash, &strings, hits, mask);
			cs += s;
			hs = MAX(s, hs);
			ls = MIN(s, ls);
			if (s > best_run){
				printf("A %5u B %2u C %2u D %3u E %2u score %4d:"
				       "%4d gen %6lu.%04d\n",
				       hash->A, hash->B, hash->C, hash->D,
				       hash->E, s, strings.n_strings - s, count, i);
				best_run = s;
				best_hash = *hash;
				if (s == strings.n_strings) {
					goto win;
				}
			}
		}

		memset(defeats, 0, sizeof(defeats[0]) * POP);
		for (i = 0; i < POP; i++) {
			int b = rand_range(&rng, 0, POP - 1);
			uint64_t r = rand64(&rng);
			int score_i = hashpool[i].score + (r & 1);
			r >>= 2;
			int score_b = hashpool[b].score + (r & 1);

			if (score_i > score_b) {
				defeats[b]++;
			} else if (score_b > score_i) {
				defeats[i]++;
			}
		}
		refresh_pool(hashpool, defeats, &rng);
		count++;
		if (count % (4 * 1024) == 0) {
			int64_t secs, nano, total;
			clock_gettime(CLOCK_MONOTONIC, &end);
			total = end.tv_sec - start.tv_sec;
			secs = end.tv_sec - mid.tv_sec;
			nano = end.tv_nsec - mid.tv_nsec;
			printf("\033[00;37m%luk in %2ld:%02ld:%02ld "
			       "[+%.2fs]\033[00m scores min %4u mean %4u max %4u\n",
			       count >> 10,
			       total / 3600, (total / 60) % 60,
			       total % 60, secs + nano * 1e-9,
			       ls, cs / POP, hs);
			mid = end;
		}
	}
  win:
	print_collisions(&best_hash, &strings, mask);
	printf("final best results\n");
	printf("run %d A %u B %u C %u D %u E %u\n", best_run,
	       best_hash.A, best_hash.B,
	       best_hash.C, best_hash.D,
	       best_hash.E);
	for (i = 0; i < 256; i++) {
		printf("%2x ", best_hash.lut[i]);
	}
	printf("\n");
	return 0;
}
