#include "config.h"

#include <ldns/ldns.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bloom_filter/bloom.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <errno.h>

char* prog;
int verbosity = 2;

unsigned int count_rrsigs(FILE* fp)
{
  ldns_rr* current_rr = NULL;
  ldns_status status;
  int line_nr = 0;

  size_t rrsig_count = 0;
  while ((status = ldns_rr_new_frm_fp_l(&current_rr, fp, 0, NULL, NULL, &line_nr)) == LDNS_STATUS_OK) {
    if (ldns_rr_get_type(current_rr) == LDNS_RR_TYPE_RRSIG) {
      rrsig_count++;
    }
    ldns_rr_free(current_rr);
  }
  if (status != LDNS_STATUS_SYNTAX_EMPTY && status != LDNS_STATUS_OK) {
    fprintf(stderr, "Error parsing zone at line %d: %s\n",
            line_nr, ldns_get_errorstr_by_id(status));
  }

  return rrsig_count;
}

typedef enum ldns_enum_filter_algorithm
{
  BLOOM_FILTER,
  GOLOMB_COMPRESSED_SET,
  BINARY_FUSE_FILTER,
} ldns_filter_algorithms;

ldns_lookup_table filter_algorithms[] = {
  {BLOOM_FILTER, "Bloom filter"},
  {GOLOMB_COMPRESSED_SET, "Golomb compressed set"},
  {BINARY_FUSE_FILTER, "Binary fuse filter"}};

static void
show_algorithms(FILE* out)
{
  ldns_lookup_table* lt = filter_algorithms;
  fprintf(out, "Possible algorithms:\n");

  while (lt->name) {
    fprintf(out, "%s\n", lt->name);
    lt++;
  }
}

static void
usage(FILE* fp, char* prog)
{
  fprintf(fp, "%s [-f <filter>] [-u] [-v] -p <false positive rate> <zonefile1> <zonefile2>  key [key [key]]  \n",
          prog);
  fprintf(fp, "  generate a new filter rr type\n");
  fprintf(fp, "  -f - filter type (default to a bloom fitler) (-f list to show a list)\n");
  fprintf(fp, "  -p <double> - false positive rate (must be greater than 0)\n");
  fprintf(fp, "  -u <int> - number of modified RRSIG to be included in a filter (default value 1000) and must be greater than 1000\n");
}

ldns_status load_rrsigs(const char* filename, ldns_rr_list** rrsig_list)
{
  FILE* fp = fopen(filename, "r");

  if (!fp) {
    fprintf(stderr, "Unable to open %s: %s\n", filename, strerror(errno));
    return LDNS_STATUS_FILE_ERR;
  }

  ldns_rr* rr = NULL;
  ldns_status status = LDNS_STATUS_OK;
  int line_nr = 0;
  while ((status = ldns_rr_new_frm_fp_l(&rr, fp, NULL, NULL, NULL, &line_nr))) {
    if (!rr)
      continue;

    if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG) {
      ldns_rr_list_push_rr(*rrsig_list, rr);
    }
    else {
      ldns_rr_free(rr);
    }
  }

  if (status != LDNS_STATUS_SYNTAX_EMPTY && status != LDNS_STATUS_OK) {
    fprintf(stderr, "Warning: Parsing ended with status %s at line %d in %s\n",
            ldns_get_errorstr_by_id(status), line_nr, filename);
  }

  fclose(fp);

  return LDNS_STATUS_OK;
}

int main(int argc, char* argv[])
{

  int c;
  ldns_filter_algorithms filter = BLOOM_FILTER;
  double false_positive = 0;
  while ((c = getopt(argc, argv, "f:u:vp:")) != -1) {
    switch (c) {
    case 'f':
      if (filter != 0) {
        fprintf(stderr, "The -f argument can only be used once\n");
        exit(1);
      }
      if (strncmp(optarg, "list", 5) == 0) {
        show_algorithms(stdout);
        exit(EXIT_SUCCESS);
      }
      break;
    case 'p':
      false_positive = (double)atoi(optarg);
      break;

    default:
      exit(EXIT_FAILURE);
      break;
    }
  }

  argc -= optind;
  argv += optind;

  if (argc != 2) {
    argv -= optind;
    usage(stderr, argv[0]);
    exit(EXIT_FAILURE);
  }

  char *fn1, *fn2;
  fn1 = argv[0];
  ldns_rr_list* sigs1 = ldns_rr_list_new();
  printf("Reading Zone 1: %s\n", fn1);
  if (load_rrsigs(fn1, &sigs1)) {
    exit(EXIT_FAILURE);
  }
  printf("Loaded %zu RRSIGs from %s\n", ldns_rr_list_rr_count(sigs1), fn1);

  fn2 = argv[1];
  ldns_rr_list* sigs2 = ldns_rr_list_new();
  printf("Reading Zone 2: %s\n", fn2);
  if (load_rrsigs(fn2, &sigs2)) {
    exit(EXIT_FAILURE);
  }
  printf("Loaded %zu RRSIGs from %s\n", ldns_rr_list_rr_count(sigs2), fn2);

  printf("Canonicalizing and sorting...\n");
  for (size_t i = 0; i < ldns_rr_list_rr_count(sigs1); i++) {
    ldns_rr2canonical(ldns_rr_list_rr(sigs1, i));
  }
  ldns_rr_list_sort(sigs1);

  for (size_t i = 0; i < ldns_rr_list_rr_count(sigs2); i++) {
    ldns_rr2canonical(ldns_rr_list_rr(sigs2, i));
  }
  ldns_rr_list_sort(sigs2);

  printf("Comparing lists...\n");
  size_t i1 = 0, i2 = 0;
  size_t c1 = ldns_rr_list_rr_count(sigs1);
  size_t c2 = ldns_rr_list_rr_count(sigs2);

  ldns_rr_list* affected_rrsigs = ldns_rr_list_new();
  while (i1 < c1 && i2 < c2) {
    ldns_rr* rr1 = ldns_rr_list_rr(sigs1, i1);
    ldns_rr* rr2 = ldns_rr_list_rr(sigs2, i2);

    int cmp = ldns_rr_compare(rr1, rr2);

    if (cmp < 0) {
      /* rr1 is smaller than rr2, so rr1 is not in zone file 2 (since lists are sorted) */
      ldns_rr_list_push_rr(affected_rrsigs, rr1);
      i1++;
    }
    else if (cmp > 0) {
      i2++;
    }
    else {
      i1++;
      i2++;
    }
  }

  while (i1 < c1) {
    ldns_rr* rr1 = ldns_rr_list_rr(sigs1, i1);
    ldns_rr_list_push_rr(affected_rrsigs, rr1);
    i1++;
  }

  ldns_rr_list_deep_free(sigs1);
  ldns_rr_list_deep_free(sigs2);

  struct bloom bloom;
  if (bloom_init2(&bloom, ldns_rr_list_rr_count(affected_rrsigs), false_positive) != 0) {
    fprintf(stderr, "Error initializing bloom filter\n");
    ldns_rr_list_deep_free(sigs1);
    ldns_rr_list_deep_free(sigs2);
    exit(EXIT_FAILURE);
  }

  ldns_rdf* exp = ldns_rr_rrsig_expiration(ldns_rr_list_rr(sigs1, 0));

  for (size_t i = 0; i < ldns_rr_list_rr_count(affected_rrsigs); i++) {
    uint8_t* wire = NULL;
    size_t size = 0;
    if (ldns_rr2wire(&wire, ldns_rr_list_rr(affected_rrsigs, i), LDNS_SECTION_ANSWER, &size) == LDNS_STATUS_OK) {
      bloom_add(&bloom, wire, (int)size);
      LDNS_FREE(wire);
    }
  }

  bloom_print(&bloom);

  ldns_rr_list_deep_free(affected_rrsigs);
  bloom_free(&bloom);

  exit(EXIT_SUCCESS);
}
