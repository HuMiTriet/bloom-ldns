#include "config.h"

#include <ldns/ldns.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bloom_filter/bloom.h"
#include "ldns/host2str.h"
#include "ldns/rdata.h"
#include "ldns/rr.h"
#include "ldns/rr_functions.h"
#include "ldns/zone.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <errno.h>

char* prog;
int verbosity = 2;

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

ldns_status load_rrsigs(const char* filename, ldns_rr_list** rrsig_list, bool rrsig_file)
{
  FILE* fp = fopen(filename, "r");

  if (!fp) {
    fprintf(stderr, "Unable to open %s: %s\n", filename, strerror(errno));
    return LDNS_STATUS_FILE_ERR;
  }

  ldns_rr* rr = NULL;
  ldns_status status = LDNS_STATUS_OK;
  int line_nr = 0;
  if (rrsig_file) {
    ldns_zone* zone = NULL;
    status = ldns_zone_new_frm_fp_l(&zone, fp, NULL, 3600, LDNS_RR_CLASS_IN, &line_nr);
    *rrsig_list = ldns_zone_rrs(zone);
  }
  else {
    while ((status = ldns_rr_new_frm_fp_l(&rr, fp, NULL, NULL, NULL, &line_nr)) == LDNS_STATUS_OK) {
      if (!rr)
        continue;

      if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG) {
        ldns_rr_list_push_rr(*rrsig_list, rr);
      }
      else {
        ldns_rr_free(rr);
      }
    }
  }

  if (status != LDNS_STATUS_SYNTAX_EMPTY && status != LDNS_STATUS_OK) {
    fprintf(stderr, "Warning: Parsing ended with status %s at line %d in %s\n",
            ldns_get_errorstr_by_id(status), line_nr, filename);
  }

  fclose(fp);

  return LDNS_STATUS_OK;
}

int compare_exp_date(const void* a, const void* b)
{
  ldns_rr* rrsig_a = *(ldns_rr**)a;
  ldns_rr* rrsig_b = *(ldns_rr**)b;

  int32_t exp_a = (int32_t)ldns_rdf2native_time_t(ldns_rr_rrsig_expiration(rrsig_a));
  int32_t exp_b = (int32_t)ldns_rdf2native_time_t(ldns_rr_rrsig_expiration(rrsig_b));

  return exp_a - exp_b;
}

int main(int argc, char* argv[])
{

  int c;
  ldns_filter_algorithms filter = BLOOM_FILTER;
  double false_positive = 0.2;
  bool rrsig_file = false;
  while ((c = getopt(argc, argv, "f:u:vp:r")) != -1) {
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
    case 'r':
      rrsig_file = true;
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
  if (load_rrsigs(fn1, &sigs1, rrsig_file)) {
    exit(EXIT_FAILURE);
  }
  printf("Loaded %zu RRSIGs from %s\n", ldns_rr_list_rr_count(sigs1), fn1);

  fn2 = argv[1];
  ldns_rr_list* sigs2 = ldns_rr_list_new();
  printf("Reading Zone 2: %s\n", fn2);
  if (load_rrsigs(fn2, &sigs2, rrsig_file)) {
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

  ldns_rr_list* tmp_rrsigs = ldns_rr_list_new();
  while (i1 < c1 && i2 < c2) {
    ldns_rr* rr1 = ldns_rr_list_rr(sigs1, i1);
    ldns_rr* rr2 = ldns_rr_list_rr(sigs2, i2);

    int cmp = ldns_rr_compare(rr1, rr2);

    if (cmp < 0) {

#ifdef DEBUG
      printf("rrsig in %s :\n", fn1);
      ldns_rr_print(stdout, rr1);
      char exp_buf[26], inc_buf[26];
      time_t t_exp = ldns_rdf2native_time_t(ldns_rr_rrsig_expiration(rr1));
      time_t t_inc = ldns_rdf2native_time_t(ldns_rr_rrsig_inception(rr1));
      struct tm tm_exp, tm_inc;
      localtime_r(&t_exp, &tm_exp);
      localtime_r(&t_inc, &tm_inc);
      strftime(exp_buf, sizeof(exp_buf), "%Y-%m-%d %H:%M:%S", &tm_exp);
      strftime(inc_buf, sizeof(inc_buf), "%Y-%m-%d %H:%M:%S", &tm_inc);
      printf("  Expiration: %s\n  Inception: %s\n", exp_buf, inc_buf);
      printf("===========================================\n");
      printf("rrsig in %s :\n", fn2);
      ldns_rr_print(stdout, rr2);
      t_exp = ldns_rdf2native_time_t(ldns_rr_rrsig_expiration(rr2));
      t_inc = ldns_rdf2native_time_t(ldns_rr_rrsig_inception(rr2));
      localtime_r(&t_exp, &tm_exp);
      localtime_r(&t_inc, &tm_inc);
      strftime(exp_buf, sizeof(exp_buf), "%Y-%m-%d %H:%M:%S", &tm_exp);
      strftime(inc_buf, sizeof(inc_buf), "%Y-%m-%d %H:%M:%S", &tm_inc);
      printf("  Expiration: %s\n  Inception: %s\n", exp_buf, inc_buf);
      printf("\n");
#endif /* ifdef DEBUG */

      /* rr1 is smaller than rr2, so rr1 is not in zone file 2 (since lists are sorted) */
      ldns_rdf2buffer_str_time(ldns_rr_rrsig_origttl(rr1));
      ldns_rr_list_push_rr(tmp_rrsigs, rr1);
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
    ldns_rr_list_push_rr(tmp_rrsigs, rr1);
    i1++;
  }

  ldns_rr_list* affected_rrsigs = ldns_rr_list_clone(tmp_rrsigs);

  ldns_rr_list_free(tmp_rrsigs);
  ldns_rr_list_deep_free(sigs1);
  ldns_rr_list_deep_free(sigs2);

  /* Sort by expiration date using qsort and the helper function */
  qsort(affected_rrsigs->_rrs,
        ldns_rr_list_rr_count(affected_rrsigs),
        sizeof(ldns_rr*),
        compare_exp_date);

  // split the rrsigs according to their expiration date.

  size_t count = ldns_rr_list_rr_count(affected_rrsigs);
  size_t group_start = 0;
  for (size_t i = 1; i <= count; i++) {
    bool end_of_group = false;
    if (i == count) {
      end_of_group = true;
    }
    else {
      ldns_rr* prev = ldns_rr_list_rr(affected_rrsigs, group_start);
      ldns_rr* curr = ldns_rr_list_rr(affected_rrsigs, i);
      ldns_rdf* prev_exp = ldns_rr_rrsig_expiration(prev);
      ldns_rdf* curr_exp = ldns_rr_rrsig_expiration(curr);

      time_t t_prev = ldns_rdf2native_time_t(prev_exp);
      time_t t_curr = ldns_rdf2native_time_t(curr_exp);
      struct tm tm_prev, tm_curr;
      localtime_r(&t_prev, &tm_prev);
      localtime_r(&t_curr, &tm_curr);

      if (tm_prev.tm_year != tm_curr.tm_year || tm_prev.tm_mon != tm_curr.tm_mon || tm_prev.tm_mday != tm_curr.tm_mday) {
        end_of_group = true;
      }
    }

    if (end_of_group) {
      size_t group_size = i - group_start;
      ldns_rr* representative = ldns_rr_list_rr(affected_rrsigs, i - 1);
      ldns_rdf* exp = ldns_rr_rrsig_expiration(representative);
      time_t t = ldns_rdf2native_time_t(exp);
      char buf[26];
      strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&t));
      printf("Expiration: %s\n", buf);

      struct bloom bloom;

      size_t bloom_size = (group_size < 1000) ? 1000 : group_size;
      if (bloom_init2(&bloom, bloom_size, false_positive) != 0) {
        fprintf(stderr, "Error initializing bloom filter\n");
        exit(EXIT_FAILURE);
      }

      for (size_t j = group_start; j < i; j++) {
        uint8_t* wire = NULL;
        size_t size = 0;
        if (ldns_rr2wire(&wire, ldns_rr_list_rr(affected_rrsigs, j), LDNS_SECTION_ANSWER, &size) == LDNS_STATUS_OK) {
          bloom_add(&bloom, wire, (int)size);
          LDNS_FREE(wire);
        }
      }
      bloom_print(&bloom);
      bloom_free(&bloom);
      printf("\n");

      group_start = i;
    }
  }

  ldns_rr_list_deep_free(affected_rrsigs);

  exit(EXIT_SUCCESS);
}
