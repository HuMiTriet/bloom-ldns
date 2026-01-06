#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bloom_filter/bloom.h"
#include "ldns/error.h"
#include "ldns/rr.h"
#include "ldns/util.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

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
  fprintf(fp, "%s [-f <filter>] -p <false positive rate> [-u] [-v] [-a] key [key [key]]  \n",
          prog);
  fprintf(fp, "  generate a new key pair for domain\n");
  fprintf(fp, "  -a <alg>\tuse the specified algorithm (-a list to");
  fprintf(fp, " show a list)\n");
  fprintf(fp, "  -k\t\tset the flags to 257; key signing key\n");
  fprintf(fp, "  -b <bits>\tspecify the keylength\n");
  fprintf(fp, "  -r <random>\tspecify a random device (defaults to /dev/random)\n");
  fprintf(fp, "\t\tto seed the random generator with\n");
  fprintf(fp, "  -s\t\tcreate additional symlinks with constant names\n");
  fprintf(fp, "  -f\t\tforce override of existing symlinks\n");
  fprintf(fp, "  -v\t\tshow the version and exit\n");
  fprintf(fp, "  The following files will be created:\n");
  fprintf(fp, "    K<name>+<alg>+<id>.key\tPublic key in RR format\n");
  fprintf(fp, "    K<name>+<alg>+<id>.private\tPrivate key in key format\n");
  fprintf(fp, "    K<name>+<alg>+<id>.ds\tDS in RR format (only for DNSSEC KSK keys)\n");
  fprintf(fp, "  The base name (K<name>+<alg>+<id> will be printed to stdout\n");
}

int main(int argc, char* argv[])
{
  const char* zonefile_name;
  FILE* zonefile = NULL;

  int c;
  int filter = 0;
  double false_positive = 0;
  while ((c = getopt(argc, argv, "f:p:uv")) != -1) {
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

  // count the number of rrsigs
  // struct bloom rrsig_bloom;
  // int rrsig_count = 0;
  // double error_rate = 0.2;
  //
  // bloom_init2(&rrsig_bloom, rrsig_count, error_rate);

  exit(EXIT_SUCCESS);
}
