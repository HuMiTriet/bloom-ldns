#include "config.h"

#include <bits/getopt_core.h>
#include <ctype.h>
#include <ldns/ldns.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "bloom_filter/bloom.h"
#include "ldns/buffer.h"
#include "ldns/error.h"
#include "ldns/host2str.h"
#include "ldns/host2wire.h"
#include "ldns/packet.h"
#include "ldns/rdata.h"
#include "ldns/rr.h"
#include "ldns/util.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <errno.h>

#include "khashl.h"

/* * Extracts multiple whitespace-delimited columns from a string in a single pass.
 * target_cols: array of 0-indexed column numbers to find.
 * num_targets: how many columns you are looking for.
 * col_starts: array to store the pointers to the start of each found column.
 * col_lens: array to store the lengths of each found column.
 * Returns the number of columns successfully found.
 */
static inline int get_multiple_columns(
  const char* line,
  const int* target_cols,
  int num_targets,
  const char** col_starts,
  int* col_lens)
{
  if (!line || !target_cols || !col_starts || !col_lens || num_targets <= 0)
    return 0;

  const char* c = line;
  int current_col = 0;
  int found_count = 0;

  // Initialize outputs to safe defaults (in case a column doesn't exist on this line)
  for (int i = 0; i < num_targets; i++) {
    col_starts[i] = NULL;
    col_lens[i] = 0;
  }

  // Skip any leading whitespace at the very beginning of the line
  while (*c == ' ' || *c == '\t')
    c++;

  // Walk through the string exactly once
  while (*c != '\0' && found_count < num_targets) {

    const char* current_start = c;

    // Fast-forward to find the end of the current column
    while (*c != '\0' && *c != ' ' && *c != '\t')
      c++;

    int current_len = (int)(c - current_start);

    // Check if the column we just walked over is one of the targets we want
    for (int i = 0; i < num_targets; i++) {
      if (target_cols[i] == current_col) {
        col_starts[i] = current_start;
        col_lens[i] = current_len;
        found_count++;
      }
    }

    // Skip the whitespace gap to the next column
    while (*c == ' ' || *c == '\t')
      c++;

    current_col++;
  }

  return found_count;
}

static inline time_t parse_dnssec_time(const char* time_str, int len)
{
  if (len != 14)
    return (time_t)-1; // DNSSEC times are strictly 14 chars

  // 1. Copy the 14 chars to a null-terminated stack buffer
  char buf[15];
  memcpy(buf, time_str, 14);
  buf[14] = '\0';

  // 2. Parse the string into a broken-down calendar struct
  struct tm tm_time = {0};
  if (strptime(buf, "%Y%m%d%H%M%S", &tm_time) == NULL) {
    return (time_t)-1; // Failed to parse
  }

  // 3. Convert the UTC calendar struct to an integer timestamp
  return timegm(&tm_time);
}

static inline uint32_t parse_dns_ttl(const char* str, int len)
{
  uint32_t ttl = 0;

  for (int i = 0; i < len; i++) {
    // Ensure the character is actually a digit between 0 and 9
    if (str[i] >= '0' && str[i] <= '9') {
      // Shift the current number left by one decimal place,
      // then add the integer value of the new character.
      ttl = (ttl * 10) + (str[i] - '0');
    }
    else {
      // If we hit a weird character (like an unexpected space), stop parsing
      break;
    }
  }

  return ttl;
}

KHASHL_SET_INIT(KH_LOCAL, str_set_t, str_set, kh_cstr_t, kh_hash_str, kh_eq_str);

typedef struct
{
  char* data;
  size_t size;
  int fd;
} mapped_file_t;

mapped_file_t map_file_private(const char* filepath)
{

  mapped_file_t mf = {NULL, 0, -1};

  mf.fd = open(filepath, O_RDONLY);
  if (mf.fd < 0) {
    perror("Error opening file");
    return mf;
  }

  struct stat st;
  if (fstat(mf.fd, &st) < 0) {
    perror("Error getting file size");
    close(mf.fd);
    mf.fd = -1;
    return mf;
  }
  mf.size = st.st_size;

  if (mf.size == 0) {
    return mf; // Valid, but empty file
  }

  // PROT_WRITE + MAP_PRIVATE is the magic combination here.
  // It allows us to mutate the memory (change \n to \0) without altering the file on disk.
  mf.data = mmap(NULL, mf.size, PROT_READ | PROT_WRITE, MAP_PRIVATE, mf.fd, 0);
  if (mf.data == MAP_FAILED) {
    perror("Error mapping file");
    close(mf.fd);
    mf.fd = -1;
    mf.data = NULL;
  }

  return mf;
}

void unmap_file(mapped_file_t* mf)
{
  if (mf->data && mf->size > 0)
    munmap(mf->data, mf->size);
  if (mf->fd >= 0)
    close(mf->fd);
}
char* prog;
int verbosity = 2;

// #define DEBUG

typedef enum ldns_enum_filter_algorithm
{
  BLOOM_FILTER,
  GOLOMB_COMPRESSED_SET,
  BINARY_FUSE_FILTER,
} ldns_filter_algorithms;

ldns_lookup_table filter_algorithms[] = {
  {BLOOM_FILTER, "bloom"},
  {GOLOMB_COMPRESSED_SET, "gcs"},
  {BINARY_FUSE_FILTER, "fuse"},
  {0, NULL}};

static void show_algorithms(FILE* out)
{
  ldns_lookup_table* lt = filter_algorithms;
  fprintf(out, "Possible algorithms:\n");

  while (lt->name) {
    fprintf(out, "%s\n", lt->name);
    lt++;
  }
}

static void usage(FILE* fp, char* prog)
{
  fprintf(fp, "%s [-f <filter>] [-p <false positive rate>] [-c <current time in YYYY-MM-DD HH:MM:SS format>] [-b <seconds>] [-r] -o <output filename> <zonefile1> <zonefile2>\n",
          prog);
  fprintf(fp, "  generate a new filter rr type\n");
  fprintf(fp, "  -f - filter type (default to a bloom fitler) (-f list to show a list)\n");
  fprintf(fp, "  -p <double> - false positive rate (must be greater than 0)\n");
  fprintf(fp, "  -c current time (usually the start of the date of the second zone file)\n");

  fprintf(fp, "  output multiple files prefixed with _filter. One file for each expiration date in the zone\n");
}

int main(int argc, char* argv[])
{

  int c;
  ldns_filter_algorithms filter = BLOOM_FILTER;
  double false_positive = 0.2;
  uint32_t current_time = 0;
  uint32_t exp_buffer_sec = 86400 * 2;
  char* domain_name = NULL;
  uint32_t ttl = 900;
  prog = argv[0];

  const char* output_fn = "filter.txt";

  while ((c = getopt(argc, argv, "f:c:b:p:rd:t:o:h")) != -1) {
    switch (c) {
    case 'f':
      if (strncmp(optarg, "list", 5) == 0) {
        show_algorithms(stdout);
        exit(EXIT_SUCCESS);
      }
      {
        ldns_lookup_table* lt = ldns_lookup_by_name(filter_algorithms, optarg);
        if (lt) {
          filter = (ldns_filter_algorithms)lt->id;
        }
        else {
          fprintf(stderr, "Unknown filter algorithm: %s\n", optarg);
          show_algorithms(stderr);
          exit(EXIT_FAILURE);
        }
      }
      break;
    case 'c': {
      struct tm tm;
      memset(&tm, 0, sizeof(struct tm));
      if (strptime(optarg, "%Y-%m-%d %H:%M:%S", &tm) == NULL) {
        fprintf(stderr, "Invalid time format for -c. Use 'YYYY-MM-DD HH:MM:SS'\n");
        exit(EXIT_FAILURE);
      }
      time_t t = mktime(&tm);
      if (t == -1) {
        fprintf(stderr, "Failed to convert time for -c\n");
        exit(EXIT_FAILURE);
      }
      current_time = (uint32_t)t;
      break;
    }
    case 'b':
      exp_buffer_sec = atoi(optarg);
      break;
    case 'p':
      false_positive = atof(optarg);
      break;

    case 'd':
      domain_name = optarg;
      while (isspace(*domain_name)) {
        domain_name++;
      }
      break;
    case 'o':
      output_fn = optarg;
      break;

    case 'h':
      usage(stdout, prog);
      exit(EXIT_SUCCESS);
      break;

    case 't':
      ttl = atoi(optarg);
      break;

    default:
      exit(EXIT_FAILURE);
      break;
    }
  }

  if (current_time == 0) {
    current_time = (uint32_t)time(NULL);
  }

  argc -= optind;
  argv += optind;

  if (argc < 2) {
    argv -= optind;
    usage(stderr, argv[0]);
    exit(EXIT_FAILURE);
  }

  char *fn1, *fn2;
  fn1 = argv[0];
  fn2 = argv[1];

  mapped_file_t file2 = map_file_private(fn2);
  if (!file2.data && file2.size > 0)
    exit(EXIT_FAILURE);

  str_set_t* set_z2 = str_set_init();
  if (file2.size > 0) {
    char* start = file2.data;
    char* end = file2.data + file2.size;
    int absent;

    for (char* p = file2.data; p < end; p++) {
      if (*p == '\n') {
        *p = '\0'; // Mutate newline to null-terminator
        // kh_str_t_put(h, start, &absent); // Insert pointer directly into set
        str_set_put(set_z2, start, &absent);
        start = p + 1;
      }
    }
  }

  mapped_file_t file1 = map_file_private(fn1);
  if (!file1.data && file1.size > 0) {
    unmap_file(&file2);
    str_set_destroy(set_z2);
    exit(EXIT_FAILURE);
  }

  ldns_rr_list* affected_rrsigs = ldns_rr_list_new();
  if (file1.size > 0) {
    char* start = file1.data;
    char* end = file1.data + file1.size;

    for (char* p = file1.data; p < end; p++) {
      if (*p == '\n') {
        *p = '\0'; // Mutate newline to null-terminator

        // Query the set
        khint_t k_pos = str_set_get(set_z2, start);

        if (k_pos == kh_end(set_z2)) {
          const char* col_starts[2];
          int col_lens[2];

          int targets[] = {7, 8};
          int found = get_multiple_columns(start, targets, 2, col_starts, col_lens);

          if (found < 2) {
            str_set_destroy(set_z2);
            ldns_rr_list_deep_free(affected_rrsigs);
            unmap_file(&file1);
            unmap_file(&file2);
            fprintf(stderr, "Error while trying to get oritinal ttl and exp time for line of: \n%s\n", start);
            exit(EXIT_FAILURE);
          }
          const char* s_orig_ttl = col_starts[0];
          int s_orig_ttl_len = col_lens[0];
          uint32_t orig_ttl = parse_dns_ttl(s_orig_ttl, s_orig_ttl_len);

          const char* exp = col_starts[1];
          int exp_len = col_lens[1];
          time_t exp_t = parse_dnssec_time(exp, exp_len);

          if ((current_time + orig_ttl) < exp_t && current_time < exp_t - exp_buffer_sec) {
            ldns_rr* rrsig;
            ldns_status status = ldns_rr_new_frm_str(&rrsig, start, 0, NULL, NULL);

            if (status != LDNS_STATUS_OK) {
              str_set_destroy(set_z2);
              ldns_rr_list_deep_free(affected_rrsigs);
              unmap_file(&file1);
              unmap_file(&file2);
              fprintf(stderr, "Error while trying to get oritinal ttl and exp time for line of: \n%s\n", start);
              exit(EXIT_FAILURE);
            }

            ldns_rr_list_push_rr(affected_rrsigs, rrsig);
          }
        }
        start = p + 1;
      }
    }
  }

  str_set_destroy(set_z2);

  printf("Opening file for writing: '%s'\n", output_fn);
  FILE* fp = fopen(output_fn, "a");
  if (!fp) {
    fprintf(stderr, "Unable to open %s: %s\n", output_fn, strerror(errno));
    unmap_file(&file1);
    unmap_file(&file2);
    return EXIT_FAILURE;
  }

  // add each affected_rrsigs to the bloom filter
  struct bloom bloom;
  size_t rrsig_num = ldns_rr_list_rr_count(affected_rrsigs);

  printf("Num rrsig: %zu \n", rrsig_num);

  if (bloom_init2(&bloom, rrsig_num, false_positive) != 0) {
    fprintf(stderr, "Error initializing bloom filter\n");
    fclose(fp);
    unmap_file(&file1);
    unmap_file(&file2);
    exit(EXIT_FAILURE);
  }

  ldns_buffer* b = ldns_buffer_new(LDNS_MAX_PACKETLEN);
  for (size_t i = 0; i < ldns_rr_list_rr_count(affected_rrsigs); i++) {
    ldns_rr* rr = ldns_rr_list_rr(affected_rrsigs, i);
    ldns_buffer_clear(b);
    if (ldns_rr_rdata2buffer_wire(b, rr) == LDNS_STATUS_OK) {
      bloom_add(&bloom, ldns_buffer_begin(b), (int)ldns_buffer_position(b));
    }
  }
  ldns_buffer_free(b);

  if (domain_name == NULL) {
    fprintf(stderr, "Error: Domain name (-d) is required for TXT record generation\n");
    ldns_rr_list_deep_free(affected_rrsigs);
    bloom_free(&bloom);
    fclose(fp);
    unmap_file(&file1);
    unmap_file(&file2);
    exit(EXIT_FAILURE);
  }

  // 1. Create TXT record owner name: YYYYMMDD._filter,<signer name>
  size_t domain_len = strlen(domain_name);
  // "_filter." (8) + YYYYMMDD (8) + "." (1) + domain + null (1) = 18 + domain_len
  size_t owner_len = 18 + domain_len;
  char* owner_name = malloc(owner_len);
  if (!owner_name) {
    perror("malloc");
    ldns_rr_list_deep_free(affected_rrsigs);
    bloom_free(&bloom);
    fclose(fp);
    unmap_file(&file1);
    unmap_file(&file2);
    exit(EXIT_FAILURE);
  }

  // convert key to YYYYMMDD format
  time_t t_current = (time_t)current_time;
  struct tm tm_latest_epoch;
  gmtime_r(&t_current, &tm_latest_epoch);

  snprintf(owner_name, owner_len, "%04d%02d%02d._filter.%s",
           tm_latest_epoch.tm_year + 1900, tm_latest_epoch.tm_mon + 1, tm_latest_epoch.tm_mday, domain_name);

  // 2. Prepare header: r=86400 * 2;a=0;d=
  char* header_buf = NULL;
  int header_len = asprintf(&header_buf, "r=%u;a=0;d=", exp_buffer_sec);

  if (header_len < 0) {
    perror("asprintf");
    ldns_rr_list_deep_free(affected_rrsigs);
    bloom_free(&bloom);
    fclose(fp);
    unmap_file(&file1);
    unmap_file(&file2);
    free(owner_name);
    exit(EXIT_FAILURE);
  }

  // 3. Combine header and bloom filter bytes into one buffer
  size_t full_len = header_len + sizeof(struct bloom) + bloom.bytes;
  uint8_t* full_data = malloc(full_len);
  if (!full_data) {
    perror("malloc");
    free(header_buf);
    ldns_rr_list_deep_free(affected_rrsigs);
    bloom_free(&bloom);
    fclose(fp);
    unmap_file(&file1);
    unmap_file(&file2);
    free(owner_name);
    exit(EXIT_FAILURE);
  }
  memcpy(full_data, header_buf, header_len);
  free(header_buf);
  memcpy(full_data + header_len, &bloom, sizeof(struct bloom));
  memcpy(full_data + header_len + sizeof(struct bloom), bloom.bf, bloom.bytes);

  // 4. Create the TXT RR
  ldns_rr* txt_rr = ldns_rr_new();
  ldns_rr_set_type(txt_rr, LDNS_RR_TYPE_TXT);
  ldns_rr_set_class(txt_rr, LDNS_RR_CLASS_IN);
  ldns_rr_set_ttl(txt_rr, ttl);

  ldns_rdf* owner_rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, owner_name);
  if (!owner_rdf) {
    fprintf(stderr, "Error: Could not create owner name RDF for %s\n", owner_name);
    ldns_rr_free(txt_rr);
    free(full_data);
    free(owner_name);
    bloom_free(&bloom);
    fclose(fp);
    unmap_file(&file1);
    unmap_file(&file2);
    ldns_rr_list_deep_free(affected_rrsigs);
    exit(EXIT_FAILURE);
  }
  ldns_rr_set_owner(txt_rr, owner_rdf);

  // 5. Add data as 255-byte chunks
  size_t offset = 0;
  while (offset < full_len) {
    size_t chunk_size = (full_len - offset) > 255 ? 255 : (full_len - offset);

    // Prepend length byte for LDNS_RDF_TYPE_STR wire format
    uint8_t chunk_buf[256];
    chunk_buf[0] = (uint8_t)chunk_size;
    memcpy(chunk_buf + 1, full_data + offset, chunk_size);

    ldns_rdf* rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_STR, chunk_size + 1, chunk_buf);
    ldns_rr_push_rdf(txt_rr, rdf);
    offset += chunk_size;
  }

  ldns_rr_print(fp, txt_rr);
  if (ferror(fp)) {
    perror("Error writing to file");
  }
  else {
    printf("Successfully wrote to %s\n", owner_name);
  }

  ldns_rr_free(txt_rr);
  free(full_data);
  free(owner_name);

  bloom_free(&bloom);

  fclose(fp);

  unmap_file(&file1);
  unmap_file(&file2);

  ldns_rr_list_deep_free(affected_rrsigs);
  exit(EXIT_SUCCESS);
}
