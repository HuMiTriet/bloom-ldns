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
#include "bloom_filter/bloom.h"
#include "ldns/dnssec_sign.h"
#include "ldns/error.h"
#include "ldns/host2str.h"
#include "ldns/host2wire.h"
#include "ldns/keys.h"
#include "ldns/packet.h"
#include "ldns/rdata.h"
#include "ldns/rr.h"
#include "ldns/rr_functions.h"
#include "ldns/util.h"
#include "ldns/zone.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <errno.h>

#include "khashl.h"

KHASHL_MAP_INIT(KH_LOCAL, map32_t, map32, uint32_t, ldns_rr_list*, kh_hash_uint32, kh_eq_generic);

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
  {BLOOM_FILTER, "Bloom filter"},
  {GOLOMB_COMPRESSED_SET, "Golomb compressed set"},
  {BINARY_FUSE_FILTER, "Binary fuse filter"}};

static void show_algorithms(FILE* out)
{
  ldns_lookup_table* lt = filter_algorithms;
  fprintf(out, "Possible algorithms:\n");

  while (lt->name) {
    fprintf(out, "%s\n", lt->name);
    lt++;
  }
}

static void deep_free_map2rr_list(map32_t* map)
{
  if (!map)
    return;

  khint_t k;
  kh_foreach(map, k)
  {
    ldns_rr_list_deep_free(kh_val(map, k));
  }

  map32_destroy(map);
}

static void usage(FILE* fp, char* prog)
{
  fprintf(fp, "%s [-f <filter>] [-p <false positive rate>] [-c <current time in YYYY-MM-DD HH:MM:SS format>] [-b <seconds>] [-r] -o <output filename> <zonefile1> <zonefile2> [key [key]]\n",
          prog);
  fprintf(fp, "  generate a new filter rr type\n");
  fprintf(fp, "  -f - filter type (default to a bloom fitler) (-f list to show a list)\n");
  fprintf(fp, "  -p <double> - false positive rate (must be greater than 0)\n");
  fprintf(fp, "  -c current time (usually the start of the date of the second zone file)\n");

  fprintf(fp, "  output multiple files prefixed with _filter. One file for each expiration date in the zone\n");
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

int main(int argc, char* argv[])
{

  int c;
  ldns_filter_algorithms filter = BLOOM_FILTER;
  double false_positive = 0.2;
  bool rrsig_file = false;
  uint32_t current_time = 0;
  uint32_t exp_buffer_sec = 86400 * 2;
  char* domain_name = NULL;
  uint32_t ttl = 900;
  const char* output_fn = "filter.txt";
  ldns_key_list* key_list = NULL;
  uint32_t version = 0;

  while ((c = getopt(argc, argv, "f:c:b:p:rd:t:o:v:h")) != -1) {
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
    case 'r':
      rrsig_file = true;
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

    case 'v':
      version = atoi(optarg);
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

  for (int i = 2; i < argc; i++) {
    char* key_fn_base = argv[i];
    char* priv_key_fn = LDNS_XMALLOC(char, strlen(key_fn_base) + 9);
    snprintf(priv_key_fn,
             strlen(key_fn_base) + 9,
             "%s.private",
             key_fn_base);
    FILE* priv_key_fp = fopen(priv_key_fn, "r");
    int line_nr = 0;

    if (!priv_key_fp) {
      fprintf(stderr,
              "Error: unable to read %s: %s\n",
              priv_key_fn,
              strerror(errno));
      exit(EXIT_FAILURE);
    }

    ldns_key* priv_key;
    ldns_status s;
    s = ldns_key_new_frm_fp_l(&priv_key, priv_key_fp, &line_nr);
    fclose(priv_key_fp);

    if (s != LDNS_STATUS_OK) {
      fprintf(stderr, "Error reading key from %s at line %d: %s\n", priv_key_fn, line_nr, ldns_get_errorstr_by_id(s));
      exit(EXIT_FAILURE);
    }

    char* pub_key_fn = LDNS_XMALLOC(char, strlen(key_fn_base) + 5);
    snprintf(pub_key_fn, strlen(key_fn_base) + 5, "%s.key", key_fn_base);

    FILE* pub_key_fp = fopen(pub_key_fn, "r");

    if (!pub_key_fp) {
      fprintf(stderr,
              "Error: unable to read %s: %s\n",
              pub_key_fn,
              strerror(errno));
      ldns_key_deep_free(priv_key);
      exit(EXIT_FAILURE);
    }

    ldns_rr* pub_key;
    s = ldns_rr_new_frm_fp_l(&pub_key, pub_key_fp, NULL, NULL, NULL, &line_nr);
    fclose(pub_key_fp);

    if (s != LDNS_STATUS_OK) {
      fprintf(stderr, "Error reading key from %s at line %d: %s\n", pub_key_fn, line_nr, ldns_get_errorstr_by_id(s));
      exit(EXIT_FAILURE);
    }

    if (!key_list) {
      key_list = ldns_key_list_new();
    }

    ldns_key_set_pubkey_owner(priv_key, ldns_rdf_clone(ldns_rr_owner(pub_key)));
    ldns_key_set_flags(priv_key, ldns_rdf2native_int16(ldns_rr_rdf(pub_key, 0)));
    ldns_key_set_keytag(priv_key, ldns_calc_keytag(pub_key));

    ldns_key_list_push_key(key_list, priv_key);
    ldns_rr_free(pub_key);
  }

  char *fn1, *fn2;
  fn1 = argv[0];
  ldns_rr_list* sigs1 = ldns_rr_list_new();
  printf("Reading Zone 1: %s\n", fn1);
  if (load_rrsigs(fn1, &sigs1, rrsig_file)) {
    ldns_rr_list_deep_free(sigs1);
    exit(EXIT_FAILURE);
  }
  printf("Loaded %zu RRSIGs from %s\n", ldns_rr_list_rr_count(sigs1), fn1);

  fn2 = argv[1];
  ldns_rr_list* sigs2 = ldns_rr_list_new();
  printf("Reading Zone 2: %s\n", fn2);
  if (load_rrsigs(fn2, &sigs2, rrsig_file)) {
    ldns_rr_list_deep_free(sigs2);
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

      /* rr1 is smaller than rr2, so rr1 is not in zone file 2 (since lists are sorted) */
      uint32_t orig_ttl = ldns_rdf2native_int32(ldns_rr_rrsig_origttl(rr1));
      uint32_t rrsig_exp = ldns_rdf2native_int32(ldns_rr_rrsig_expiration(rr1));

      if ((current_time + orig_ttl) < rrsig_exp && ((current_time + exp_buffer_sec) < rrsig_exp)) {
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
        ldns_rr_list_push_rr(tmp_rrsigs, rr1);
      }
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

  int absent;
  map32_t* exp2rr_list = map32_init();
  khint_t k;
  for (size_t i = 0; i < ldns_rr_list_rr_count(affected_rrsigs); i++) {

    ldns_rr* rrsig = ldns_rr_list_rr(affected_rrsigs, i);
    uint32_t exp = ldns_rdf2native_int32(ldns_rr_rrsig_expiration(rrsig));
    uint32_t exp_day = exp / 86400; // Convert to days since epoch

    k = map32_put(exp2rr_list, exp_day, &absent);

    ldns_rr_list* rrsig_list;
    if (absent) { // key does not exist
      rrsig_list = kh_val(exp2rr_list, k) = ldns_rr_list_new();
    }
    else {
      rrsig_list = kh_val(exp2rr_list, k);
    }

    ldns_rr_list_push_rr(rrsig_list, rrsig);
  }

  printf("Opening file for writing: '%s'\n", output_fn);
  FILE* fp = fopen(output_fn, "a");
  if (!fp) {
    fprintf(stderr, "Unable to open %s: %s\n", output_fn, strerror(errno));

    deep_free_map2rr_list(exp2rr_list);
    return LDNS_STATUS_FILE_ERR;
  }

  kh_foreach(exp2rr_list, k)
  { // for each expiration date create a bloom filter
    ldns_rr_list* rrsig_list = kh_val(exp2rr_list, k);

    struct bloom bloom;
    size_t rrsig_num = ldns_rr_list_rr_count(rrsig_list);

    printf("Num rrsig: %zu \n", rrsig_num);

    if (bloom_init2(&bloom, rrsig_num, false_positive) != 0) {
      fprintf(stderr, "Error initializing bloom filter\n");
      exit(EXIT_FAILURE);
    }

    // Track the latest expiration time while adding to bloom filter
    uint32_t max_exp = 0;
    for (size_t i = 0; i < ldns_rr_list_rr_count(rrsig_list); i++) {
      ldns_rr* rr = ldns_rr_list_rr(rrsig_list, i);

      // Track max expiration
      uint32_t exp = ldns_rdf2native_int32(ldns_rr_rrsig_expiration(rr));
      if (exp > max_exp) {
        max_exp = exp;
      }

      // Add to bloom filter
      uint8_t* wire = NULL;
      size_t size = 0;
      if (ldns_rr2wire(&wire, rr, LDNS_SECTION_ANSWER, &size) == LDNS_STATUS_OK) {
        bloom_add(&bloom, wire, (int)size);
        LDNS_FREE(wire);
      }
    }

    time_t t_exp = (time_t)max_exp;
    struct tm tm_max;
    gmtime_r(&t_exp, &tm_max);

    if (domain_name == NULL) {
      fprintf(stderr, "Error: Domain name (-d) is required for TXT record generation\n");
      deep_free_map2rr_list(exp2rr_list);
      exit(EXIT_FAILURE);
    }

    // 1. Create TXT record owner name: _filter.YYYYMMDD.<domain_name>
    size_t domain_len = strlen(domain_name);
    // "_filter." (8) + YYYYMMDD (8) + "." (1) + domain + null (1) = 18 + domain_len
    size_t owner_len = 18 + domain_len;
    char* owner_name = malloc(owner_len);
    if (!owner_name) {
      perror("malloc");
      deep_free_map2rr_list(exp2rr_list);
      exit(EXIT_FAILURE);
    }

    snprintf(owner_name, owner_len, "_filter.%04d%02d%02d.%s",
             tm_max.tm_year + 1900, tm_max.tm_mon + 1, tm_max.tm_mday, domain_name);

    // 2. Prepare header: v=0;s=HHMMSS;a=0;d=
    char header_buf[64];
    int header_len = snprintf(header_buf, sizeof(header_buf), "v=%u;s=%02d%02d%02d;a=0;d=",
                              version, tm_max.tm_hour, tm_max.tm_min, tm_max.tm_sec);

    // 3. Combine header and bloom filter bytes into one buffer
    size_t full_len = header_len + sizeof(struct bloom) + bloom.bytes;
    uint8_t* full_data = malloc(full_len);
    if (!full_data) {
      perror("malloc");
      deep_free_map2rr_list(exp2rr_list);
      exit(EXIT_FAILURE);
    }
    memcpy(full_data, header_buf, header_len);
    memcpy(full_data + header_len, &bloom, sizeof(struct bloom));
    memcpy(full_data + header_len + sizeof(struct bloom), bloom.bf, bloom.bytes);

    // 4. Create the TXT RR
    ldns_rr* txt_rr = ldns_rr_new();
    ldns_rr_set_type(txt_rr, LDNS_RR_TYPE_TXT);
    ldns_rr_set_class(txt_rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_ttl(txt_rr, ttl);

    ldns_rdf* owner_rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, owner_name);
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

    if (key_list) {
      ldns_rr_list* rrset = ldns_rr_list_new();
      ldns_rr_list_push_rr(rrset, txt_rr);

      ldns_rr_list* siglist = ldns_sign_public(rrset, key_list);

      ldns_rr_list_print(fp, siglist);
      ldns_rr_list_deep_free(siglist);
      ldns_rr_list_free(rrset);
    }

    ldns_rr_free(txt_rr);
    free(full_data);
    free(owner_name);

    bloom_free(&bloom);
  }

  fclose(fp);

  if (key_list) {
    ldns_key_list_free(key_list);
  }

  ldns_rr_list_free(affected_rrsigs);

  deep_free_map2rr_list(exp2rr_list);
  exit(EXIT_SUCCESS);
}
