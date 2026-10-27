/*
 * ldns-compare-zones compares two zone files but count only what is relevant for RRR paper
 *
 * Written by Triet Huynh in 2026
 *
 * See the file LICENSE for the license
 */

#include "config.h"
#include "ldns/dname.h"
#include "ldns/rr.h"
#include "ldns/util.h"
#include "ldns/zone.h"
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <inttypes.h>

#include <ldns/ldns.h>

#include <errno.h>

#define OP_INS '+'
#define OP_DEL '-'
#define OP_CHG '~'
#define OP_EQ '='

static void
usage(char* prog)
{
  printf("Usage: %s [-s] [-h] [-v]"
         "<zonefile1> <zonefile2>\n",
         prog);

  printf("       -s - do not sort zones\n");
  printf("       -h - show usage and exit\n");
  printf("       -v - show the version and exit\n");
}

static bool same_owner(const ldns_rr* a, const ldns_rr* b)
{
  return ldns_rr_get_class(a) == ldns_rr_get_class(b) && ldns_dname_compare(ldns_rr_owner(a), ldns_rr_owner(b)) == 0;
}

struct rrset_rrsig
{
  ldns_rr_list* rrset;
  ldns_rr_list* rrsigs;
};
typedef struct rrset_rrsig rrset_rrsig;

/* type an RR is grouped under: the covered type for an RRSIG, its own type otherwise */
static ldns_rr_type rrset_type(const ldns_rr* rr)
{
  if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG) {
    return ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(rr));
  }
  return ldns_rr_get_type(rr);
}

/* order by owner, class, then covered type; used for the sort and the zone merge */
static int rrset_key_compare(const ldns_rr* a, const ldns_rr* b)
{
  int r = ldns_dname_compare(ldns_rr_owner(a), ldns_rr_owner(b));
  if (r != 0) {
    return r;
  }
  if (ldns_rr_get_class(a) != ldns_rr_get_class(b)) {
    return ldns_rr_get_class(a) < ldns_rr_get_class(b) ? -1 : 1;
  }
  if (rrset_type(a) != rrset_type(b)) {
    return rrset_type(a) < rrset_type(b) ? -1 : 1;
  }
  return 0;
}

/* qsort comparator: RRset first, then its RRSIGs, each in canonical rdata order */
static int rr_sort_compare(const void* a, const void* b)
{
  const ldns_rr* x = *(ldns_rr* const*)a;
  const ldns_rr* y = *(ldns_rr* const*)b;
  int r = rrset_key_compare(x, y);

  if (r != 0) {
    return r;
  }

  int x_sig = ldns_rr_get_type(x) == LDNS_RR_TYPE_RRSIG;
  int y_sig = ldns_rr_get_type(y) == LDNS_RR_TYPE_RRSIG;
  if (x_sig != y_sig) {
    return x_sig - y_sig;
  }
  return ldns_rr_compare(x, y);
}

/* sort so each RRset is directly followed by the RRSIGs covering it */
static void sort_zone_rrset_rrsig(ldns_rr_list* rrl)
{
  size_t n = ldns_rr_list_rr_count(rrl), k;
  ldns_rr** rrs;

  if (n == 0) {
    return;
  }
  rrs = LDNS_XMALLOC(ldns_rr*, n);
  if (!rrs) {
    fprintf(stderr, "Out of memory\n");
    exit(EXIT_FAILURE);
  }
  for (k = 0; k < n; k++) {
    rrs[k] = ldns_rr_list_rr(rrl, k);
  }
  qsort(rrs, n, sizeof(*rrs), rr_sort_compare);
  for (k = 0; k < n; k++) {
    ldns_rr_list_set_rr(rrl, rrs[k], k); /* only swaps pointers, frees nothing */
  }
  LDNS_FREE(rrs);
}

/* RRset at zone_rrs[*cur_idx] and the RRSIGs covering it; *cur_idx ends just past both.
 * Needs the sort_zone_rrs() order. Lists are shallow: free with ldns_rr_list_free. */
static rrset_rrsig get_rrset(const ldns_rr_list* zone_rrs, size_t* cur_idx)
{
  ldns_rr* first_rr = ldns_rr_list_rr(zone_rrs, *cur_idx);
  rrset_rrsig res;

  res.rrset = ldns_rr_list_new();
  res.rrsigs = ldns_rr_list_new();

  for (; *cur_idx < ldns_rr_list_rr_count(zone_rrs); (*cur_idx)++) {
    ldns_rr* rr = ldns_rr_list_rr(zone_rrs, *cur_idx);

    if (!same_owner(first_rr, rr) || rrset_type(rr) != rrset_type(first_rr)) {
      break;
    }
    if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG) {
      ldns_rr_list_push_rr(res.rrsigs, rr);
    }
    else {
      ldns_rr_list_push_rr(res.rrset, rr);
    }
  }
  return res;
}

int main(int argc, char** argv)
{
  char *fn1, *fn2;
  FILE *fp1, *fp2;
  ldns_zone *z1, *z2;
  ldns_status s;
  size_t i, j;
  ldns_rr_list *rrl1, *rrl2;
  int line_nr1 = 0, line_nr2 = 0;
  size_t rrc1, rrc2;
  size_t num_rrsigs_del = 0, num_rrsigs_chg = 0, num_rrset_del = 0, num_rrset_chg = 0;
  int c;
  bool sort = true;

  while ((c = getopt(argc, argv, "ahvdicuUesZz")) != -1) {
    switch (c) {
    case 'h':
      usage(argv[0]);
      exit(EXIT_SUCCESS);
      break;
    case 'v':
      printf("%s version %s (ldns version %s)\n",
             argv[0],
             LDNS_VERSION,
             ldns_version());
      exit(EXIT_SUCCESS);
      break;
    case 's':
      sort = false;
      break;
    }
  }

  argc -= optind;
  argv += optind;

  if (argc != 2) {
    argv -= optind;
    usage(argv[0]);
    exit(EXIT_FAILURE);
  }
  fn1 = argv[0];
  fp1 = fopen(fn1, "r");
  if (!fp1) {
    fprintf(stderr, "Unable to open %s: %s\n", fn1, strerror(errno));
    exit(EXIT_FAILURE);
  }
  /* Read first zone */
  s = ldns_zone_new_frm_fp_l(&z1, fp1, NULL, 0,
                             LDNS_RR_CLASS_IN, &line_nr1);
  if (s != LDNS_STATUS_OK) {
    fclose(fp1);
    fprintf(stderr, "%s: %s at line %d\n",
            fn1,
            ldns_get_errorstr_by_id(s),
            line_nr1);
    exit(EXIT_FAILURE);
  }
  fclose(fp1);

  fn2 = argv[1];
  fp2 = fopen(fn2, "r");
  if (!fp2) {
    fprintf(stderr, "Unable to open %s: %s\n", fn2, strerror(errno));
    exit(EXIT_FAILURE);
  }
  /* Read second zone */
  s = ldns_zone_new_frm_fp_l(&z2, fp2, NULL, 0,
                             LDNS_RR_CLASS_IN, &line_nr2);
  if (s != LDNS_STATUS_OK) {
    ldns_zone_deep_free(z1);
    fclose(fp2);
    fprintf(stderr, "%s: %s at line %d\n",
            fn2,
            ldns_get_errorstr_by_id(s),
            line_nr2);
    exit(EXIT_FAILURE);
  }
  fclose(fp2);

  rrl1 = ldns_zone_rrs(z1);
  rrc1 = ldns_rr_list_rr_count(rrl1);

  rrl2 = ldns_zone_rrs(z2);
  rrc2 = ldns_rr_list_rr_count(rrl2);

  if (sort) {
    /* canonicalize zone 1 */
    ldns_rr2canonical(ldns_zone_soa(z1));
    for (i = 0; i < ldns_rr_list_rr_count(ldns_zone_rrs(z1)); i++) {
      ldns_rr2canonical(ldns_rr_list_rr(ldns_zone_rrs(z1), i));
    }
    /* sort zone 1 */
    sort_zone_rrset_rrsig(rrl1);
    /* canonicalize zone 2 */
    ldns_rr2canonical(ldns_zone_soa(z2));
    for (i = 0; i < ldns_rr_list_rr_count(ldns_zone_rrs(z2)); i++) {
      ldns_rr2canonical(ldns_rr_list_rr(ldns_zone_rrs(z2), i));
    }
    /* sort zone 2 */
    sort_zone_rrset_rrsig(rrl2);
  }

  ldns_rr_list_print(stdout, rrl1);

  // find the diff of the SOA serial number

  ldns_rr* z1_soa = ldns_zone_soa(z1);
  ldns_rr* z2_soa = ldns_zone_soa(z2);

  if (ldns_rr_compare(z1_soa, z2_soa) == 0) {
    printf("0,0,0,0,0\n");
    exit(EXIT_SUCCESS);
  }

  uint32_t z1_soa_serial = ldns_rdf2native_int32(ldns_rr_rdf(z1_soa, 2));
  uint32_t z2_soa_serial = ldns_rdf2native_int32(ldns_rr_rdf(z2_soa, 2));

  if (z1_soa_serial > z2_soa_serial) {
    fprintf(stderr, "The second zone file has larger serial number that the first. The second zone file should be the day after the first zone file capture day.");
    exit(EXIT_FAILURE);
  }

  for (i = 0, j = 0; i < rrc1 || j < rrc2;) {
    rrset_rrsig z1_rrs = {NULL, NULL}, z2_rrs = {NULL, NULL};
    int cmp;

    if (i >= rrc1) {
      cmp = 1;
    }
    else if (j >= rrc2) {
      cmp = -1;
    }
    else {
      cmp = rrset_key_compare(ldns_rr_list_rr(rrl1, i), ldns_rr_list_rr(rrl2, j));
    }

    if (cmp <= 0) {
      z1_rrs = get_rrset(rrl1, &i);
    }
    if (cmp >= 0) {
      z2_rrs = get_rrset(rrl2, &j);
    }

    if (cmp < 0) {
      /* RRset only in zone 1: removed */
      if (z1_rrs.rrsigs != NULL) { // if RRset is unsigned
        num_rrsigs_del += ldns_rr_list_rr_count(z1_rrs.rrsigs);
      }
      num_rrset_del++;
    }
    else if (cmp > 0) {
      /* RRset only in zone 2: added */
      // we don't care about add in RRR
    }
    else {
      if (z1_rrs.rrsigs != NULL) {
        size_t i1_rrsig;
        for (i1_rrsig = 0; i < ldns_rr_list_rr_count(z1_rrs.rrsigs); i++) {

          if (i1_rrsig > ldns_rr_list_rr_count(z2_rrs.rrsigs)) {
            num_rrsigs_del += ldns_rr_list_rr_count(z1_rrs.rrsigs) - ldns_rr_list_rr_count(z2_rrs.rrsigs);
            break;
          }
          if (ldns_rr_compare(ldns_rr_list_rr(z1_rrs.rrsigs, i1_rrsig), ldns_rr_list_rr(z2_rrs.rrsigs, i1_rrsig)) != 0) {
            num_rrsigs_chg++;
          }
        }
      }

      if (ldns_rr_list_compare(z1_rrs.rrset, z2_rrs.rrset) != 0) {
        num_rrset_chg++;
      }
    }

    ldns_rr_list_free(z1_rrs.rrset);
    ldns_rr_list_free(z1_rrs.rrsigs);
    ldns_rr_list_free(z2_rrs.rrset);
    ldns_rr_list_free(z2_rrs.rrsigs);
  }

  uint32_t serial_diff = z2_soa_serial - z1_soa_serial;
  printf("%u,%u,%u,%u,%u\n",
         (unsigned int)serial_diff,
         (unsigned int)num_rrsigs_del,
         (unsigned int)num_rrset_del,
         (unsigned int)num_rrset_del,
         (unsigned int)num_rrset_chg);
}
