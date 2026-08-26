#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <string.h>

#define SQL_DIFF(col, rrtype)                                       \
  "SELECT name, SUM(changed) AS changes, COUNT(*) AS polls\n"       \
  "FROM (\n"                                                        \
  "    SELECT name,\n"                                              \
  "           CASE\n"                                               \
  "               WHEN LAG(" col ") OVER w IS NULL THEN 0\n"        \
  "               WHEN " col " IS NOT LAG(" col ") OVER w THEN 1\n" \
  "               ELSE 0\n"                                         \
  "           END AS changed\n"                                     \
  "    FROM observations\n"                                         \
  "    WHERE error IS NULL AND qtype = " rrtype "\n"                \
  "    WINDOW w AS (PARTITION BY name ORDER BY round)\n"            \
  ")\n"                                                             \
  "GROUP BY name\n"                                                 \
  "ORDER BY changes DESC;\n"

static void usage(FILE* fp, char* prog)
{
  fprintf(fp, "%s -p 0.001 -d <domain name> -b <rrsig referesh> <file1> <file2>\n",
          prog);
  fprintf(fp, "  generate a new filter rr type\n");
  fprintf(fp, "  -p <double> - false positive rate (must be greater than 0)\n");

  fprintf(fp, "  output multiple files prefixed with _filter. One file for each expiration date in the zone\n");
}

int main(int argc, char* argv[])
{

  char* input = argv[1];

  struct sqlite3* conn;
  int status = sqlite3_open_v2(input, &conn, SQLITE_OPEN_READONLY, "");

  if (status != SQLITE_OK) {
    const char* err_msg = sqlite3_errmsg(conn);
    fprintf(stderr, "Cannot open sqlite3 file error code: %s", err_msg);
    exit(EXIT_FAILURE);
  }

  // zone changes

  struct sqlite3_stmt* stmt;
  int prep_stat = sqlite3_prepare_v2(conn, sql_diff, strlen(sql_diff), &stmt, NULL);

  return EXIT_SUCCESS;
}
