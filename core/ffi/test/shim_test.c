/* Calls every function of osva_core.h through the shim and the Lean-compiled core, and checks the answers the
 * theorems and examples promise. Run by scripts/check-core.sh on Linux and macOS. */
#include <stdio.h>
#include <string.h>
#include "osva_core.h"

static int fails = 0;
#define S(x) (const uint8_t *)(x), strlen(x)
#define CHECK(cond, what) do { if (!(cond)) { printf("FAIL %s\n", what); fails++; } else printf("ok   %s\n", what); } while (0)

/* strlen, or 0 for an absent bound. A function rather than `(x) ? strlen(x) : 0` in the macro: GCC's -Wnonnull
   flags strlen(NULL) in the untaken branch when the macro is given a literal NULL. */
static size_t len_or_0(const char *s) { return s ? strlen(s) : 0; }

int main(void) {
    CHECK(osva_core_init() == 0, "init");
    CHECK(osva_core_init() == 0, "init twice");
    CHECK(osva_vcmp(S("1.0rc1"), S("1.0")) == -1, "1.0rc1 < 1.0");
    CHECK(osva_vcmp(S("1.0.1"), S("1.0.post1")) == 1, "1.0.1 > 1.0.post1");
    CHECK(osva_vcmp(S("v1.2.3"), S("1.2.3")) == 0, "v1.2.3 = 1.2.3");
    CHECK(osva_vcmp(S("10.6p2"), S("10.6")) == 1, "10.6p2 > 10.6");
    CHECK(osva_vcmp((const uint8_t *)"", 0, (const uint8_t *)"", 0) == 0, "empty = empty");

    const uint8_t *fx[] = { (const uint8_t *)"1.30.7", (const uint8_t *)"1.31.9" };
    size_t fl[] = { 6, 6 };
    CHECK(osva_affected(S("1.31.5"), fx, fl, 2) == 1, "nginx 1.31.5 affected");
    CHECK(osva_affected(S("1.30.8"), fx, fl, 2) == 0, "nginx 1.30.8 not affected");
    CHECK(osva_affected(S("1.29.0"), fx, fl, 2) == 1, "nginx 1.29.0 affected");
    CHECK(osva_affected(S("1.32.0"), fx, fl, 2) == 0, "nginx 1.32.0 not affected");
    CHECK(osva_affected(S("1.0"), NULL, NULL, 0) == -1, "no fixes: unknown");

    /* affected ranges: PostgreSQL's CVE-2026-14662 (one range per branch) and CPython's CVE-2026-119170 (only 3.14.10) */
#define R(i, f, l) { (const uint8_t *)(i), len_or_0(i), (const uint8_t *)(f), len_or_0(f), (const uint8_t *)(l), len_or_0(l) }
    const osva_range pg[] = { R(NULL, "14.24", NULL), R("15", "15.19", NULL), R("16", "16.15", NULL), R("17", "17.11", NULL), R("18", "18.6", NULL) };
    const osva_range py[] = { R("3.14.10", "3.14.11", NULL) };
    uint8_t up[32];
    CHECK(osva_affected_ranges(S("16.16"), pg, 5) == 0, "postgresql 16.16 not affected (outside every branch's range)");
    CHECK(osva_affected_ranges(S("16.14"), pg, 5) == 1, "postgresql 16.14 affected");
    CHECK(osva_upgrade_ranges(S("16.14"), pg, 5, up, sizeof up) == 5 && memcmp(up, "16.15", 5) == 0, "postgresql 16.14: upgrade to 16.15, its own branch's fix");
    CHECK(osva_affected_ranges(S("13.9"), pg, 5) == 1, "postgresql 13.9 affected (range from the first version)");
    CHECK(osva_affected_ranges(S("14.24"), pg, 5) == 0, "postgresql 14.24 not affected (fixed is excluded)");
    CHECK(osva_affected_ranges(S("3.11.18"), py, 1) == 0, "cpython 3.11.18 not affected");
    CHECK(osva_affected_ranges(S("3.14.10"), py, 1) == 1, "cpython 3.14.10 affected");
    CHECK(osva_upgrade_ranges(S("3.11.18"), py, 1, up, sizeof up) == 7 && memcmp(up, "3.14.11", 7) == 0, "upgrade is computed even when not flagged");
    CHECK(osva_affected_ranges(S("1.0"), NULL, 0) == -1, "no ranges: unknown");
    CHECK(osva_affected_ranges(S("1.0"), NULL, 1) == -2, "NULL ranges refused");
    CHECK(osva_upgrade_ranges(S("1.0"), NULL, 0, up, sizeof up) == -1, "no ranges: no upgrade");
    const osva_range open_end[] = { R("1.5", NULL, NULL) };
    CHECK(osva_affected_ranges(S("9.0"), open_end, 1) == 1 && osva_upgrade_ranges(S("9.0"), open_end, 1, up, sizeof up) == -1, "no end: affected, no upgrade");
    const osva_range last[] = { R("2.11.0", NULL, "2.13.0") };
    CHECK(osva_affected_ranges(S("2.13.0"), last, 1) == 1 && osva_affected_ranges(S("2.13.1"), last, 1) == 0, "last_affected is included, the next is not");
    const osva_range empty_bound[] = { R("", "1.0", NULL) };       /* present but empty: a bound, not "absent" */
    CHECK(osva_affected_ranges(S("dev"), empty_bound, 1) == 0, "an empty introduced is a bound");
    const osva_range two[] = { R("16", "16.15", NULL), R("16.14", "16.20", NULL) };
    CHECK(osva_upgrade_ranges(S("16.10"), two, 2, up, sizeof up) == 5 && memcmp(up, "16.20", 5) == 0, "an upgrade inside another range is skipped");
    CHECK(osva_upgrade_ranges(S("16.10"), two, 2, up, 4) == -3, "upgrade refuses a small buffer");
    CHECK(osva_upgrade_ranges(S("16.10"), two, 2, NULL, 8) == -2, "upgrade refuses a NULL buffer");

    const uint8_t *ix[] = { (const uint8_t *)"npm\x1f" "axios", (const uint8_t *)"PyPI\x1f" "requests" };
    size_t il[] = { 9, 13 };
    const uint8_t *inv[] = { (const uint8_t *)"npm\x1f" "axios", (const uint8_t *)"npm\x1f" "my-private-thing", (const uint8_t *)"PyPI\x1f" "requests" };
    size_t invl[] = { 9, 20, 13 };
    uint8_t mask[3] = { 9, 9, 9 };
    CHECK(osva_select(ix, il, 2, inv, invl, 3, mask) == 0 && mask[0] == 1 && mask[1] == 0 && mask[2] == 1, "privacy filter");
    CHECK(osva_select(ix, il, 2, inv, invl, 0, NULL) == 0, "empty inventory");

    uint8_t out[64];
    long n = osva_pct_encode(S("@scope/name"), out, sizeof out);
    CHECK(n == 15 && memcmp(out, "%40scope%2Fname", 15) == 0, "encode @scope/name");
    CHECK(osva_pct_encode(S("abc"), out, 8) == -1, "encode refuses a small buffer");

    /* many calls: no leaks or crashes across repeated use */
    for (int i = 0; i < 100000; i++) if (osva_vcmp(S("1.2.3"), S("1.2.4")) != -1) { fails++; break; }
    CHECK(1, "100000 calls");
    printf(fails ? "%d FAILED\n" : "all shim checks passed\n", fails);
    return fails ? 1 : 0;
}
