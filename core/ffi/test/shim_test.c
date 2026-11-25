/* Calls every function of osva_core.h through the shim and the Lean-compiled core, and checks the answers the
 * theorems and examples promise. Run by scripts/check-core.sh on Linux and macOS. */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
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
    CHECK(osva_vcmp(S("1.0"), S("1.0.0")) == 0 && osva_vcmp(S("1.0.0"), S("1.0")) == 0, "1.0 = 1.0.0");
    CHECK(osva_vcmp(S("15.0.0-canary.12"), S("15.0.0")) == -1 && osva_vcmp(S("15.0.0"), S("15.0.0-canary.12")) == 1,
          "15.0.0-canary.12 < 15.0.0");
    CHECK(osva_vcmp(S("2.4.6-p3"), S("2.4.6")) == 1 && osva_vcmp(S("2.4.6"), S("2.4.6-p3")) == -1, "2.4.6-p3 > 2.4.6");
    CHECK(osva_vcmp(S("1.0-SP1"), S("1.0")) == 1, "1.0-SP1 > 1.0");
    CHECK(osva_vcmp(S("5.3.0-RELEASE"), S("5.3.0")) == 0 && osva_vcmp(S("5.3.0"), S("5.3.0-RELEASE")) == 0,
          "5.3.0-RELEASE = 5.3.0");

    CHECK(osva_version_uncertain(S("33.7.2-jre")) == 1, "uncertain: 33.7.2-jre");
    CHECK(osva_version_uncertain(S("2.0.0-incubating")) == 1, "uncertain: 2.0.0-incubating");
    CHECK(osva_version_uncertain(S("1.0.0-rc.1")) == 1, "uncertain: 1.0.0-rc.1, a pre-release word on neither list");
    CHECK(osva_version_uncertain(S("2.4.6-p3")) == 0, "certain: 2.4.6-p3");
    CHECK(osva_version_uncertain(S("1.0-SP1")) == 0, "certain: 1.0-SP1");
    CHECK(osva_version_uncertain(S("5.3.0-RELEASE")) == 0, "certain: 5.3.0-RELEASE");
    CHECK(osva_version_uncertain(S("1.2.3")) == 0 && osva_version_uncertain(S("10.6p2")) == 0, "certain without a '-'");
    CHECK(osva_version_uncertain(S("7.1.1-41")) == 0, "certain: a number after a '-'");
    CHECK(osva_version_uncertain(S("1.0+build-jre")) == 0, "certain: build metadata ignored");
    CHECK(osva_version_uncertain((const uint8_t *)"", 0) == 0 && osva_version_uncertain(NULL, 0) == 0, "certain: empty");
    CHECK(osva_version_uncertain(NULL, 3) == -2, "uncertain refuses a NULL version with a length");

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

    /* advisories (Decide.lean's examples): ranges decide when there are any, else the first fixed versions, as "likely" */
    const uint8_t *f1620[] = { (const uint8_t *)"16.20" };
    size_t f1620l[] = { 5 };
    const uint8_t *f99[] = { (const uint8_t *)"99" };
    size_t f99l[] = { 2 };
    const osva_advisory nginx = { 0, NULL, 0, fx, fl, 2 };
    const osva_advisory pg_nginx[] = { { 1, pg, 5, NULL, NULL, 0 }, nginx };
    const osva_advisory pg_ff1620[] = { { 1, pg, 5, NULL, NULL, 0 }, { 0, NULL, 0, f1620, f1620l, 1 } };
    uint8_t vd[2] = { 9, 9 };
    CHECK(osva_verdicts(S("16.14"), pg_nginx, 2, vd) == 0 && vd[0] == 1 && vd[1] == 0, "verdicts: postgresql 16.14 inside a range, nginx clear");
    vd[0] = 9;
    CHECK(osva_verdicts(S("1.31.5"), &nginx, 1, vd) == 0 && vd[0] == 2, "verdicts: no ranges, nginx 1.31.5 likely");
    CHECK(osva_verdicts(S("1.32.0"), &nginx, 1, vd) == 0 && vd[0] == 0, "verdicts: no ranges, nginx 1.32.0 clear");
    const osva_advisory pg_99 = { 1, pg, 5, f99, f99l, 1 };
    vd[0] = 9;
    CHECK(osva_verdicts(S("16.16"), &pg_99, 1, vd) == 0 && vd[0] == 0, "verdicts: ranges decide, first fixed versions not consulted");
    const osva_advisory empty_ranges = { 1, NULL, 0, f1620, f1620l, 1 };
    vd[0] = 9;
    CHECK(osva_verdicts(S("1.0"), &empty_ranges, 1, vd) == 0 && vd[0] == 2, "verdicts: an empty list of ranges is no answer, the fixed versions decide");
    const osva_advisory states_nothing = { 1, NULL, 0, NULL, NULL, 0 };
    vd[0] = 9;
    CHECK(osva_verdicts(S("1.0"), &states_nothing, 1, vd) == 0 && vd[0] == 0, "verdicts: an empty list and no fixed versions is clear");
    const osva_advisory pg_256 = { 256, pg, 5, NULL, NULL, 0 };    /* any non-zero has_ranges, not only its low byte */
    vd[0] = 9;
    CHECK(osva_verdicts(S("16.14"), &pg_256, 1, vd) == 0 && vd[0] == 1, "verdicts: has_ranges 256 has ranges");
    CHECK(osva_upgrade_for(S("16.14"), pg_ff1620, 2, up, sizeof up) == 5 && memcmp(up, "16.20", 5) == 0, "upgrade for: 16.20 leaves both advisories");
    CHECK(osva_upgrade_for(S("16.14"), pg_ff1620, 2, up, 4) == -3, "upgrade for refuses a small buffer");
    const osva_advisory open_adv = { 1, open_end, 1, NULL, NULL, 0 };
    CHECK(osva_upgrade_for(S("2.0"), &open_adv, 1, up, sizeof up) == -1, "upgrade for: no end, no upgrade");
    uint8_t jd[2] = { 9, 9 };
    CHECK(osva_judge(S("16.14"), S("16.15"), pg_ff1620, 2, jd) == 1 && jd[0] == 1 && jd[1] == 0, "judge: 16.15 leaves postgresql's ranges, not 16.20's fix");
    jd[0] = jd[1] = 9;
    CHECK(osva_judge(S("16.14"), S("16.14"), pg_ff1620, 2, jd) == 0 && jd[0] == 9 && jd[1] == 9, "judge: not above, out untouched");
    const osva_range rc[] = { R(NULL, "2.7.1-rc1", NULL) };
    const osva_range all[] = { R(NULL, NULL, NULL) };
    const osva_advisory rc_all[] = { { 1, rc, 1, NULL, NULL, 0 }, { 1, all, 1, NULL, NULL, 0 } };
    CHECK(osva_judge(S("2.2.0"), S("2.13.0"), rc_all, 2, jd) == 1 && jd[0] == 1 && jd[1] == 0, "judge: 2.13.0 leaves a fixed range, not an open one");
    /* clear is no evidence: an advisory that states nothing is never fixed, and never lets an upgrade through */
    const osva_advisory pg_nothing[] = { { 1, pg, 5, NULL, NULL, 0 }, { 0, NULL, 0, NULL, NULL, 0 } };
    vd[0] = jd[0] = 9;
    CHECK(osva_verdicts(S("1.1"), &pg_nothing[1], 1, vd) == 0 && vd[0] == 0 &&
          osva_judge(S("1.0"), S("1.1"), &pg_nothing[1], 1, jd) == 1 && jd[0] == 0, "judge: clear of an advisory that states nothing is no fix");
    jd[0] = 9;
    CHECK(osva_judge(S("1.0"), S("1.1"), &states_nothing, 1, jd) == 1 && jd[0] == 0, "judge: nor of an empty list without fixed versions");
    CHECK(osva_upgrade_for(S("16.14"), pg_nothing, 2, up, sizeof up) == -1, "upgrade for: none past an advisory that states nothing");
    const osva_advisory pg_empty[] = { { 1, pg, 5, NULL, NULL, 0 }, states_nothing };
    CHECK(osva_upgrade_for(S("16.14"), pg_empty, 2, up, sizeof up) == -1, "upgrade for: nor past an empty list without fixed versions");
    jd[0] = 9;
    CHECK(osva_judge(S("1.0"), S("16.20"), &empty_ranges, 1, jd) == 1 && jd[0] == 1, "judge: an empty list, fixed versions as evidence");
    /* candidates are releases: a pre-release is never suggested, a release named beside it is */
    const uint8_t *f271[] = { (const uint8_t *)"2.7.1" };
    size_t f271l[] = { 5 };
    const osva_advisory rc_only = { 1, rc, 1, NULL, NULL, 0 }, rc_and_release = { 1, rc, 1, f271, f271l, 1 };
    CHECK(osva_upgrade_for(S("2.2.0"), &rc_only, 1, up, sizeof up) == -1, "upgrade for: never a pre-release");
    CHECK(osva_upgrade_for(S("2.2.0"), &rc_and_release, 1, up, sizeof up) == 5 && memcmp(up, "2.7.1", 5) == 0, "upgrade for: the release named beside it");
    CHECK(osva_verdicts(S("1.0"), NULL, 0, NULL) == 0, "verdicts: no advisories");
    CHECK(osva_upgrade_for(S("1.0"), NULL, 0, up, sizeof up) == -1, "upgrade for: no advisories, no upgrade");
    CHECK(osva_judge(S("1.0"), S("2.0"), NULL, 0, NULL) == 1, "judge: no advisories, above");

    /* the ranges are not read when has_ranges is 0: here a stale pointer and count into a page that cannot be read */
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    void *guard = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(guard != MAP_FAILED, "a page that cannot be read");
    if (guard != MAP_FAILED) {
        const osva_advisory stale = { 0, (const osva_range *)guard, 1, f1620, f1620l, 1 };
        vd[0] = jd[0] = 9;
        CHECK(osva_verdicts(S("16.14"), &stale, 1, vd) == 0 && vd[0] == 2 &&
              osva_upgrade_for(S("16.14"), &stale, 1, up, sizeof up) == 5 && memcmp(up, "16.20", 5) == 0 &&
              osva_judge(S("16.14"), S("16.20"), &stale, 1, jd) == 1 && jd[0] == 1, "ranges not read when has_ranges is 0");
        munmap(guard, page);
    }

    /* bad arguments: -2 from all three, nothing written */
    vd[0] = 9;
    CHECK(osva_verdicts(S("1.0"), NULL, 1, vd) == -2 && osva_upgrade_for(S("1.0"), NULL, 1, up, sizeof up) == -2 &&
          osva_judge(S("1.0"), S("2.0"), NULL, 1, vd) == -2 && vd[0] == 9, "advisories NULL refused");
    const osva_advisory no_ranges_ptr = { 1, NULL, 1, NULL, NULL, 0 };
    const osva_advisory no_fixed_ptr = { 0, NULL, 0, NULL, f1620l, 1 };
    const osva_advisory no_fixed_len = { 0, NULL, 0, f1620, NULL, 1 };
    const uint8_t *null_item[] = { NULL };
    const osva_advisory null_fixed_item = { 0, NULL, 0, null_item, f1620l, 1 };
    const osva_advisory too_many_ranges = { 1, pg, SIZE_MAX / 3 + 1, NULL, NULL, 0 };
    const osva_advisory unused_ranges = { 0, NULL, 1, NULL, NULL, 0 };    /* read or not, a NULL with a count is refused */
    const osva_advisory bad[] = { no_ranges_ptr, no_fixed_ptr, no_fixed_len, null_fixed_item, too_many_ranges, unused_ranges };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        const osva_advisory two_adv[] = { nginx, bad[i] };      /* the bad one second: every advisory is checked */
        char what[64];
        snprintf(what, sizeof what, "bad advisory %zu refused", i);
        vd[0] = vd[1] = 9;
        CHECK(osva_verdicts(S("1.0"), two_adv, 2, vd) == -2 && osva_upgrade_for(S("1.0"), two_adv, 2, up, sizeof up) == -2 &&
              osva_judge(S("1.0"), S("2.0"), two_adv, 2, vd) == -2 && vd[0] == 9 && vd[1] == 9, what);
    }
    CHECK(osva_verdicts(S("1.0"), &nginx, SIZE_MAX / 3 + 1, vd) == -2, "verdicts refuse n above SIZE_MAX / 3");
    CHECK(osva_verdicts(S("1.0"), &nginx, 1, NULL) == -2, "verdicts refuse a NULL out");
    CHECK(osva_upgrade_for(S("1.0"), &nginx, 1, NULL, 8) == -2, "upgrade for refuses a NULL buffer");
    CHECK(osva_judge(S("1.0"), S("2.0"), &nginx, 1, NULL) == -2, "judge refuses a NULL out");
    CHECK(osva_verdicts(NULL, 3, &nginx, 1, vd) == -2 && osva_upgrade_for(NULL, 3, &nginx, 1, up, sizeof up) == -2 &&
          osva_judge(S("1.0"), NULL, 3, &nginx, 1, vd) == -2, "a NULL version with a length refused");

    /* many calls with nested arguments: no leaks or crashes across repeated use */
    for (int i = 0; i < 20000; i++)
        if (osva_judge(S("16.14"), S("16.15"), pg_ff1620, 2, jd) != 1 || osva_upgrade_for(S("16.14"), pg_ff1620, 2, up, sizeof up) != 5) { fails++; break; }
    CHECK(1, "20000 advisory calls");

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
