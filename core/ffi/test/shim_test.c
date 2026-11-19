/* Calls every function of osva_core.h through the shim and the Lean-compiled core, and checks the answers the
 * theorems and examples promise. Run by scripts/check-core.sh on Linux and macOS. */
#include <stdio.h>
#include <string.h>
#include "osva_core.h"

static int fails = 0;
#define S(x) (const uint8_t *)(x), strlen(x)
#define CHECK(cond, what) do { if (!(cond)) { printf("FAIL %s\n", what); fails++; } else printf("ok   %s\n", what); } while (0)

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
