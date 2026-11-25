/*
 * OSVA Monitor's verified core: the C interface the Swift app calls.
 *
 * These functions decide version order, what an advisory says about a version (by its ranges or, without them, by
 * its first fixed versions), the upgrade that leaves the advisories behind, which names may be sent, and how a name is
 * written into a URL, where the app asks them to (app/Sources/OSVAKit/Core.swift says where). The app flags a version
 * as affected, and names a version to upgrade to, only through them; its ClaimsTests fail on a path around them.
 * Each function is written in Lean 4 (the .lean files in core/OSVACore) together with theorems about it that Lean
 * checks for every input; Lean compiles those same definitions to C, which is linked into the app. A small shim
 * (core/ffi/osva_shim.c) converts between C bytes and Lean values; it is the only unproved code on this path.
 *
 * Strings are byte buffers with explicit lengths (not NUL-terminated). Call osva_core_init() once before anything
 * else, and call the functions from one thread at a time.
 */
#ifndef OSVA_CORE_H
#define OSVA_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Starts the Lean runtime. Returns 0 on success. Safe to call more than once. */
int osva_core_init(void);

/*
 * Version order, one ordering for the common forms (semver, PEP 440 releases and pre-releases, Go's "v1.2.3",
 * OpenSSH's "10.6p2"):
 *   - a leading 'v' or 'V' before a digit, and everything from the first '+' (build metadata), are ignored;
 *   - the rest is read as tokens: maximal runs of digits (numbers, leading zeros ignored, any length) and maximal
 *     runs of ASCII letters (words, case-insensitive); every other byte separates tokens;
 *   - a word right after a '-' is: the release itself if it is ga, final or release (Maven's "5.3.0-RELEASE" =
 *     "5.3.0"); after the release if it is p, patch, pl, sp, r, post or rev (Composer's "2.4.6-p3" > "2.4.6"); a
 *     pre-release word below if it is one; otherwise a pre-release below every known kind ("15.0.0-canary.12");
 *   - a zero right after a '-' that ends the version or is followed by a '.' is semver's lowest pre-release, below
 *     every other ("1.24.0-0" < "1.24.0-rc.2" < "1.24.0"; Go's "v1.2.4-0.20190101-abcdef" < "v1.2.4"); any other
 *     number after a '-' is still a number ("7.1.1-41" > "7.1.1");
 *   - the release numbers a version starts with lose the zeros that end them, keeping the first ("1.0" = "1.0.0");
 *   - tokens are compared in turn: word after a '-' < pre-release word < end of version < other word < number;
 *     numbers numerically; pre-release words by rank (dev < a = alpha < b = beta < c = rc = pre = preview); other
 *     words, and words after a '-', bytewise.
 * So "1.0rc1" < "1.0" < "1.0.post1" < "1.0.1", "15.0.0-canary.12" < "15.0.0-rc.1" < "15.0.0", and "10.6" < "10.6p2".
 * This is the core's version order. Where it differs from an ecosystem's: a number after a '-' other than that zero
 * continues the version (semver reads "1.0.0-1" as a pre-release, and Go puts "v0.0.0-20191109021931-…" below
 * v0.0.0), and a word after a '-' on neither list above ("-jre", "-android", "-rc1") is ordered as semver orders it,
 * which Maven and Composer may not; osva_version_uncertain names those versions.
 * Returns -1, 0 or 1.
 * Theorems (OSVACore/Version.lean): reflexive, antisymmetric, transitive, for all inputs.
 */
int osva_vcmp(const uint8_t *a, size_t na, const uint8_t *b, size_t nb);

/*
 * Whether the core's version order may not be v's ecosystem's: 1 when v has a word right after a '-' that is neither
 * release-equal (ga, final, release) nor post-release (p, patch, pl, sp, r, post, rev), such as Maven's "33.7.2-jre",
 * which the core orders below 33.7.2 and Maven above it, or "1.0.0-rc.1"; else 0. Always 0 for a version without a
 * '-' ("1.2.3", "10.6p2", "1.0rc1"), and for one semver's "-0" makes a pre-release ("1.24.0-0",
 * "v1.2.4-0.20190101-abcdef"), which is ordered with certainty. The words are read as osva_vcmp reads them
 * (case-insensitive, after dropping a leading 'v' and everything from the first '+'). -2 on a bad argument: v NULL
 * while nv is not 0.
 * Theorems (OSVACore/Version.lean, FFI.lean): 1 exactly when there is no "-0" and such a word exists; never 1 for a
 * version without a '-'.
 */
int osva_version_uncertain(const uint8_t *v, size_t nv);

/*
 * One affected range, as an advisory's issuer publishes it: every version v with introduced <= v, and v < fixed, and
 * v <= last_affected, in the order of osva_vcmp. A NULL pointer means that bound is absent: no introduced means from the
 * first version, no fixed and no last_affected means every later version. A non-NULL pointer is a bound, even with
 * length 0. Pointers are read only during the call.
 */
typedef struct {
    const uint8_t *introduced;
    size_t introduced_len;
    const uint8_t *fixed;
    size_t fixed_len;
    const uint8_t *last_affected;
    size_t last_affected_len;
} osva_range;

/*
 * One advisory as the site publishes it, for osva_verdicts, osva_upgrade_for and osva_judge: its affected ranges, and
 * the first fixed versions its issuer names, one per release branch (nginx: "1.30.7", "1.31.9"). The ranges are read
 * only when has_ranges is not 0. Without them (has_ranges 0, or n_ranges 0: an empty list is no answer) the fixed
 * versions decide. Pointers are read only during the call.
 *
 * A bad argument, for all three: as NULL while n is not 0; an advisory's ranges NULL while its n_ranges is not 0 (even
 * when has_ranges is 0), its fixed or fixed_len NULL while its n_fixed is not 0, or one of its fixed versions NULL
 * with a length that is not 0; a version NULL with a length that is not 0; out NULL while n is not 0 (osva_upgrade_for:
 * while cap is not 0); n or any n_ranges above SIZE_MAX / 3. Every argument is checked before any is used. All three
 * also return -2 if the core could not start (osva_core_init failed).
 */
typedef struct {
    int has_ranges;                     /* 0: the site publishes none it can read; fixed then decides */
    const osva_range *ranges;
    size_t n_ranges;
    const uint8_t *const *fixed;
    const size_t *fixed_len;
    size_t n_fixed;
} osva_advisory;

/*
 * What each advisory says about an installed version. Ranges decide when an advisory has them; without them (see
 * osva_advisory) its first fixed versions decide, and only as "likely":
 *   1 (inside a published range)  <=>  the advisory has ranges, and v lies in one of them;
 *   2 (likely)                    <=>  it has none, and the first-fixed rule says v is affected: some first fixed
 *                                      version is above v, and none on v's own branch (its first two numbers) is at
 *                                      or below v;
 *   0 (clear)                         otherwise.
 * 0 is not evidence that a version fixes anything: an advisory with neither ranges nor fixed versions is 0 for every
 * version. Never read 0 as "fixed"; ask osva_judge, which answers 0 for such an advisory.
 * Writes one answer per advisory to out[0 .. n-1] and returns 0; returns -2 on a bad argument (above), writing nothing.
 * Theorems (OSVACore/Decide.lean, FFI.lean): 1 only when v lies in one of the advisory's published ranges, and always
 * then; 2 only for an advisory without ranges whose first fixed versions say v is affected (and then, OSVACore/
 * Affected.lean, one of them is above v).
 */
int osva_verdicts(const uint8_t *v, size_t nv, const osva_advisory *as, size_t n, uint8_t *out);

/*
 * The upgrade to suggest, given the advisories that concern an installed version: the lowest candidate that is above v
 * and clear of every advisory, with evidence. The candidates are the releases (never a pre-release such as
 * "2.7.1-rc1") that the advisories' ranges name as fixed or their issuers name as first fixed. A version is clear of an
 * advisory, with evidence, when the advisory has ranges and the version lies in none of them, or has none and its first
 * fixed versions say the version is not affected; no version is clear of an advisory with neither, so given one, there
 * is no upgrade. Writes it to out and returns its length; returns -1 if there is none, -2 on a bad argument (above), -3
 * if cap is smaller than the version (cap at least the longest fixed version given is always enough).
 * Its cost grows with the square of n, since every candidate is checked against every advisory: milliseconds for 40
 * advisories, about half a second for 400, seconds for 1,000. Give it one package's advisories, off the main thread.
 * Theorems (OSVACore/Decide.lean): the version is above v and, for every advisory, lies in none of its published ranges
 * or, when it has none, is not affected by its first fixed versions; no other candidate with those properties is below
 * it; and it is one of the candidates.
 */
long osva_upgrade_for(const uint8_t *v, size_t nv, const osva_advisory *as, size_t n, uint8_t *out, size_t cap);

/*
 * Checks an upgrade u that the core did not pick (the server's target, a vendor's build, pip's choice). When u is
 * above v, sets out[i] to 1 if u is clear of advisory i, with evidence (as for osva_upgrade_for), else to 0, and
 * returns 1; when u is not above v, returns 0 and leaves out untouched. Returns -2 on a bad argument (above), writing
 * nothing.
 * An advisory with neither ranges nor fixed versions gets 0 here, even though osva_verdicts writes 0 (clear) for it:
 * with nothing stated, clear is no evidence that u fixes it.
 * Theorem (OSVACore/Decide.lean): it answers only for a u above v, one answer per advisory, and out[i] is 1 only if u
 * lies in none of advisory i's published ranges or, when it has none, its first fixed versions say u is not affected.
 */
int osva_judge(const uint8_t *v, size_t nv, const uint8_t *u, size_t nu, const osva_advisory *as, size_t n,
               uint8_t *out);

/*
 * Privacy filter. Keys are "<ecosystem>\x1f<name>". mask[i] is set to 1 if inventory key i is in the public index
 * the app downloaded, else 0; only keys with mask 1 may be sent to the API. Returns 0, or -1 on a bad argument,
 * writing nothing: index or index_len NULL while n_index is not 0, inventory or inventory_len NULL while n_inventory
 * is not 0, a key NULL with a length that is not 0, or mask NULL while n_inventory is not 0. Every argument is checked
 * before any is used. Also -1 if the core could not start (osva_core_init failed).
 * Theorem (OSVACore/Select.lean): mask[i] = 1 exactly when inventory key i equals some index key byte for byte.
 */
int osva_select(const uint8_t *const *index, const size_t *index_len, size_t n_index,
                const uint8_t *const *inventory, const size_t *inventory_len, size_t n_inventory,
                uint8_t *mask);

/*
 * Percent-encodes one URL path component: RFC 3986 unreserved bytes (A-Z a-z 0-9 - . _ ~) are kept, every other
 * byte becomes %XX. Writes the result to out and returns its length, or -1 if cap is smaller than 3 * n.
 * Theorems (OSVACore/Encode.lean): the output contains only unreserved bytes and %XX (so never / ? # @ :), and
 * decoding it gives back the input (so two different names never encode alike).
 */
long osva_pct_encode(const uint8_t *in, size_t n, uint8_t *out, size_t cap);

#ifdef __cplusplus
}
#endif
#endif
