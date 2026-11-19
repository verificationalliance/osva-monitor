/*
 * OSVA Monitor's verified core: the C interface the Swift app calls.
 *
 * Every decision in the app where a bug would mislead the person using it goes through these functions. Each is
 * written in Lean 4 (the .lean files in core/OSVACore) together with theorems about it that Lean checks for every input; Lean
 * compiles those same definitions to C, which is linked into the app. A small shim (core/ffi/osva_shim.c) converts
 * between C bytes and Lean values; it is the only unproved code on this path.
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
 *   - tokens are compared in turn: pre-release word < end of version < other word < number; numbers numerically;
 *     pre-release words by rank (dev < a = alpha < b = beta < c = rc = pre = preview); other words bytewise.
 * So "1.0rc1" < "1.0" < "1.0.post1" < "1.0.1", and "10.6" < "10.6p2". Returns -1, 0 or 1.
 * Theorems (OSVACore/Version.lean): reflexive, antisymmetric, transitive, for all inputs.
 */
int osva_vcmp(const uint8_t *a, size_t na, const uint8_t *b, size_t nb);

/*
 * Is an installed version affected, given the first fixed version the issuer names for each release branch (nginx:
 * "1.30.7", "1.31.9")? A version's branch is its first two numbers.
 *   affected  <=>  some fixed version is above v,  and no fixed version on v's own branch is at or below v.
 * Returns 1 (affected), 0 (not affected), -1 (unknown: no fixed versions).
 * Theorems (OSVACore/Affected.lean): an affected version always has a fixed version above it to upgrade to; a version
 * at or past its own branch's fix is never affected; a version at or above every fixed version is never affected.
 */
int osva_affected(const uint8_t *v, size_t nv,
                  const uint8_t *const *fixed, const size_t *fixed_len, size_t n_fixed);

/*
 * Privacy filter. Keys are "<ecosystem>\x1f<name>". mask[i] is set to 1 if inventory key i is in the public index
 * the app downloaded, else 0; only keys with mask 1 may be sent to the API. Returns 0, or -1 on a bad argument.
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
