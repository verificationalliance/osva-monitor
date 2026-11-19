/*
 * The C side of OSVA Monitor's verified core: implements include/osva_core.h by handing bytes to the Lean
 * definitions (OSVACore/FFI.lean) and copying their answers back. This file is the only unproved code between the
 * app and the theorems, so it does nothing but convert: no decisions are made here.
 *
 * Ownership: the Lean exports take their arguments owned (each call consumes the objects made for it) and return
 * owned results, which are released here after copying.
 */
#include <lean/lean.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include "osva_core.h"

extern uint8_t osva_lean_vcmp(lean_object *a, lean_object *b);
extern uint8_t osva_lean_affected(lean_object *v, lean_object *fixed);
extern uint8_t osva_lean_affected_ranges(lean_object *v, lean_object *present, lean_object *bounds);
extern lean_object *osva_lean_upgrade_ranges(lean_object *v, lean_object *present, lean_object *bounds);
extern lean_object *osva_lean_select(lean_object *index, lean_object *inventory);
extern lean_object *osva_lean_encode(lean_object *s);
extern lean_object *initialize_osvaCore_OSVACore(uint8_t builtin);
extern void lean_initialize_runtime_module(void);      /* in libleanrt, not declared by lean.h in this Lean version */

static int g_ready = 0;

int osva_core_init(void) {
    if (g_ready) return 0;
    lean_initialize_runtime_module();
    lean_set_panic_messages(false);
    lean_object *res = initialize_osvaCore_OSVACore(1);
    lean_set_panic_messages(true);
    if (!lean_io_result_is_ok(res)) { lean_dec_ref(res); return -1; }
    lean_dec_ref(res);
    lean_io_mark_end_initialization();
    g_ready = 1;
    return 0;
}

static lean_object *mk_bytes(const uint8_t *p, size_t n) {
    lean_object *a = lean_alloc_sarray(1, n, n);
    if (n > 0) memcpy(lean_sarray_cptr(a), p, n);
    return a;
}

static lean_object *mk_byte_arrays(const uint8_t *const *items, const size_t *lens, size_t n) {
    lean_object *arr = lean_alloc_array(n, n);
    lean_object **cells = lean_array_cptr(arr);
    for (size_t i = 0; i < n; i++) cells[i] = mk_bytes(items[i], lens[i]);
    return arr;
}

int osva_vcmp(const uint8_t *a, size_t na, const uint8_t *b, size_t nb) {
    if (osva_core_init() != 0) return 0;
    return (int)osva_lean_vcmp(mk_bytes(a, na), mk_bytes(b, nb)) - 1;     /* 0,1,2 -> -1,0,1 */
}

int osva_affected(const uint8_t *v, size_t nv, const uint8_t *const *fixed, const size_t *fixed_len, size_t n_fixed) {
    if (osva_core_init() != 0) return -1;
    uint8_t r = osva_lean_affected(mk_bytes(v, nv), mk_byte_arrays(fixed, fixed_len, n_fixed));
    return r == 2 ? -1 : (int)r;                                            /* 2 = unknown */
}

/* The ranges as FFI.lean's decodeRanges reads them: bound 3k, 3k+1, 3k+2 of range k (introduced, fixed, last affected),
 * each present when its byte in `present` is 1; an absent bound is passed as an empty array. */
static int mk_ranges(const osva_range *ranges, size_t n, lean_object **present, lean_object **bounds) {
    if ((n > 0 && ranges == NULL) || n > SIZE_MAX / 3) return -1;
    lean_object *p = lean_alloc_sarray(1, 3 * n, 3 * n);
    lean_object *b = lean_alloc_array(3 * n, 3 * n);
    uint8_t *flags = lean_sarray_cptr(p);
    lean_object **cells = lean_array_cptr(b);
    for (size_t k = 0; k < n; k++) {
        const uint8_t *ptr[3] = { ranges[k].introduced, ranges[k].fixed, ranges[k].last_affected };
        size_t len[3] = { ranges[k].introduced_len, ranges[k].fixed_len, ranges[k].last_affected_len };
        for (int j = 0; j < 3; j++) {
            flags[3 * k + j] = ptr[j] != NULL;
            cells[3 * k + j] = ptr[j] != NULL ? mk_bytes(ptr[j], len[j]) : mk_bytes(NULL, 0);
        }
    }
    *present = p; *bounds = b;
    return 0;
}

int osva_affected_ranges(const uint8_t *v, size_t nv, const osva_range *ranges, size_t n_ranges) {
    if (osva_core_init() != 0) return -2;
    lean_object *present, *bounds;
    if (mk_ranges(ranges, n_ranges, &present, &bounds) != 0) return -2;
    uint8_t r = osva_lean_affected_ranges(mk_bytes(v, nv), present, bounds);
    return r == 2 ? -1 : (int)r;                                            /* 2 = unknown */
}

long osva_upgrade_ranges(const uint8_t *v, size_t nv, const osva_range *ranges, size_t n_ranges, uint8_t *out, size_t cap) {
    if (osva_core_init() != 0 || (cap > 0 && out == NULL)) return -2;
    lean_object *present, *bounds;
    if (mk_ranges(ranges, n_ranges, &present, &bounds) != 0) return -2;
    lean_object *res = osva_lean_upgrade_ranges(mk_bytes(v, nv), present, bounds);
    size_t m = lean_sarray_size(res);
    const uint8_t *r = lean_sarray_cptr(res);
    long out_len;
    if (m == 0) out_len = -1;                                               /* no upgrade */
    else if (r[0] != 1 || m - 1 > (size_t)LONG_MAX) out_len = -2;           /* cannot happen (ffiUpgradeRanges_spec) */
    else if (m - 1 > cap) out_len = -3;
    else { if (m > 1) memcpy(out, r + 1, m - 1); out_len = (long)(m - 1); }
    lean_dec(res);
    return out_len;
}

int osva_select(const uint8_t *const *index, const size_t *index_len, size_t n_index,
                const uint8_t *const *inventory, const size_t *inventory_len, size_t n_inventory,
                uint8_t *mask) {
    if (osva_core_init() != 0 || (n_inventory > 0 && mask == NULL)) return -1;
    lean_object *res = osva_lean_select(mk_byte_arrays(index, index_len, n_index),
                                        mk_byte_arrays(inventory, inventory_len, n_inventory));
    size_t m = lean_sarray_size(res);
    if (m != n_inventory) { lean_dec(res); return -1; }   /* cannot happen (ffiSelect_length); never trusted blindly */
    if (m > 0) memcpy(mask, lean_sarray_cptr(res), m);
    lean_dec(res);
    return 0;
}

long osva_pct_encode(const uint8_t *in, size_t n, uint8_t *out, size_t cap) {
    if (osva_core_init() != 0) return -1;
    if (n > (size_t)(LONG_MAX / 3) || cap < 3 * n) return -1;
    lean_object *res = osva_lean_encode(mk_bytes(in, n));
    size_t m = lean_sarray_size(res);
    if (m > cap) { lean_dec(res); return -1; }               /* cannot happen (encode_length); never trusted blindly */
    if (m > 0) memcpy(out, lean_sarray_cptr(res), m);
    lean_dec(res);
    return (long)m;
}
