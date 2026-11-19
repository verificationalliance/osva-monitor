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
#include <string.h>
#include "osva_core.h"

extern uint8_t osva_lean_vcmp(lean_object *a, lean_object *b);
extern uint8_t osva_lean_affected(lean_object *v, lean_object *fixed);
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
