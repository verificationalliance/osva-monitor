/* Reads lines "<a>\x1f<b>\n" on stdin and prints osva_vcmp(a, b) for each: the Lean-compiled version order, for
 * differential tests of other implementations (formalinformer/api/test_vorder.py checks the server's port). */
#include <stdio.h>
#include <string.h>
#include "osva_core.h"

int main(void) {
    static char line[4096];
    if (osva_core_init() != 0) return 2;
    while (fgets(line, sizeof line, stdin)) {
        size_t n = strlen(line);
        if (n && line[n - 1] == '\n') line[--n] = 0;
        char *sep = memchr(line, 0x1f, n);
        if (!sep) return 3;
        size_t na = (size_t)(sep - line), nb = n - na - 1;
        printf("%d\n", osva_vcmp((const uint8_t *)line, na, (const uint8_t *)sep + 1, nb));
    }
    return 0;
}
