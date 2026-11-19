#!/usr/bin/env bash
# Checks OSVA Monitor's verified core, on Linux or macOS, with only Lean (elan) and a C compiler installed:
#   1. builds the Lean core: Lean re-checks every theorem (warnings are errors, so no `sorry` gets through);
#   2. audits the axioms each published theorem rests on: Lean's standard three only;
#   3. compiles the C shim against the Lean-compiled core and runs ffi/test/shim_test.c.
set -euo pipefail
cd "$(dirname "$0")/../core"
export PATH="$HOME/.elan/bin:$PATH"

echo "1. building the core (every theorem re-checked)"
lake build OSVACore OSVACore:static >/dev/null

echo "2. axioms"
out=$(lake env lean Audit.lean)
n=$(grep -c "depends on axioms\|does not depend on any axioms" <<<"$out")
bad=$(grep "depends on axioms" <<<"$out" | grep -v -E "axioms: \[((propext|Quot.sound|Classical.choice)(, )?)+\]$" || true)
if [ -n "$bad" ] || [ "$n" -lt 19 ]; then echo "$out"; echo "FAILED: unexpected axioms or missing theorems"; exit 1; fi
echo "   $n theorems, standard axioms only"

echo "3. C shim"
T=$(dirname "$(dirname "$(elan which lean)")")
LIB=.lake/build/lib/libosvaCore_OSVACore.a
if [ "$(uname)" = Darwin ]; then
  LINK=(-L "$T/lib/lean" -lStd -lInit -lleanrt -lcadical -L "$T/lib" -lc++ -lgmp -luv -Wl,-dead_strip)
else
  LINK=(-L "$T/lib/lean" -L "$T/lib" -Wl,--start-group -lStd -lInit -lleanrt -Wl,--end-group -lcadical
        -Wl,-Bstatic -lc++ -lc++abi -Wl,-Bdynamic -lgmp -luv -lpthread -ldl -lm -Wl,--gc-sections)
fi
tmp=$(mktemp -d)
cc -O2 -Wall -Wextra -Werror -I include -I "$T/include" -o "$tmp/shim_test" ffi/test/shim_test.c ffi/osva_shim.c "$LIB" "${LINK[@]}"
"$tmp/shim_test" | tail -1
rm -rf "$tmp"
