import Lake
open Lake DSL

-- OSVA Monitor's verified core: the definitions the app runs, and the theorems Lean checks about them.
package osvaCore where
  -- every theorem must be closed: `sorry` is an error, not a warning
  leanOptions := #[⟨`warningAsError, true⟩]

@[default_target]
lean_lib OSVACore where
  -- `lake build OSVACore:static` gives .lake/build/lib/libosvaCore_OSVACore.a, which the app links (with the shim in ffi/)
