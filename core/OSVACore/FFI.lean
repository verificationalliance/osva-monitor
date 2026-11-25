/-
  The functions the C shim (ffi/osva_shim.c) calls. Each is the proved definition applied to the bytes it is given,
  with its result encoded as a small number; the theorems below state that correspondence, so what the app receives
  is what the proofs are about.
-/
import OSVACore.Version
import OSVACore.Affected
import OSVACore.Ranges
import OSVACore.Decide
import OSVACore.Select
import OSVACore.Encode

namespace OSVA

def toBytes (a : ByteArray) : Bytes := a.data.toList
def ofBytes (l : Bytes) : ByteArray := ⟨l.toArray⟩

def ordCode : Ordering → UInt8
  | .lt => 0
  | .eq => 1
  | .gt => 2

/-- osva_vcmp: 0 older, 1 same, 2 newer. -/
@[export osva_lean_vcmp]
def ffiVcmp (a b : ByteArray) : UInt8 := ordCode (vcmp (toBytes a) (toBytes b))

/-- Bound `j` of the C caller's ranges: present when byte `j` of `present` is not 0. -/
def boundAt (present : Bytes) (bounds : List Bytes) (j : Nat) : Option Bytes :=
  if present.getD j 0 = 0 then none else some (bounds.getD j [])

/-- The C caller's ranges: range `k` has its introduced, fixed and last affected versions at `3k`, `3k + 1`, `3k + 2`. -/
def decodeRanges (present : Bytes) (bounds : List Bytes) : List Range :=
  (List.range (present.length / 3)).map fun k =>
    { introduced := boundAt present bounds (3 * k), fixed := boundAt present bounds (3 * k + 1),
      lastAffected := boundAt present bounds (3 * k + 2) }

/-- The C caller's advisories: advisory `k` has ranges when byte `k` of `has` is not 0, read from `presents[k]` and
  `bounds[k]` as `decodeRanges` reads them, and the first fixed versions `fixed[k]`. -/
def decodeAdvisories (has : Bytes) (presents : List Bytes) (bounds fixed : List (List Bytes)) : List Advisory :=
  (List.range has.length).map fun k =>
    { ranges := if has.getD k 0 ≠ 0 then some (decodeRanges (presents.getD k []) (bounds.getD k [])) else none,
      fixed := fixed.getD k [] }

/-- osva_verdicts' answer for one advisory: 0 clear, 1 inside a published range, 2 likely. -/
def verdictCode : Verdict → UInt8
  | .clear => 0
  | .inRange => 1
  | .likely => 2

/-- osva_verdicts: one byte per advisory, 0 clear, 1 inside a published range, 2 likely. -/
@[export osva_lean_verdicts]
def ffiVerdicts (v has : ByteArray) (presents : Array ByteArray) (bounds fixed : Array (Array ByteArray)) :
    ByteArray :=
  ofBytes ((decodeAdvisories (toBytes has) (presents.toList.map toBytes) (bounds.toList.map (·.toList.map toBytes))
    (fixed.toList.map (·.toList.map toBytes))).map fun a => verdictCode (verdict (toBytes v) a))

/-- osva_upgrade_for: empty when there is no upgrade, else 1 followed by the version. -/
@[export osva_lean_upgrade_for]
def ffiUpgradeFor (v has : ByteArray) (presents : Array ByteArray) (bounds fixed : Array (Array ByteArray)) :
    ByteArray :=
  match upgradeFor (toBytes v) (decodeAdvisories (toBytes has) (presents.toList.map toBytes)
      (bounds.toList.map (·.toList.map toBytes)) (fixed.toList.map (·.toList.map toBytes))) with
  | none => ofBytes []
  | some u => ofBytes (1 :: u)

/-- osva_judge: empty when `u` is not above `v`, else 1 followed by one byte per advisory, 1 if `u` leaves it. -/
@[export osva_lean_judge]
def ffiJudge (v u has : ByteArray) (presents : Array ByteArray) (bounds fixed : Array (Array ByteArray)) :
    ByteArray :=
  match judge (toBytes v) (toBytes u) (decodeAdvisories (toBytes has) (presents.toList.map toBytes)
      (bounds.toList.map (·.toList.map toBytes)) (fixed.toList.map (·.toList.map toBytes))) with
  | none => ofBytes []
  | some m => ofBytes (1 :: m.map fun b => if b then 1 else 0)

/-- osva_select: one byte per inventory key, 1 if it may be sent. -/
@[export osva_lean_select]
def ffiSelect (index inventory : Array ByteArray) : ByteArray :=
  ofBytes ((select (index.toList.map toBytes) (inventory.toList.map toBytes)).map (fun b => if b then 1 else 0))

/-- osva_pct_encode. -/
@[export osva_lean_encode]
def ffiEncode (s : ByteArray) : ByteArray := ofBytes (pctEncode (toBytes s))

/-- osva_version_uncertain: 1 when the core may order the version differently from its ecosystem, else 0. -/
@[export osva_lean_version_uncertain]
def ffiVersionUncertain (v : ByteArray) : UInt8 := if versionUncertain (toBytes v) then 1 else 0

theorem ffiVersionUncertain_spec (v : ByteArray) :
    ffiVersionUncertain v = 1 ↔ versionUncertain (toBytes v) = true := by
  unfold ffiVersionUncertain
  split <;> simp_all

theorem ffiVcmp_spec (a b : ByteArray) : ffiVcmp a b = ordCode (vcmp (toBytes a) (toBytes b)) := rfl

/-- Range `k` is read from bounds `3k`, `3k + 1` and `3k + 2`, as osva_core.h says. -/
theorem decodeRanges_get (present : Bytes) (bounds : List Bytes) (k : Nat) (hk : k < present.length / 3) :
    (decodeRanges present bounds)[k]'(by simpa [decodeRanges] using hk) =
      { introduced := boundAt present bounds (3 * k), fixed := boundAt present bounds (3 * k + 1),
        lastAffected := boundAt present bounds (3 * k + 2) } := by
  simp [decodeRanges]

theorem ffiVerdicts_spec (v has : ByteArray) (presents : Array ByteArray) (bounds fixed : Array (Array ByteArray)) :
    toBytes (ffiVerdicts v has presents bounds fixed) =
      (decodeAdvisories (toBytes has) (presents.toList.map toBytes) (bounds.toList.map (·.toList.map toBytes))
        (fixed.toList.map (·.toList.map toBytes))).map fun a => verdictCode (verdict (toBytes v) a) := by
  simp [ffiVerdicts, toBytes, ofBytes]

theorem ffiUpgradeFor_spec (v has : ByteArray) (presents : Array ByteArray) (bounds fixed : Array (Array ByteArray)) :
    toBytes (ffiUpgradeFor v has presents bounds fixed) =
      match upgradeFor (toBytes v) (decodeAdvisories (toBytes has) (presents.toList.map toBytes)
          (bounds.toList.map (·.toList.map toBytes)) (fixed.toList.map (·.toList.map toBytes))) with
      | none => []
      | some u => 1 :: u := by
  unfold ffiUpgradeFor; split <;> simp_all [toBytes, ofBytes]

theorem ffiJudge_spec (v u has : ByteArray) (presents : Array ByteArray) (bounds fixed : Array (Array ByteArray)) :
    toBytes (ffiJudge v u has presents bounds fixed) =
      match judge (toBytes v) (toBytes u) (decodeAdvisories (toBytes has) (presents.toList.map toBytes)
          (bounds.toList.map (·.toList.map toBytes)) (fixed.toList.map (·.toList.map toBytes))) with
      | none => []
      | some m => 1 :: m.map fun b => if b then 1 else 0 := by
  unfold ffiJudge; split <;> simp_all [toBytes, ofBytes]

/-- Advisory `k` is read from byte `k` of `has`, `presents[k]`, `bounds[k]` and `fixed[k]`, as osva_core.h says. -/
theorem decodeAdvisories_get (has : Bytes) (presents : List Bytes) (bounds fixed : List (List Bytes)) (k : Nat)
    (hk : k < has.length) :
    (decodeAdvisories has presents bounds fixed)[k]'(by simpa [decodeAdvisories] using hk) =
      { ranges := if has.getD k 0 ≠ 0 then some (decodeRanges (presents.getD k []) (bounds.getD k [])) else none,
        fixed := fixed.getD k [] } := by
  simp [decodeAdvisories]

/-- osva_verdicts writes 1 exactly for "inside a published range"… -/
theorem verdictCode_eq_one_iff (x : Verdict) : verdictCode x = 1 ↔ x = .inRange := by
  cases x <;> decide

/-- …and 2 exactly for "likely". -/
theorem verdictCode_eq_two_iff (x : Verdict) : verdictCode x = 2 ↔ x = .likely := by
  cases x <;> decide

/-- One advisory per byte of `has`: the C caller's `n`. -/
theorem decodeAdvisories_length (has : Bytes) (presents : List Bytes) (bounds fixed : List (List Bytes)) :
    (decodeAdvisories has presents bounds fixed).length = has.length := by
  simp [decodeAdvisories]

/-- osva_verdicts gets one answer per advisory. -/
theorem ffiVerdicts_length (v has : ByteArray) (presents : Array ByteArray) (bounds fixed : Array (Array ByteArray)) :
    (toBytes (ffiVerdicts v has presents bounds fixed)).length = has.size := by
  rw [ffiVerdicts_spec, List.length_map, decodeAdvisories_length]
  simp [toBytes]

theorem ffiEncode_spec (s : ByteArray) : toBytes (ffiEncode s) = pctEncode (toBytes s) := by
  simp [ffiEncode, toBytes, ofBytes]

theorem ffiSelect_length (index inventory : Array ByteArray) :
    (toBytes (ffiSelect index inventory)).length = inventory.size := by
  simp [ffiSelect, toBytes, ofBytes, select_length]

end OSVA
