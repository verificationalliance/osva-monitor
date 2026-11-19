/-
  The functions the C shim (ffi/osva_shim.c) calls. Each is the proved definition applied to the bytes it is given,
  with its result encoded as a small number; the theorems below state that correspondence, so what the app receives
  is what the proofs are about.
-/
import OSVACore.Version
import OSVACore.Affected
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

/-- osva_affected: 1 affected, 0 not, 2 unknown. -/
@[export osva_lean_affected]
def ffiAffected (v : ByteArray) (fixed : Array ByteArray) : UInt8 :=
  match affected (toBytes v) (fixed.toList.map toBytes) with
  | none => 2
  | some true => 1
  | some false => 0

/-- osva_select: one byte per inventory key, 1 if it may be sent. -/
@[export osva_lean_select]
def ffiSelect (index inventory : Array ByteArray) : ByteArray :=
  ofBytes ((select (index.toList.map toBytes) (inventory.toList.map toBytes)).map (fun b => if b then 1 else 0))

/-- osva_pct_encode. -/
@[export osva_lean_encode]
def ffiEncode (s : ByteArray) : ByteArray := ofBytes (pctEncode (toBytes s))

theorem ffiVcmp_spec (a b : ByteArray) : ffiVcmp a b = ordCode (vcmp (toBytes a) (toBytes b)) := rfl

theorem ffiAffected_one_iff (v : ByteArray) (fixed : Array ByteArray) :
    ffiAffected v fixed = 1 ↔ affected (toBytes v) (fixed.toList.map toBytes) = some true := by
  unfold ffiAffected; split <;> simp_all

theorem ffiEncode_spec (s : ByteArray) : toBytes (ffiEncode s) = pctEncode (toBytes s) := by
  simp [ffiEncode, toBytes, ofBytes]

theorem ffiSelect_length (index inventory : Array ByteArray) :
    (toBytes (ffiSelect index inventory)).length = inventory.size := by
  simp [ffiSelect, toBytes, ofBytes, select_length]

end OSVA
