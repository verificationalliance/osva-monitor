/-
  Is an installed version affected? (C: osva_affected)

  Input: the version installed, and the first fixed version the issuer names for each release branch (nginx's
  CVE-2026-123633: "1.30.7" and "1.31.9"). A version's branch is its first two numbers.

    affected  ⟺  some fixed version is above v,  and no fixed version on v's own branch is at or below v.

  The three theorems are the promises the app makes to the person reading its warning:
    · a warning always comes with a fixed version above the installed one, to upgrade to;
    · a version at or past its own branch's fix is never flagged;
    · a version at or above every fixed version is never flagged.
-/
import OSVACore.Version

namespace OSVA

def isNumKey (k : List Nat) : Bool := k.head? == some 3

/-- The first two numbers of a version (as keys, so "007" and "7" are the same branch number). -/
def branchKey (s : Bytes) : List (List Nat) := ((tokens s).filter isNumKey).take 2

/-- `none` when there is nothing to compare against; otherwise whether `v` is affected. -/
def affected (v : Bytes) (fixed : List Bytes) : Option Bool :=
  if fixed.isEmpty then none
  else some (fixed.any (fun f => vcmp v f == .lt) &&
             !(fixed.any (fun f => vcmp v f != .lt && branchKey v == branchKey f)))

/-- Every warning has a fixed version above the installed one. -/
theorem affected_has_upgrade {v : Bytes} {fixed : List Bytes} (h : affected v fixed = some true) :
    ∃ f ∈ fixed, vcmp v f = .lt := by
  unfold affected at h
  split at h
  · simp at h
  · simp only [Option.some.injEq, Bool.and_eq_true, List.any_eq_true, beq_iff_eq] at h
    exact h.1

/-- A version at or past the fixed version of its own branch is never flagged. -/
theorem affected_not_when_fixed_on_branch {v f : Bytes} {fixed : List Bytes} (hf : f ∈ fixed)
    (hb : branchKey v = branchKey f) (hv : vcmp v f ≠ .lt) : affected v fixed ≠ some true := by
  unfold affected
  split
  · simp
  · intro h
    simp only [Option.some.injEq, Bool.and_eq_true, Bool.not_eq_true', List.any_eq_false] at h
    have := h.2 f hf
    simp [hv, hb] at this

/-- A version at or above every fixed version is never flagged. -/
theorem affected_not_when_newest {v : Bytes} {fixed : List Bytes} (h : ∀ f ∈ fixed, vcmp v f ≠ .lt) :
    affected v fixed ≠ some true := by
  intro ha
  obtain ⟨f, hf, hlt⟩ := affected_has_upgrade ha
  exact h f hf hlt

/-- Without fixed versions there is no answer. -/
theorem affected_unknown_without_fixes (v : Bytes) : affected v [] = none := by
  simp [affected]

/-! nginx, CVE-2026-123633: fixed in 1.30.7 and 1.31.9. -/
#guard affected (bytes "1.31.5") [bytes "1.30.7", bytes "1.31.9"] == some true
#guard affected (bytes "1.30.8") [bytes "1.30.7", bytes "1.31.9"] == some false
#guard affected (bytes "1.29.0") [bytes "1.30.7", bytes "1.31.9"] == some true
#guard affected (bytes "1.32.0") [bytes "1.30.7", bytes "1.31.9"] == some false
#guard affected (bytes "1.31.9") [bytes "1.30.7", bytes "1.31.9"] == some false
#guard affected (bytes "10.6p1") [bytes "10.6p2"] == some true
#guard affected (bytes "10.6p2") [bytes "10.6p2"] == some false
#guard affected (bytes "1.0") [] == none

end OSVA
