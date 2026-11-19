/-
  Is an installed version affected, given the affected ranges the issuer publishes? (C: osva_affected_ranges,
  osva_upgrade_ranges)

  A range runs from `introduced` (none: from the first version) up to but not including `fixed`, or up to and including
  `lastAffected` (neither: every later version). PostgreSQL's CVE-2026-14662 gives one range per release branch: 16 up
  to 16.15, 17 up to 17.11, and so on. CPython's CVE-2026-119170 gives one: 3.14.10 up to 3.14.11.

    affected  ⟺  v lies in some range.

  The theorems are the promises the app makes to the person reading its warning:
    · with no ranges there is no answer (the app then uses the older decision, Affected.lean);
    · a warning means the version lies in one of the issuer's ranges, and every version in one is flagged;
    · a version outside every range is never flagged;
    · a warning whose range has a fixed version has that version above it to upgrade to;
    · the upgrade the app proposes is above the installed version, lies in none of the ranges, and is the lowest such
      fixed version.

  `affected` (Affected.lean) is kept for advisories that carry only first fixed versions.
-/
import OSVACore.Version

namespace OSVA

/-- One affected range as the issuer publishes it. A bound that is `none` is absent. -/
structure Range where
  introduced : Option Bytes := none
  fixed : Option Bytes := none
  lastAffected : Option Bytes := none

/-- `v` lies in `r`: at or above `introduced`, below `fixed`, at or below `lastAffected` (each when present). -/
def InRange (v : Bytes) (r : Range) : Prop :=
  (∀ i, r.introduced = some i → vcmp i v ≠ .gt) ∧
  (∀ f, r.fixed = some f → vcmp v f = .lt) ∧
  (∀ l, r.lastAffected = some l → vcmp v l ≠ .gt)

/-- The same, computed. -/
def Range.contains (r : Range) (v : Bytes) : Bool :=
  (match r.introduced with | none => true | some i => vcmp i v != .gt) &&
  (match r.fixed with | none => true | some f => vcmp v f == .lt) &&
  (match r.lastAffected with | none => true | some l => vcmp v l != .gt)

theorem contains_iff (r : Range) (v : Bytes) : r.contains v = true ↔ InRange v r := by
  rcases r with ⟨i, f, l⟩
  cases i <;> cases f <;> cases l <;> simp [Range.contains, InRange, and_assoc]

/-- `none` when there are no ranges; otherwise whether `v` lies in one. -/
def affectedIn (v : Bytes) (rs : List Range) : Option Bool :=
  if rs.isEmpty then none else some (rs.any (·.contains v))

/-- With no ranges there is no answer, and only then. -/
theorem affectedIn_unknown_iff (v : Bytes) (rs : List Range) : affectedIn v rs = none ↔ rs = [] := by
  cases rs <;> simp [affectedIn]

/-- Every warning means the version lies in one of the issuer's ranges. -/
theorem affectedIn_sound {v : Bytes} {rs : List Range} (h : affectedIn v rs = some true) : ∃ r ∈ rs, InRange v r := by
  cases rs with
  | nil => simp [affectedIn] at h
  | cons r rs =>
    simp only [affectedIn, List.isEmpty_cons, Bool.false_eq_true, ite_false, Option.some.injEq, List.any_eq_true] at h
    obtain ⟨r', hr', hc⟩ := h
    exact ⟨r', hr', (contains_iff r' v).1 hc⟩

/-- Every version that lies in one of the ranges is flagged. -/
theorem affectedIn_complete {v : Bytes} {rs : List Range} {r : Range} (hr : r ∈ rs) (hv : InRange v r) :
    affectedIn v rs = some true := by
  cases rs with
  | nil => simp at hr
  | cons r0 rs =>
    simp only [affectedIn, List.isEmpty_cons, Bool.false_eq_true, ite_false, Option.some.injEq, List.any_eq_true]
    exact ⟨r, hr, (contains_iff r v).2 hv⟩

/-- A version outside every range is never flagged. -/
theorem affectedIn_outside {v : Bytes} {rs : List Range} (hne : rs ≠ []) (h : ∀ r ∈ rs, ¬ InRange v r) :
    affectedIn v rs = some false := by
  cases rs with
  | nil => exact absurd rfl hne
  | cons r0 rs =>
    simp only [affectedIn, List.isEmpty_cons, Bool.false_eq_true, ite_false, Option.some.injEq, List.any_eq_false]
    intro r hr hc
    exact h r hr ((contains_iff r v).1 hc)

/-- A warning whose range has a fixed version has that version above the installed one, to upgrade to. -/
theorem affectedIn_fixed_above {v f : Bytes} {r : Range} (hv : InRange v r) (hf : r.fixed = some f) : vcmp v f = .lt :=
  hv.2.1 f hf

/-! ### The upgrade -/

/-- The fixed versions above `v` that lie in no range: each leaves every range behind. -/
def upgrades (v : Bytes) (rs : List Range) : List Bytes :=
  (rs.filterMap (·.fixed)).filter (fun f => vcmp v f == .lt && !(rs.any (·.contains f)))

/-- The lowest of `b` and `gs`, in the version order. -/
def lowest : Bytes → List Bytes → Bytes
  | b, [] => b
  | b, g :: gs => lowest (if vcmp g b = .lt then g else b) gs

/-- The upgrade the app proposes: the lowest fixed version above `v` that no range includes. -/
def upgradeIn (v : Bytes) (rs : List Range) : Option Bytes :=
  match upgrades v rs with
  | [] => none
  | f :: fs => some (lowest f fs)

theorem mem_upgrades {v u : Bytes} {rs : List Range} :
    u ∈ upgrades v rs ↔ (∃ r ∈ rs, r.fixed = some u) ∧ vcmp v u = .lt ∧ ∀ r ∈ rs, ¬ InRange u r := by
  simp only [upgrades, List.mem_filter, List.mem_filterMap, Bool.and_eq_true, beq_iff_eq, Bool.not_eq_true',
    List.any_eq_false]
  constructor
  · rintro ⟨h1, h2, h3⟩
    exact ⟨h1, h2, fun r hr hin => h3 r hr ((contains_iff r u).2 hin)⟩
  · rintro ⟨h1, h2, h3⟩
    refine ⟨h1, h2, fun r hr hc => h3 r hr ((contains_iff r u).1 (by simpa using hc))⟩

theorem lowest_mem : ∀ (b : Bytes) (gs : List Bytes), lowest b gs = b ∨ lowest b gs ∈ gs
  | b, [] => Or.inl rfl
  | b, g :: gs => by
    simp only [lowest]
    by_cases hc : vcmp g b = .lt
    · rcases lowest_mem g gs with h | h <;> simp [hc, h]
    · rcases lowest_mem b gs with h | h <;> simp [hc, h]

theorem lowest_le : ∀ (b : Bytes) (gs : List Bytes), ∀ x ∈ b :: gs, vcmp (lowest b gs) x ≠ .gt
  | b, [], x, hx => by
    simp only [List.mem_singleton] at hx
    subst hx
    simp [lowest, vcmp_refl]
  | b, g :: gs, x, hx => by
    simp only [lowest]
    have step : ∀ b', vcmp b' b ≠ .gt → vcmp b' g ≠ .gt → vcmp (lowest b' gs) x ≠ .gt := by
      intro b' hb hg
      have here := lowest_le b' gs b' (by simp)
      rcases List.mem_cons.1 hx with rfl | hx'
      · exact vcmp_trans _ _ _ here hb
      · rcases List.mem_cons.1 hx' with rfl | hx''
        · exact vcmp_trans _ _ _ here hg
        · exact lowest_le b' gs x (List.mem_cons_of_mem _ hx'')
    by_cases hc : vcmp g b = .lt
    · simp only [hc, ite_true]
      exact step g (by simp [hc]) (by simp [vcmp_refl])
    · simp only [hc, ite_false]
      refine step b (by simp [vcmp_refl]) ?_
      rw [vcmp_antisymm b g]
      cases h : vcmp g b <;> simp_all [Ordering.swap]

theorem upgradeIn_mem {v u : Bytes} {rs : List Range} (h : upgradeIn v rs = some u) : u ∈ upgrades v rs := by
  cases hu : upgrades v rs with
  | nil => simp [upgradeIn, hu] at h
  | cons f fs =>
    simp only [upgradeIn, hu, Option.some.injEq] at h
    subst h
    rcases lowest_mem f fs with h1 | h1
    · rw [h1]; simp
    · exact List.mem_cons_of_mem _ h1

/-- The proposed upgrade is above the installed version. -/
theorem upgradeIn_above {v u : Bytes} {rs : List Range} (h : upgradeIn v rs = some u) : vcmp v u = .lt :=
  (mem_upgrades.1 (upgradeIn_mem h)).2.1

/-- The proposed upgrade lies in none of the ranges: the advisory does not flag it. -/
theorem upgradeIn_clears {v u : Bytes} {rs : List Range} (h : upgradeIn v rs = some u) : affectedIn u rs = some false := by
  obtain ⟨⟨r, hr, _⟩, _, hout⟩ := mem_upgrades.1 (upgradeIn_mem h)
  exact affectedIn_outside (List.ne_nil_of_mem hr) hout

/-- It is the lowest such fixed version: no other upgrade that leaves every range behind is below it. -/
theorem upgradeIn_nearest {v u g : Bytes} {rs : List Range} (h : upgradeIn v rs = some u) (hg : g ∈ upgrades v rs) :
    vcmp u g ≠ .gt := by
  cases hu : upgrades v rs with
  | nil => simp [hu] at hg
  | cons f fs =>
    simp only [upgradeIn, hu, Option.some.injEq] at h
    subst h
    exact lowest_le f fs g (by simpa [hu] using hg)

/-- When the range a version lies in has a fixed version that no range includes, there is an upgrade. -/
theorem upgradeIn_exists {v f : Bytes} {r : Range} {rs : List Range} (hr : r ∈ rs) (hv : InRange v r)
    (hf : r.fixed = some f) (hout : ∀ r' ∈ rs, ¬ InRange f r') : (upgradeIn v rs).isSome := by
  have hmem : f ∈ upgrades v rs := mem_upgrades.2 ⟨⟨r, hr, hf⟩, hv.2.1 f hf, hout⟩
  cases hu : upgrades v rs with
  | nil => simp [hu] at hmem
  | cons g gs => simp [upgradeIn, hu]

/-! Examples, checked every time the core is built. -/

/-- PostgreSQL's CVE-2026-14662: one range per release branch. -/
def pg : List Range :=
  [⟨none, some (bytes "14.24"), none⟩, ⟨some (bytes "15"), some (bytes "15.19"), none⟩, ⟨some (bytes "16"), some (bytes "16.15"), none⟩,
   ⟨some (bytes "17"), some (bytes "17.11"), none⟩, ⟨some (bytes "18"), some (bytes "18.6"), none⟩]
/-- CPython's CVE-2026-119170: only 3.14.10. -/
def py : List Range := [⟨some (bytes "3.14.10"), some (bytes "3.14.11"), none⟩]

#guard affectedIn (bytes "16.16") pg == some false
#guard affectedIn (bytes "16.14") pg == some true
#guard upgradeIn (bytes "16.14") pg == some (bytes "16.15")
#guard affectedIn (bytes "14.24") pg == some false
#guard affectedIn (bytes "13.9") pg == some true
#guard affectedIn (bytes "3.11.18") py == some false
#guard affectedIn (bytes "3.13.18") py == some false
#guard affectedIn (bytes "3.14.10") py == some true
#guard upgradeIn (bytes "3.14.10") py == some (bytes "3.14.11")
#guard affectedIn (bytes "1.0") [] == none
#guard affectedIn (bytes "2.0") [⟨some (bytes "1.5"), none, none⟩] == some true          -- no upper bound
#guard upgradeIn (bytes "2.0") [⟨some (bytes "1.5"), none, none⟩] == none
#guard affectedIn (bytes "2.13.0") [⟨some (bytes "2.11.0"), none, some (bytes "2.13.0")⟩] == some true
#guard affectedIn (bytes "2.13.1") [⟨some (bytes "2.11.0"), none, some (bytes "2.13.0")⟩] == some false
-- an upgrade that another range includes is not proposed: 16.15 starts a later flaw, so 16.20 it is
#guard upgradeIn (bytes "16.10") [⟨some (bytes "16"), some (bytes "16.15"), none⟩, ⟨some (bytes "16.14"), some (bytes "16.20"), none⟩]
  == some (bytes "16.20")

end OSVA
