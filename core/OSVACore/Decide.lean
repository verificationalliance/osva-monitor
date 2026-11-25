/-
  One decision per advisory, and one per upgrade, from what the site publishes.

  An advisory carries the affected ranges the site publishes for it (Ranges.lean), or none when it publishes none it
  can read, and the first fixed versions its issuer names (Affected.lean). Ranges decide when there are any; without
  them the first-fixed rule decides, and its answer is only "likely":

    inRange  ⟺  the advisory has ranges, and v lies in one of them;
    likely   ⟺  it has none, and the first-fixed rule says v is affected;
    clear       otherwise (an empty list of ranges flags no version).

  An upgrade u leaves an advisory when the advisory calls u clear. The theorems say, of the core, for every input:
    · a version is flagged as inside a range only if it lies in one of the advisory's published ranges, and every
      version in one is flagged;
    · "likely" comes only from an advisory without ranges, by the first-fixed rule;
    · the upgrade the core suggests is above the installed version and leaves every advisory it was given: it lies in
      none of their published ranges, and the first-fixed rule does not flag it for those without;
    · it is the lowest such candidate (a fixed version named by a range or by the issuer);
    · asked about an upgrade it did not pick (the server's target, a vendor's build, pip's choice), the core answers
      only when it is above the installed version, and says it fixes an advisory only if it leaves that advisory.
-/
import OSVACore.Ranges
import OSVACore.Affected

namespace OSVA

/-- One advisory as the site publishes it. -/
structure Advisory where
  /-- The affected ranges the site publishes; `none` when it publishes none it can read. -/
  ranges : Option (List Range) := none
  /-- The first fixed versions the issuer names, one per release branch (the server's `fixed_hint` or `fixed_in`). -/
  fixed : List Bytes := []

/-- What one advisory says about one version. -/
inductive Verdict where
  /-- The version lies in one of the advisory's published ranges. -/
  | inRange
  /-- The advisory has no ranges, and the first-fixed rule says the version is affected. -/
  | likely
  /-- Neither. -/
  | clear
  deriving DecidableEq, Repr

/-- Ranges decide when there are any; otherwise the first fixed versions do, and only as "likely". -/
def verdict (v : Bytes) (a : Advisory) : Verdict :=
  match a.ranges with
  | some rs => if affectedIn v rs = some true then .inRange else .clear
  | none => if affected v a.fixed = some true then .likely else .clear

/-- A warning "inside a range" means the version lies in one of the advisory's published ranges. -/
theorem verdict_inRange_sound {v : Bytes} {a : Advisory} (h : verdict v a = .inRange) :
    ∃ rs, a.ranges = some rs ∧ ∃ r ∈ rs, InRange v r := by
  rcases a with ⟨_ | rs, fixed⟩
  · simp only [verdict] at h
    split at h <;> cases h
  · simp only [verdict] at h
    split at h
    · exact ⟨rs, rfl, affectedIn_sound ‹_›⟩
    · cases h

/-- Every version that lies in one of the advisory's published ranges is flagged as inside one. -/
theorem verdict_inRange_complete {v : Bytes} {a : Advisory} {rs : List Range} {r : Range} (ha : a.ranges = some rs)
    (hr : r ∈ rs) (hv : InRange v r) : verdict v a = .inRange := by
  simp [verdict, ha, affectedIn_complete hr hv]

/-- "Likely" comes only from an advisory without ranges, when the first-fixed rule says the version is affected. -/
theorem verdict_likely_spec {v : Bytes} {a : Advisory} (h : verdict v a = .likely) :
    a.ranges = none ∧ affected v a.fixed = some true := by
  rcases a with ⟨_ | rs, fixed⟩
  · simp only [verdict] at h
    split at h
    · exact ⟨rfl, ‹_›⟩
    · cases h
  · simp only [verdict] at h
    split at h <;> cases h

/-- A version an advisory calls clear lies in none of its published ranges; without ranges, the first-fixed rule does
  not flag it. -/
theorem verdict_clear {u : Bytes} {a : Advisory} (h : verdict u a = .clear) :
    (∀ rs, a.ranges = some rs → ∀ r ∈ rs, ¬ InRange u r) ∧
    (a.ranges = none → affected u a.fixed ≠ some true) := by
  constructor
  · intro rs ha r hr hv
    rw [verdict_inRange_complete ha hr hv] at h
    cases h
  · intro ha hf
    simp [verdict, ha, hf] at h

/-! ### The upgrade -/

/-- `u` is above `v` and every advisory calls it clear. -/
def leaves (v u : Bytes) (as : List Advisory) : Bool :=
  vcmp v u == .lt && as.all (fun a => verdict u a == .clear)

/-- An upgrade that leaves the advisories is above the installed version, lies in none of their published ranges,
  and is not flagged by the first-fixed rule of any advisory without ranges. -/
theorem leaves_sound {v u : Bytes} {as : List Advisory} (h : leaves v u as = true) :
    vcmp v u = .lt ∧ ∀ a ∈ as,
      (∀ rs, a.ranges = some rs → ∀ r ∈ rs, ¬ InRange u r) ∧
      (a.ranges = none → affected u a.fixed ≠ some true) := by
  simp only [leaves, Bool.and_eq_true, beq_iff_eq, List.all_eq_true] at h
  exact ⟨h.1, fun a ha => verdict_clear (h.2 a ha)⟩

/-- The versions worth trying: every fixed version a range names, and every first fixed version the issuer names. -/
def candidates (as : List Advisory) : List Bytes :=
  as.flatMap fun a => (a.ranges.getD []).filterMap (·.fixed) ++ a.fixed

/-- The upgrade the core suggests: the lowest candidate that leaves every advisory. -/
def upgradeFor (v : Bytes) (as : List Advisory) : Option Bytes :=
  match (candidates as).filter (leaves v · as) with
  | [] => none
  | u :: us => some (lowest u us)

theorem upgradeFor_mem {v u : Bytes} {as : List Advisory} (h : upgradeFor v as = some u) :
    u ∈ (candidates as).filter (leaves v · as) := by
  cases hu : (candidates as).filter (leaves v · as) with
  | nil => simp [upgradeFor, hu] at h
  | cons f fs =>
    simp only [upgradeFor, hu, Option.some.injEq] at h
    subst h
    rcases lowest_mem f fs with h1 | h1
    · rw [h1]; simp
    · exact List.mem_cons_of_mem _ h1

/-- The upgrade the core suggests is above the installed version and leaves every advisory it was given. -/
theorem upgradeFor_leaves {v u : Bytes} {as : List Advisory} (h : upgradeFor v as = some u) :
    vcmp v u = .lt ∧ ∀ a ∈ as,
      (∀ rs, a.ranges = some rs → ∀ r ∈ rs, ¬ InRange u r) ∧
      (a.ranges = none → affected u a.fixed ≠ some true) :=
  leaves_sound (List.mem_filter.1 (upgradeFor_mem h)).2

/-- It is the lowest such candidate: no other candidate that leaves every advisory is below it. -/
theorem upgradeFor_nearest {v u g : Bytes} {as : List Advisory} (h : upgradeFor v as = some u)
    (hg : g ∈ candidates as) (hl : leaves v g as = true) : vcmp u g ≠ .gt := by
  have hmem : g ∈ (candidates as).filter (leaves v · as) := List.mem_filter.2 ⟨hg, hl⟩
  cases hu : (candidates as).filter (leaves v · as) with
  | nil => simp [hu] at hmem
  | cons f fs =>
    simp only [upgradeFor, hu, Option.some.injEq] at h
    subst h
    exact lowest_le f fs g (by simpa [hu] using hmem)

/-! ### An upgrade the core did not pick -/

/-- For an upgrade `u` proposed from elsewhere: nothing unless `u` is above `v`; otherwise, per advisory, whether `u`
  leaves it. -/
def judge (v u : Bytes) (as : List Advisory) : Option (List Bool) :=
  if vcmp v u = .lt then some (as.map fun a => verdict u a == .clear) else none

/-- The core answers only for an upgrade above the installed version, with one answer per advisory, and says it fixes
  an advisory only if it lies in none of that advisory's published ranges (or, without ranges, the first-fixed rule
  does not flag it). -/
theorem judge_spec {v u : Bytes} {as : List Advisory} {m : List Bool} (h : judge v u as = some m) :
    vcmp v u = .lt ∧ m.length = as.length ∧
      ∀ (i : Nat) (hi : i < as.length) (hm : i < m.length), m[i] = true →
        (∀ rs, as[i].ranges = some rs → ∀ r ∈ rs, ¬ InRange u r) ∧
        (as[i].ranges = none → affected u as[i].fixed ≠ some true) := by
  unfold judge at h
  split at h
  · simp only [Option.some.injEq] at h
    subst h
    refine ⟨‹_›, by simp, fun i _ _ hi => verdict_clear ?_⟩
    simpa using hi
  · cases h

/-! Examples, checked every time the core is built (`pg` is PostgreSQL's CVE-2026-14662, Ranges.lean). -/

#guard verdict (bytes "16.14") ⟨some pg, []⟩ == .inRange
#guard verdict (bytes "16.16") ⟨some pg, [bytes "99"]⟩ == .clear          -- ranges decide; first fixed versions not consulted
#guard verdict (bytes "1.0") ⟨some [], [bytes "2.0"]⟩ == .clear            -- []: no version is affected
#guard verdict (bytes "1.31.5") ⟨none, [bytes "1.30.7", bytes "1.31.9"]⟩ == .likely
#guard verdict (bytes "1.32.0") ⟨none, [bytes "1.30.7", bytes "1.31.9"]⟩ == .clear
#guard upgradeFor (bytes "16.14") [⟨some pg, []⟩, ⟨none, [bytes "16.20"]⟩] == some (bytes "16.20")
#guard upgradeFor (bytes "2.0") [⟨some [⟨some (bytes "1.5"), none, none⟩], []⟩] == none
#guard judge (bytes "16.14") (bytes "16.15") [⟨some pg, []⟩, ⟨none, [bytes "16.20"]⟩] == some [true, false]
#guard judge (bytes "16.14") (bytes "16.14") [⟨some pg, []⟩] == none
#guard judge (bytes "2.2.0") (bytes "2.13.0") [⟨some [⟨none, some (bytes "2.7.1-rc1"), none⟩], []⟩, ⟨some [{}], []⟩] == some [true, false]

end OSVA
