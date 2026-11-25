/-
  One decision per advisory, and one per upgrade, from what the site publishes.

  An advisory carries the affected ranges the site publishes for it (Ranges.lean), or none when it publishes none it
  can read, and the first fixed versions its issuer names (Affected.lean). Ranges decide when there are any; without
  them (none, or an empty list: no answer, as in Ranges.lean) the first-fixed rule decides, and its answer is only
  "likely":

    inRange  ⟺  the advisory has ranges, and v lies in one of them;
    likely   ⟺  it has none, and the first-fixed rule says v is affected;
    clear       otherwise.

  "clear" alone is no evidence: an advisory that states neither ranges nor fixed versions calls every version clear.
  So an upgrade u is clear of an advisory, with evidence, only when the advisory has ranges and u lies in none of them,
  or has none and its fixed versions say u is not affected. The theorems say, of the core, for every input:
    · a version is flagged as inside a range only if it lies in one of the advisory's published ranges, and every
      version in one is flagged;
    · "likely" comes only from an advisory without ranges, by the first-fixed rule;
    · the upgrade the core suggests is above the installed version and clear, with evidence, of every advisory it was
      given;
    · it is the lowest such candidate (a release, not a pre-release, named as fixed by a range or by the issuer);
    · asked about an upgrade it did not pick (the server's target, a vendor's build, pip's choice), the core answers
      only when it is above the installed version, and says it fixes an advisory only if it is clear of it, with
      evidence.
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
  match affectedIn v (a.ranges.getD []) with
  | some true => .inRange
  | some false => .clear
  | none => if affected v a.fixed = some true then .likely else .clear

/-- A warning "inside a range" means the version lies in one of the advisory's published ranges. -/
theorem verdict_inRange_sound {v : Bytes} {a : Advisory} (h : verdict v a = .inRange) :
    ∃ rs, a.ranges = some rs ∧ ∃ r ∈ rs, InRange v r := by
  rcases a with ⟨_ | rs, fixed⟩
  · simp only [verdict, Option.getD, affectedIn, List.isEmpty_nil, ite_true] at h
    split at h <;> cases h
  · simp only [verdict, Option.getD] at h
    split at h
    · exact ⟨rs, rfl, affectedIn_sound ‹_›⟩
    · cases h
    · split at h <;> cases h

/-- Every version that lies in one of the advisory's published ranges is flagged as inside one. -/
theorem verdict_inRange_complete {v : Bytes} {a : Advisory} {rs : List Range} {r : Range} (ha : a.ranges = some rs)
    (hr : r ∈ rs) (hv : InRange v r) : verdict v a = .inRange := by
  simp [verdict, ha, affectedIn_complete hr hv]

/-- "Likely" comes only from an advisory without ranges, when the first-fixed rule says the version is affected. -/
theorem verdict_likely_spec {v : Bytes} {a : Advisory} (h : verdict v a = .likely) :
    (a.ranges = none ∨ a.ranges = some []) ∧ affected v a.fixed = some true := by
  have hn : affectedIn v (a.ranges.getD []) = none := by
    unfold verdict at h
    split at h
    · cases h
    · cases h
    · assumption
  have hl : affected v a.fixed = some true := by
    simp only [verdict, hn] at h
    split at h
    · assumption
    · cases h
  refine ⟨?_, hl⟩
  rw [affectedIn_unknown_iff] at hn
  cases hr : a.ranges with
  | none => exact Or.inl rfl
  | some rs => simp [hr] at hn; exact Or.inr (by rw [hn])

/-- The advisory states something to decide by: published ranges, or else first fixed versions. -/
def decided (a : Advisory) : Bool := !(a.ranges.getD []).isEmpty || !a.fixed.isEmpty

/-- `u` is clear of `a`, with evidence: the advisory states something, and by it `u` is not affected. -/
def clearOf (u : Bytes) (a : Advisory) : Bool := decided a && verdict u a == .clear

/-- Clear, with evidence: with ranges, `u` lies in none of them; without, its fixed versions say `u` is not affected
  (so there are some). -/
theorem clearOf_sound {u : Bytes} {a : Advisory} (h : clearOf u a = true) :
    (∀ rs, a.ranges = some rs → ∀ r ∈ rs, ¬ InRange u r) ∧
    (a.ranges = none ∨ a.ranges = some [] → affected u a.fixed = some false) := by
  simp only [clearOf, Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨hd, hc⟩ := h
  constructor
  · intro rs ha r hr hv
    rw [verdict_inRange_complete ha hr hv] at hc
    cases hc
  · intro hn
    have he : a.ranges.getD [] = [] := by rcases hn with hn | hn <;> simp [hn]
    have hf : a.fixed.isEmpty = false := by simpa [decided, he] using hd
    have hnt : affected u a.fixed ≠ some true := by
      intro hx
      simp [verdict, he, affectedIn, hx] at hc
    cases hx : affected u a.fixed with
    | none => simp [affected, hf] at hx
    | some b => cases b <;> simp_all

/-! ### The upgrade -/

/-- `u` is above `v` and clear, with evidence, of every advisory. -/
def leaves (v u : Bytes) (as : List Advisory) : Bool :=
  vcmp v u == .lt && as.all (clearOf u)

/-- An upgrade that leaves the advisories is above the installed version and, for each advisory, lies in none of its
  published ranges, or, when it has none, is not affected by its fixed versions. -/
theorem leaves_sound {v u : Bytes} {as : List Advisory} (h : leaves v u as = true) :
    vcmp v u = .lt ∧ ∀ a ∈ as,
      (∀ rs, a.ranges = some rs → ∀ r ∈ rs, ¬ InRange u r) ∧
      (a.ranges = none ∨ a.ranges = some [] → affected u a.fixed = some false) := by
  simp only [leaves, Bool.and_eq_true, beq_iff_eq, List.all_eq_true] at h
  exact ⟨h.1, fun a ha => clearOf_sound (h.2 a ha)⟩

/-- The versions worth trying: every release a range names as fixed, and every release the issuer names as first
  fixed. Pre-releases are left out, as the site leaves them out of its own targets. -/
def candidates (as : List Advisory) : List Bytes :=
  (as.flatMap fun a => (a.ranges.getD []).filterMap (·.fixed) ++ a.fixed).filter isRelease

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

/-- The upgrade the core suggests is above the installed version and, for every advisory it was given, lies in none
  of its published ranges, or, when it has none, is not affected by its fixed versions. -/
theorem upgradeFor_leaves {v u : Bytes} {as : List Advisory} (h : upgradeFor v as = some u) :
    vcmp v u = .lt ∧ ∀ a ∈ as,
      (∀ rs, a.ranges = some rs → ∀ r ∈ rs, ¬ InRange u r) ∧
      (a.ranges = none ∨ a.ranges = some [] → affected u a.fixed = some false) :=
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

/-- For an upgrade `u` proposed from elsewhere: nothing unless `u` is above `v`; otherwise, per advisory, `true`
  exactly when `u` is clear of it, with evidence. -/
def judge (v u : Bytes) (as : List Advisory) : Option (List Bool) :=
  if vcmp v u = .lt then some (as.map (clearOf u)) else none

/-- The core answers only for an upgrade above the installed version, with one answer per advisory, and says it fixes
  an advisory only if it is clear of it, with evidence: it lies in none of the advisory's published ranges, or, when
  there are none, the advisory's fixed versions say it is not affected. -/
theorem judge_spec {v u : Bytes} {as : List Advisory} {m : List Bool} (h : judge v u as = some m) :
    vcmp v u = .lt ∧ m.length = as.length ∧
      ∀ (i : Nat) (hi : i < as.length) (hm : i < m.length), m[i] = true →
        (∀ rs, as[i].ranges = some rs → ∀ r ∈ rs, ¬ InRange u r) ∧
        (as[i].ranges = none ∨ as[i].ranges = some [] → affected u as[i].fixed = some false) := by
  unfold judge at h
  split at h
  · simp only [Option.some.injEq] at h
    subst h
    refine ⟨‹_›, by simp, fun i _ _ hi => clearOf_sound ?_⟩
    simpa using hi
  · cases h

/-! Examples, checked every time the core is built (`pg` is PostgreSQL's CVE-2026-14662, Ranges.lean). -/

#guard verdict (bytes "16.14") ⟨some pg, []⟩ == .inRange
#guard verdict (bytes "16.16") ⟨some pg, [bytes "99"]⟩ == .clear          -- ranges decide; first fixed versions not consulted
#guard verdict (bytes "1.31.5") ⟨none, [bytes "1.30.7", bytes "1.31.9"]⟩ == .likely
#guard verdict (bytes "1.32.0") ⟨none, [bytes "1.30.7", bytes "1.31.9"]⟩ == .clear
#guard upgradeFor (bytes "16.14") [⟨some pg, []⟩, ⟨none, [bytes "16.20"]⟩] == some (bytes "16.20")
#guard upgradeFor (bytes "2.0") [⟨some [⟨some (bytes "1.5"), none, none⟩], []⟩] == none
#guard judge (bytes "16.14") (bytes "16.15") [⟨some pg, []⟩, ⟨none, [bytes "16.20"]⟩] == some [true, false]
#guard judge (bytes "16.14") (bytes "16.14") [⟨some pg, []⟩] == none
#guard judge (bytes "2.2.0") (bytes "2.13.0") [⟨some [⟨none, some (bytes "2.7.1-rc1"), none⟩], []⟩, ⟨some [{}], []⟩] == some [true, false]
-- an advisory that states nothing is never left: "clear" there is no evidence
#guard judge (bytes "1.0") (bytes "1.1") [⟨none, []⟩] == some [false]
#guard judge (bytes "1.0") (bytes "1.1") [⟨some [], []⟩] == some [false]
#guard upgradeFor (bytes "16.14") [⟨some pg, []⟩, ⟨none, []⟩] == none
-- an empty list of ranges is no answer, as none is: the fixed versions decide
#guard verdict (bytes "1.0") ⟨some [], [bytes "2.0"]⟩ == .likely
#guard judge (bytes "1.0") (bytes "2.0") [⟨some [], [bytes "2.0"]⟩] == some [true]
-- PEP 440 boundaries, both ways round: 1.0 is 1.0.0
#guard verdict (bytes "1.0") ⟨some [⟨some (bytes "0.9"), some (bytes "1.0.0"), none⟩], []⟩ == .clear
#guard verdict (bytes "1.0.0") ⟨some [⟨some (bytes "0.9"), some (bytes "1.0"), none⟩], []⟩ == .clear
-- semver boundaries, both ways round: a pre-release is below its release, so a downgrade is never an upgrade
#guard verdict (bytes "15.0.0") ⟨some [⟨none, some (bytes "15.0.0-canary.12"), none⟩], []⟩ == .clear
#guard verdict (bytes "15.0.0-canary.12") ⟨some [⟨none, some (bytes "15.0.0"), none⟩], []⟩ == .inRange
#guard judge (bytes "15.0.0") (bytes "15.0.0-canary.12") [⟨some [⟨none, some (bytes "15.0.0"), none⟩], []⟩] == none
#guard judge (bytes "15.0.0-canary.12") (bytes "15.0.0") [⟨some [⟨none, some (bytes "15.0.0"), none⟩], []⟩] == some [true]
-- a pre-release is never suggested; a release named beside it is
#guard upgradeFor (bytes "2.2.0") [⟨some [⟨none, some (bytes "2.7.1-rc1"), none⟩], []⟩] == none
#guard upgradeFor (bytes "2.2.0") [⟨some [⟨none, some (bytes "2.7.1-rc1"), none⟩], [bytes "2.7.1"]⟩] == some (bytes "2.7.1")
-- Composer, GHSA-2ff6-837j-hg5x's [2.4.7-beta1, 2.4.7-p2): 2.4.7-p1 is inside it, so it does not fix 2.4.6-p3
#guard judge (bytes "2.4.6-p3") (bytes "2.4.7-p1") [⟨some [⟨some (bytes "2.4.7-beta1"), some (bytes "2.4.7-p2"), none⟩], []⟩] == some [false]
#guard judge (bytes "2.4.6-p3") (bytes "2.4.7-p2") [⟨some [⟨some (bytes "2.4.7-beta1"), some (bytes "2.4.7-p2"), none⟩], []⟩] == some [true]
#guard verdict (bytes "2.4.7-p1") ⟨some [⟨some (bytes "2.4.7-beta1"), some (bytes "2.4.7-p2"), none⟩], []⟩ == .inRange
#guard verdict (bytes "2.4.6-p3") ⟨some [⟨some (bytes "2.4.7-beta1"), some (bytes "2.4.7-p2"), none⟩], []⟩ == .clear
-- Go's stdlib, CVE-2024-45341: fixed in 1.22.11 and 1.23.5, and the 1.24.0 line closed by [1.24.0-0, 1.24.0-rc.2)
#guard verdict (bytes "1.24.0-rc.1") ⟨some [⟨none, some (bytes "1.22.11"), none⟩, ⟨some (bytes "1.23.0-0"), some (bytes "1.23.5"), none⟩, ⟨some (bytes "1.24.0-0"), some (bytes "1.24.0-rc.2"), none⟩], []⟩ == .inRange
#guard verdict (bytes "1.24.0") ⟨some [⟨none, some (bytes "1.22.11"), none⟩, ⟨some (bytes "1.23.0-0"), some (bytes "1.23.5"), none⟩, ⟨some (bytes "1.24.0-0"), some (bytes "1.24.0-rc.2"), none⟩], []⟩ == .clear
#guard verdict (bytes "1.23.4") ⟨some [⟨none, some (bytes "1.22.11"), none⟩, ⟨some (bytes "1.23.0-0"), some (bytes "1.23.5"), none⟩, ⟨some (bytes "1.24.0-0"), some (bytes "1.24.0-rc.2"), none⟩], []⟩ == .inRange
#guard verdict (bytes "1.23.5") ⟨some [⟨none, some (bytes "1.22.11"), none⟩, ⟨some (bytes "1.23.0-0"), some (bytes "1.23.5"), none⟩, ⟨some (bytes "1.24.0-0"), some (bytes "1.24.0-rc.2"), none⟩], []⟩ == .clear
-- Maven, guava fixed in 33.7.2: the core reads "-jre" as semver does, below the release, so it does not call
-- 33.7.2-jre a fix, where Maven would. Both versions are uncertain, so the app does not decide by the core's order.
#guard judge (bytes "31.1-jre") (bytes "33.7.2-jre") [⟨some [⟨none, some (bytes "33.7.2"), none⟩], []⟩] == some [false]
#guard versionUncertain (bytes "31.1-jre") && versionUncertain (bytes "33.7.2-jre")
#guard judge (bytes "31.1") (bytes "33.7.2") [⟨some [⟨none, some (bytes "33.7.2"), none⟩], []⟩] == some [true]

end OSVA
