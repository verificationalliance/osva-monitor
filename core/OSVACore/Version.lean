/-
  The core's version order (C: osva_vcmp), and which versions it may order differently from their ecosystem (C:
  osva_version_uncertain).

  A version is read as a list of tokens, each turned into a key (a list of naturals), and two versions are compared
  key by key; a version that has run out reads as the key of "end of version" from then on:

    "-0" pre-release   [0]              semver's lowest: "1.24.0-0" < "1.24.0-rc.2" < "1.24.0"
    word after a "-"   [0, 0, bytes…]   a pre-release of an unknown kind: "15.0.0-canary.12", "2.0.0-next.3"
    pre-release word   [0, rank]        dev 1 · a, alpha 2 · b, beta 3 · c, rc, pre, preview 4
    end of version     [1]              also "ga", "final" and "release" after a "-": "5.3.0-RELEASE" = "5.3.0"
    other word         [2, bytes…]      lowercase
    number             [3, digit count, digits…]   leading zeros dropped, so any length compares numerically

  so "1.0rc1" < "1.0" < "1.0.post1" < "1.0.1", "15.0.0-canary.12" < "15.0.0-rc.1" < "15.0.0" < "15.0.0-p1", and
  "10.6" < "10.6p2". A word right after a "-" is a pre-release, as semver reads it, unless it is a known pre-release
  word, a release-equal word (ga, final, release, as Maven reads them) or a post-release word (p, patch, pl, sp, r,
  post, rev, as Composer, Maven and PEP 440 read them), which stays after the release. A zero right after a "-" that
  ends the version or is followed by a "." starts a pre-release, as semver says, below every other: Go's "1.24.0-0"
  opens the 1.24.0 line, and its pseudo-versions "v1.2.4-0.20190101…-abcdef" lie below v1.2.4. Any other number after
  a "-" continues the version: ImageMagick's "7.1.1-41" is above "7.1.1".

  The release numbers a version starts with lose the zeros that end them, keeping the first, so "1.0" = "1.0.0" = "1"
  and "1.0rc1" = "1.0.0rc1", as PEP 440 orders them. A leading "v" before a digit and everything from the first "+"
  (build metadata) are ignored; every byte that is not an ASCII letter or digit separates tokens.

  Where it differs from an ecosystem's own order:
    · a number after a "-" other than that zero continues the version, where semver reads "1.0.0-1" as a
      pre-release, and Go puts a pseudo-version without a base tag ("v0.0.0-20191109021931-…") below v0.0.0;
    · any other word after a "-" ("-jre", "-android", "-incubating", "-rc1") is ordered as semver orders it, which
      Maven and Composer may not: `versionUncertain` names such versions, so the app need not trust this order for
      them.

  The theorems at the end say this is a total preorder for every pair (and triple) of byte strings: the order the
  rest of the app relies on can never call a version both older and newer than another.
-/
import OSVACore.Order

namespace OSVA

abbrev Bytes := List UInt8

/-- The bytes of a string literal, for the examples below. -/
def bytes (s : String) : Bytes := s.toUTF8.data.toList

def isDigit (c : UInt8) : Bool := 48 ≤ c && c ≤ 57
def isAlpha (c : UInt8) : Bool := (65 ≤ c && c ≤ 90) || (97 ≤ c && c ≤ 122)
def lower (c : UInt8) : UInt8 := if 65 ≤ c && c ≤ 90 then c + 32 else c

def stripZeros : Bytes → Bytes
  | [] => []
  | c :: t => if c = 48 then stripZeros t else c :: t

/-- Pre-release words (already lowercase): their rank, 0 for any other word. -/
def preRank (w : Bytes) : Nat :=
  if w = bytes "dev" then 1
  else if w = bytes "a" ∨ w = bytes "alpha" then 2
  else if w = bytes "b" ∨ w = bytes "beta" then 3
  else if w = bytes "c" ∨ w = bytes "rc" ∨ w = bytes "pre" ∨ w = bytes "preview" then 4
  else 0

def wordKey (w : Bytes) : List Nat :=
  let r := preRank w
  if r > 0 then [0, r] else 2 :: w.map (·.toNat)

/-- Post-release words after a "-" (already lowercase), each optionally followed by a number: Composer's "-p3",
  "-patch1", "-pl2", Maven's "-sp1", PEP 440's "-post1", "-rev1", "-r1". -/
def isPostWord (w : Bytes) : Bool :=
  w == bytes "p" || w == bytes "patch" || w == bytes "pl" || w == bytes "sp" || w == bytes "r" || w == bytes "post" ||
    w == bytes "rev"

/-- Words that mean the release itself after a "-", as Maven reads them: "-GA", "-Final", "-RELEASE". -/
def isReleaseWord (w : Bytes) : Bool := w == bytes "ga" || w == bytes "final" || w == bytes "release"

def numKey (d : Bytes) : List Nat :=
  let s := stripZeros d
  3 :: s.length :: s.map (·.toNat)

def endKey : List Nat := [1]

/-- A word right after a "-": the release itself for a release-equal word, after the release for a post-release word,
  its rank for a known pre-release word, and otherwise a pre-release below every known kind. -/
def hyphenKey (w : Bytes) : List Nat :=
  if isReleaseWord w then endKey
  else if preRank w > 0 || isPostWord w then wordKey w
  else 0 :: 0 :: w.map (·.toNat)

/-- Between tokens (`hyp`: right after a "-"), in a number (`hdg`: one that began right after a "-"), in a word
  (`pre`: one that began right after a "-"). `zero` only closes a token: semver's "-0" (see `closing`). -/
inductive Mode where
  | sep | hyp | dig | hdg | alp | pre | zero
  deriving DecidableEq

/-- Semver's "-0": a prefix of every other pre-release key, so below each of them. -/
def lowestPre : List Nat := [0]

/-- Close the token being read (its bytes are kept reversed while reading) into its key. -/
def flush (m : Mode) (cur : Bytes) (acc : List (List Nat)) : List (List Nat) :=
  match m with
  | .sep | .hyp => acc
  | .dig | .hdg => numKey cur.reverse :: acc
  | .alp => wordKey cur.reverse :: acc
  | .pre => hyphenKey cur.reverse :: acc
  | .zero => lowestPre :: acc

/-- Keep the token being read only if it is a word that began right after a "-". -/
def flushHyphenWord (m : Mode) (cur : Bytes) (acc : List Bytes) : List Bytes :=
  if m = .pre then cur.reverse :: acc else acc

/-- How the token being read is closed, given the byte after it (`none`: the end of the version). A number that began
  right after a "-" is a number, except a zero that ends the version or is followed by a ".", which is semver's "-0". -/
def closing (m : Mode) (cur : Bytes) (next : Option UInt8) : Mode :=
  if m = .hdg then (if cur.all (· == 48) && (next == none || next == some 46) then .zero else .dig) else m

theorem closing_ne_pre {m : Mode} {cur : Bytes} {x : Option UInt8} (h : m ≠ .pre) : closing m cur x ≠ .pre := by
  unfold closing
  split
  · split <;> simp
  · exact h

/-- One pass over the bytes: runs of digits and runs of letters are tokens, each closed by `fl`; everything else
  separates them. The order and `hyphenWords` both read a version with it, so they agree on what a word after a "-"
  is. -/
def scanBy {α : Type} (fl : Mode → Bytes → List α → List α) : Bytes → Mode → Bytes → List α → List α
  | [], m, cur, acc => (fl (closing m cur none) cur acc).reverse
  | c :: t, m, cur, acc =>
    if isDigit c then
      if m = .dig ∨ m = .hdg then scanBy fl t m (c :: cur) acc
      else scanBy fl t (if m = .hyp then .hdg else .dig) [c] (fl m cur acc)
    else if isAlpha c then
      if m = .alp ∨ m = .pre then scanBy fl t m (lower c :: cur) acc
      else scanBy fl t (if m = .hyp then .pre else .alp) [lower c] (fl (closing m cur (some c)) cur acc)
    else scanBy fl t (if c = 45 then .hyp else .sep) [] (fl (closing m cur (some c)) cur acc)

/-- Drop build metadata (from the first '+') and a leading 'v'/'V' before a digit. -/
def trimVersion (s : Bytes) : Bytes :=
  match s.takeWhile (· ≠ 43) with
  | c :: d :: t => if (c = 118 ∨ c = 86) ∧ isDigit d = true then d :: t else c :: d :: t
  | s' => s'

/-- The keys of a version as written, one per token. -/
def keys (s : Bytes) : List (List Nat) := scanBy flush (trimVersion s) .sep [] []

/-- The words of a version that begin right after a "-", lowercase. -/
def hyphenWords (s : Bytes) : List Bytes := scanBy flushHyphenWord (trimVersion s) .sep [] []

/-- The core may order this version differently from its ecosystem: it has a word right after a "-" that is neither
  a post-release word nor a release-equal one ("33.7.2-jre", "2.0.0-incubating", "1.0.0-rc.1"), which the core orders
  as semver does, below the release, and Maven may not; unless semver's "-0" already makes it a pre-release (Go's
  "1.24.0-0", "v1.2.4-0.20190101-abcdef"), which every ecosystem that writes it orders as the core does. -/
def versionUncertain (s : Bytes) : Bool :=
  !(keys s).contains lowestPre && (hyphenWords s).any fun w => !(isPostWord w || isReleaseWord w)

/-- What `versionUncertain` says: no "-0", and some word after a "-" is in neither list. -/
theorem versionUncertain_spec (s : Bytes) :
    versionUncertain s = true ↔
      lowestPre ∉ keys s ∧ ∃ w ∈ hyphenWords s, isPostWord w = false ∧ isReleaseWord w = false := by
  simp [versionUncertain]

theorem scanBy_hyphenWord_none (bs : Bytes) (m : Mode) (cur : Bytes) (hb : ∀ c ∈ bs, c ≠ 45) (hh : m ≠ .hyp)
    (hp : m ≠ .pre) : scanBy flushHyphenWord bs m cur [] = [] := by
  induction bs generalizing m cur with
  | nil => simp [scanBy, flushHyphenWord, closing_ne_pre hp]
  | cons c t ih =>
    have hc : c ≠ 45 := hb c (List.mem_cons_self ..)
    have ht : ∀ x ∈ t, x ≠ 45 := fun x hx => hb x (List.mem_cons_of_mem _ hx)
    have hf : flushHyphenWord m cur [] = [] := by simp [flushHyphenWord, hp]
    have hf' : ∀ x, flushHyphenWord (closing m cur x) cur [] = [] := fun x => by
      simp [flushHyphenWord, closing_ne_pre hp]
    simp only [scanBy, hf, hf', hh, hc, ite_false]
    split
    · split
      · exact ih m _ ht hh hp
      · exact ih .dig _ ht (by simp) (by simp)
    · split
      · split
        · rename_i hm
          exact ih m _ ht hh hp
        · exact ih .alp _ ht (by simp) (by simp)
      · exact ih .sep _ ht (by simp) (by simp)

theorem mem_trimVersion {s : Bytes} {c : UInt8} (h : c ∈ trimVersion s) : c ∈ s := by
  have hs : ∀ x ∈ s.takeWhile (· ≠ 43), x ∈ s := fun x hx => (List.takeWhile_sublist _).subset hx
  unfold trimVersion at h
  split at h
  · rename_i a b t heq
    rw [heq] at hs
    split at h
    · exact hs c (List.mem_cons_of_mem _ h)
    · exact hs c h
  · exact hs c h

/-- A version without a "-" is never uncertain: "1.2.3", "10.6p2" and "1.0rc1" are ordered as their ecosystems do. -/
theorem versionUncertain_without_hyphen {s : Bytes} (h : ∀ c ∈ s, c ≠ 45) : versionUncertain s = false := by
  have hw : hyphenWords s = [] :=
    scanBy_hyphenWord_none _ .sep [] (fun c hc => h c (mem_trimVersion hc)) (by simp) (by simp)
  simp [versionUncertain, hw]

def isNumKey (k : List Nat) : Bool := k.head? == some 3

/-- The release numbers a version starts with lose the zeros that end them (`[3, 0]` is the key of any run of zeros),
  keeping the first: "1.0.0" reads as "1", "1.0rc1" as "1rc1", "0.0" as "0". -/
def trimRelease (ks : List (List Nat)) : List (List Nat) :=
  match ks.takeWhile isNumKey with
  | [] => ks
  | k :: rel => k :: (rel.reverse.dropWhile (· == [3, 0])).reverse ++ ks.dropWhile isNumKey

/-- The keys the order compares. -/
def tokens (s : Bytes) : List (List Nat) := trimRelease (keys s)

/-- No pre-release token: "2.7.1", "1.0.post1", "2.4.6-p3" and "5.3.0-RELEASE" are releases; "2.7.1-rc1",
  "1.0.dev1" and "15.0.0-canary.12" are not. -/
def isRelease (s : Bytes) : Bool := !(tokens s).any (·.head? == some 0)

/-- Keys compared number by number; a shorter key is smaller than its extensions. -/
def keyCmp (a b : List Nat) : Ordering := lexE (optCmp natCmp) none (a.map some) (b.map some)

def vcmp (a b : Bytes) : Ordering := lexE keyCmp endKey (tokens a) (tokens b)

theorem keyCmp_tp : TotalPreorder keyCmp :=
  (lexE_tp (optCmp_tp natCmp_tp) none).pullback (fun (a : List Nat) => a.map some)

theorem vcmp_tp : TotalPreorder vcmp :=
  (lexE_tp keyCmp_tp endKey).pullback tokens

/-- Every version equals itself. -/
theorem vcmp_refl (a : Bytes) : vcmp a a = .eq := vcmp_tp.refl a

/-- Swapping the versions swaps the answer: a is older than b exactly when b is newer than a. -/
theorem vcmp_antisymm (a b : Bytes) : vcmp a b = (vcmp b a).swap := vcmp_tp.swap a b

/-- If a is at most b and b at most c, then a is at most c. -/
theorem vcmp_trans (a b c : Bytes) : vcmp a b ≠ .gt → vcmp b c ≠ .gt → vcmp a c ≠ .gt := vcmp_tp.trans a b c

/-- Strictly older is transitive too. -/
theorem vcmp_lt_trans {a b c : Bytes} (h1 : vcmp a b = .lt) (h2 : vcmp b c = .lt) : vcmp a c = .lt :=
  vcmp_tp.lt_of_lt_le h1 (by simp [h2])

/-! Examples, checked every time the core is built. -/
#guard vcmp (bytes "1.0rc1") (bytes "1.0") == .lt
#guard vcmp (bytes "1.0") (bytes "1.0.post1") == .lt
#guard vcmp (bytes "1.0.post1") (bytes "1.0.1") == .lt
#guard vcmp (bytes "10.6") (bytes "10.6p2") == .lt
#guard vcmp (bytes "10.6p1") (bytes "10.6p2") == .lt
#guard vcmp (bytes "1.31.5") (bytes "1.31.9") == .lt
#guard vcmp (bytes "1.9") (bytes "1.10") == .lt
#guard vcmp (bytes "2.0.0") (bytes "1.99.99") == .gt
#guard vcmp (bytes "v1.2.3") (bytes "1.2.3") == .eq
#guard vcmp (bytes "1.0+build.7") (bytes "1.0") == .eq
#guard vcmp (bytes "1.0a1") (bytes "1.0alpha1") == .eq
#guard vcmp (bytes "1.0.0-beta.2") (bytes "1.0.0-rc.1") == .lt
#guard vcmp (bytes "1.0.0-dev") (bytes "1.0.0-alpha") == .lt
#guard vcmp (bytes "007") (bytes "7") == .eq
-- trailing zeros of the release, both ways round (PEP 440: 1.0 == 1.0.0)
#guard vcmp (bytes "1.0") (bytes "1.0.0") == .eq
#guard vcmp (bytes "1.0.0") (bytes "1.0") == .eq
#guard vcmp (bytes "1.0rc1") (bytes "1.0.0rc1") == .eq
#guard vcmp (bytes "2") (bytes "2.0.1") == .lt
#guard vcmp (bytes "") (bytes "0") == .lt                         -- the first release number is kept
#guard vcmp (bytes "1.0.0-alpha") (bytes "1.0.0-alpha.0") == .lt  -- only the release loses its zeros
-- a word after a "-" is a pre-release, both ways round (semver: 15.0.0-canary.12 < 15.0.0)
#guard vcmp (bytes "15.0.0-canary.12") (bytes "15.0.0") == .lt
#guard vcmp (bytes "15.0.0") (bytes "15.0.0-canary.12") == .gt
#guard vcmp (bytes "2.0.0-next.3") (bytes "2.0.0") == .lt
#guard vcmp (bytes "15.0.0-canary.12") (bytes "15.0.0-rc.0") == .lt
#guard vcmp (bytes "15.0.0-canary.12") (bytes "15.0.0-canary.3") == .gt
#guard vcmp (bytes "15.0.0-canary.12") (bytes "14.2.3") == .gt
#guard vcmp (bytes "1.0-SNAPSHOT") (bytes "1.0") == .lt
-- post-release words after a "-" stay after the release, both ways round (Composer, Maven, PEP 440)
#guard vcmp (bytes "2.4.6-p3") (bytes "2.4.6") == .gt
#guard vcmp (bytes "2.4.6") (bytes "2.4.6-p3") == .lt
#guard vcmp (bytes "2.4.6-patch1") (bytes "2.4.6") == .gt
#guard vcmp (bytes "2.4.6") (bytes "2.4.6-patch1") == .lt
#guard vcmp (bytes "5.4-pl2") (bytes "5.4") == .gt
#guard vcmp (bytes "5.4") (bytes "5.4-pl2") == .lt
#guard vcmp (bytes "1.0-SP1") (bytes "1.0") == .gt
#guard vcmp (bytes "1.0") (bytes "1.0-SP1") == .lt
#guard vcmp (bytes "1.0-r1") (bytes "1.0") == .gt
#guard vcmp (bytes "1.0-rev1") (bytes "1.0") == .gt
#guard vcmp (bytes "1.0-post1") (bytes "1.0") == .gt
#guard vcmp (bytes "1.0") (bytes "1.0-post1") == .lt
#guard vcmp (bytes "1.0-post1") (bytes "1.0.post1") == .eq
#guard vcmp (bytes "2.4.6-p3") (bytes "2.4.7-beta1") == .lt
#guard vcmp (bytes "2.4.7-p1") (bytes "2.4.7-p2") == .lt
-- release-equal words after a "-" are the release, both ways round (Maven)
#guard vcmp (bytes "5.3.0-RELEASE") (bytes "5.3.0") == .eq
#guard vcmp (bytes "5.3.0") (bytes "5.3.0-RELEASE") == .eq
#guard vcmp (bytes "5.4.32-Final") (bytes "5.4.32") == .eq
#guard vcmp (bytes "1.0-GA") (bytes "1.0") == .eq
#guard vcmp (bytes "1.0-GA") (bytes "1.0-SP1") == .lt
#guard vcmp (bytes "1.0-GA") (bytes "1.0.1") == .lt
#guard vcmp (bytes "7.1.1-41") (bytes "7.1.1") == .gt             -- any other number after a "-" is still a number
#guard vcmp (bytes "7.1.1") (bytes "7.1.1-41") == .lt
-- semver's "-0", ending the version or followed by a ".": the lowest pre-release, both ways round (Go's release lines)
#guard vcmp (bytes "1.24.0-0") (bytes "1.24.0-rc.2") == .lt
#guard vcmp (bytes "1.24.0-rc.2") (bytes "1.24.0-0") == .gt
#guard vcmp (bytes "1.24.0-rc.2") (bytes "1.24.0") == .lt
#guard vcmp (bytes "1.24.0") (bytes "1.24.0-rc.2") == .gt
#guard vcmp (bytes "1.24.0-0") (bytes "1.24.0") == .lt
#guard vcmp (bytes "1.24.0") (bytes "1.24.0-0") == .gt
#guard vcmp (bytes "1.23.9") (bytes "1.24.0-0") == .lt
#guard vcmp (bytes "1.24.0-0") (bytes "1.24.0-canary.1") == .lt   -- below every other pre-release
#guard vcmp (bytes "1.24.0-0") (bytes "1.24.0-0.1") == .lt
-- Go pseudo-versions on a "-0." base are pre-releases of the next version, both ways round
#guard vcmp (bytes "v1.2.4-0.20190101-abcdef") (bytes "v1.2.4") == .lt
#guard vcmp (bytes "v1.2.4") (bytes "v1.2.4-0.20190101-abcdef") == .gt
#guard vcmp (bytes "v1.2.3") (bytes "v1.2.4-0.20190101-abcdef") == .lt
#guard vcmp (bytes "v1.2.4-0.20190101-abcdef") (bytes "v1.2.3") == .gt
#guard vcmp (bytes "v1.2.4-0.20190101-abcdef") (bytes "v1.2.4-0.20190202-123abc") == .lt
#guard !isRelease (bytes "1.24.0-0") && !isRelease (bytes "v1.2.4-0.20190101-abcdef")
#guard vcmp (bytes "1.1.1w") (bytes "1.1.1") == .gt               -- a word without a "-" is not a pre-release
#guard isRelease (bytes "2.7.1")
#guard isRelease (bytes "1.0.post1")
#guard isRelease (bytes "10.6p2")
#guard isRelease (bytes "7.1.1-41")
#guard !isRelease (bytes "2.7.1-rc1")
#guard !isRelease (bytes "1.0.dev1")
#guard !isRelease (bytes "15.0.0-canary.12")
#guard !isRelease (bytes "1.0a1")
#guard isRelease (bytes "2.4.6-p3") && isRelease (bytes "1.0-SP1") && isRelease (bytes "5.3.0-RELEASE")
-- which versions the core may order differently from their ecosystem
#guard versionUncertain (bytes "33.7.2-jre") && versionUncertain (bytes "31.1-android")
#guard versionUncertain (bytes "2.0.0-incubating") && versionUncertain (bytes "15.0.0-canary.12")
#guard versionUncertain (bytes "1.0.0-rc.1")                     -- a known pre-release word, but not on either list
#guard !versionUncertain (bytes "2.4.6-p3") && !versionUncertain (bytes "1.0-SP1") && !versionUncertain (bytes "5.3.0-RELEASE")
#guard !versionUncertain (bytes "1.2.3") && !versionUncertain (bytes "10.6p2") && !versionUncertain (bytes "1.0rc1")
#guard !versionUncertain (bytes "7.1.1-41") && !versionUncertain (bytes "1.0+build-jre")
#guard !versionUncertain (bytes "1.24.0-0") && !versionUncertain (bytes "v1.2.4-0.20190101-abcdef")

end OSVA
