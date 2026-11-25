/-
  Version order (C: osva_vcmp).

  A version is read as a list of tokens, each turned into a key (a list of naturals), and two versions are compared
  key by key; a version that has run out reads as the key of "end of version" from then on:

    word after a "-"   [0, 0, bytes…]   a pre-release of an unknown kind: "15.0.0-canary.12", "2.0.0-next.3"
    pre-release word   [0, rank]        dev 1 · a, alpha 2 · b, beta 3 · c, rc, pre, preview 4
    end of version     [1]
    other word         [2, bytes…]      lowercase
    number             [3, digit count, digits…]   leading zeros dropped, so any length compares numerically

  so "1.0rc1" < "1.0" < "1.0.post1" < "1.0.1", "15.0.0-canary.12" < "15.0.0-rc.1" < "15.0.0", and "10.6" < "10.6p2".
  A word right after a "-" is a pre-release, as semver and PEP 440 read it, unless it is a post-release word PEP 440
  allows there ("1.0-post1", "-rev1", "-r1"); a number after a "-" is still a number ("7.1.1-41" > "7.1.1").

  The release numbers a version starts with lose the zeros that end them, keeping the first, so "1.0" = "1.0.0" = "1"
  and "1.0rc1" = "1.0.0rc1", as PEP 440 orders them. A leading "v" before a digit and everything from the first "+"
  (build metadata) are ignored; every byte that is not an ASCII letter or digit separates tokens.

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

/-- The post-release words PEP 440 allows after a "-" ("1.0-post1", "1.0-rev1", "1.0-r1"). -/
def isPostWord (w : Bytes) : Bool := w == bytes "post" || w == bytes "rev" || w == bytes "r"

/-- A word right after a "-": a pre-release, below every known kind unless it is one, or a post-release word. -/
def hyphenKey (w : Bytes) : List Nat :=
  if preRank w > 0 || isPostWord w then wordKey w else 0 :: 0 :: w.map (·.toNat)

def numKey (d : Bytes) : List Nat :=
  let s := stripZeros d
  3 :: s.length :: s.map (·.toNat)

def endKey : List Nat := [1]

/-- Between tokens (`hyp`: right after a "-"), in a number, in a word (`pre`: one that began right after a "-"). -/
inductive Mode where
  | sep | hyp | dig | alp | pre
  deriving DecidableEq

/-- Close the token being read (its bytes are kept reversed while reading). -/
def flush (m : Mode) (cur : Bytes) (acc : List (List Nat)) : List (List Nat) :=
  match m with
  | .sep | .hyp => acc
  | .dig => numKey cur.reverse :: acc
  | .alp => wordKey cur.reverse :: acc
  | .pre => hyphenKey cur.reverse :: acc

/-- One pass over the bytes: runs of digits and runs of letters become keys, everything else separates them. -/
def scan : Bytes → Mode → Bytes → List (List Nat) → List (List Nat)
  | [], m, cur, acc => (flush m cur acc).reverse
  | c :: t, m, cur, acc =>
    if isDigit c then
      if m = .dig then scan t .dig (c :: cur) acc else scan t .dig [c] (flush m cur acc)
    else if isAlpha c then
      if m = .alp ∨ m = .pre then scan t m (lower c :: cur) acc
      else scan t (if m = .hyp then .pre else .alp) [lower c] (flush m cur acc)
    else scan t (if c = 45 then .hyp else .sep) [] (flush m cur acc)

/-- Drop build metadata (from the first '+') and a leading 'v'/'V' before a digit. -/
def trimVersion (s : Bytes) : Bytes :=
  match s.takeWhile (· ≠ 43) with
  | c :: d :: t => if (c = 118 ∨ c = 86) ∧ isDigit d = true then d :: t else c :: d :: t
  | s' => s'

/-- The keys of a version as written, one per token. -/
def keys (s : Bytes) : List (List Nat) := scan (trimVersion s) .sep [] []

def isNumKey (k : List Nat) : Bool := k.head? == some 3

/-- The release numbers a version starts with lose the zeros that end them (`[3, 0]` is the key of any run of zeros),
  keeping the first: "1.0.0" reads as "1", "1.0rc1" as "1rc1", "0.0" as "0". -/
def trimRelease (ks : List (List Nat)) : List (List Nat) :=
  match ks.takeWhile isNumKey with
  | [] => ks
  | k :: rel => k :: (rel.reverse.dropWhile (· == [3, 0])).reverse ++ ks.dropWhile isNumKey

/-- The keys the order compares. -/
def tokens (s : Bytes) : List (List Nat) := trimRelease (keys s)

/-- No pre-release token: "2.7.1" and "1.0.post1" are releases; "2.7.1-rc1", "1.0.dev1" and "15.0.0-canary.12" are
  not. -/
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
#guard vcmp (bytes "1.0-post1") (bytes "1.0") == .gt              -- PEP 440's post-release spellings stay after it
#guard vcmp (bytes "1.0-post1") (bytes "1.0.post1") == .eq
#guard vcmp (bytes "7.1.1-41") (bytes "7.1.1") == .gt             -- a number after a "-" is still a number
#guard vcmp (bytes "1.1.1w") (bytes "1.1.1") == .gt               -- a word without a "-" is not a pre-release
#guard isRelease (bytes "2.7.1")
#guard isRelease (bytes "1.0.post1")
#guard isRelease (bytes "10.6p2")
#guard isRelease (bytes "7.1.1-41")
#guard !isRelease (bytes "2.7.1-rc1")
#guard !isRelease (bytes "1.0.dev1")
#guard !isRelease (bytes "15.0.0-canary.12")
#guard !isRelease (bytes "1.0a1")

end OSVA
