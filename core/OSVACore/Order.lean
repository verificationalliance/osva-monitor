/-
  Total preorders, and the one construction the version order is built from: comparing two lists element by element,
  the shorter one padded with an "end" element.

  A comparison `c : α → α → Ordering` is a total preorder when it is reflexive, antisymmetric (swapping the arguments
  swaps the answer) and transitive (a ≤ b and b ≤ c give a ≤ c). These are exactly the properties sorting and range
  checks rely on; a comparison without them can call one version both older and newer than another.
-/
namespace OSVA

/-- `o` is not `.gt`: "at most". -/
abbrev Ordering.isLe (o : Ordering) : Prop := o ≠ .gt

structure TotalPreorder {α : Type} (c : α → α → Ordering) : Prop where
  refl : ∀ a, c a a = .eq
  swap : ∀ a b, c a b = (c b a).swap
  trans : ∀ a b d, c a b ≠ .gt → c b d ≠ .gt → c a d ≠ .gt

namespace TotalPreorder
variable {α : Type} {c : α → α → Ordering}

theorem ne_lt_of_swap (h : TotalPreorder c) {a b} : c a b ≠ .lt ↔ c b a ≠ .gt := by
  rw [h.swap a b]; cases c b a <;> simp [Ordering.swap]

theorem eq_trans (h : TotalPreorder c) {a b d} (h1 : c a b = .eq) (h2 : c b d = .eq) : c a d = .eq := by
  have le1 : c a d ≠ .gt := h.trans a b d (by simp [h1]) (by simp [h2])
  have b1 : c b a = .eq := by rw [h.swap]; simp [h1, Ordering.swap]
  have b2 : c d b = .eq := by rw [h.swap]; simp [h2, Ordering.swap]
  have le2 : c d a ≠ .gt := h.trans d b a (by simp [b2]) (by simp [b1])
  have : c a d ≠ .lt := (h.ne_lt_of_swap).2 le2
  cases hc : c a d <;> simp_all

theorem lt_of_lt_le (h : TotalPreorder c) {a b d} (h1 : c a b = .lt) (h2 : c b d ≠ .gt) : c a d = .lt := by
  have le : c a d ≠ .gt := h.trans a b d (by simp [h1]) h2
  cases hc : c a d with
  | lt => rfl
  | gt => exact absurd hc le
  | eq =>
    -- c a d = eq, so d ≤ a; with b ≤ d this gives b ≤ a, contradicting a < b
    have da : c d a ≠ .gt := by rw [h.swap]; simp [hc, Ordering.swap]
    have ba : c b a ≠ .gt := h.trans b d a h2 da
    have : c a b ≠ .lt := (h.ne_lt_of_swap).2 ba
    exact absurd h1 this

theorem lt_of_le_lt (h : TotalPreorder c) {a b d} (h1 : c a b ≠ .gt) (h2 : c b d = .lt) : c a d = .lt := by
  have le : c a d ≠ .gt := h.trans a b d h1 (by simp [h2])
  cases hc : c a d with
  | lt => rfl
  | gt => exact absurd hc le
  | eq =>
    have da : c d a ≠ .gt := by rw [h.swap]; simp [hc, Ordering.swap]
    have db : c d b ≠ .gt := h.trans d a b da h1
    have : c b d ≠ .lt := (h.ne_lt_of_swap).2 db
    exact absurd h2 this

/-- Comparing through a function keeps a total preorder. -/
theorem pullback {β : Type} (h : TotalPreorder c) (f : β → α) : TotalPreorder (fun x y => c (f x) (f y)) where
  refl x := h.refl (f x)
  swap x y := h.swap (f x) (f y)
  trans x y z := h.trans (f x) (f y) (f z)

end TotalPreorder

/-- The natural numbers' own order. -/
def natCmp (a b : Nat) : Ordering := if a < b then .lt else if b < a then .gt else .eq

theorem natCmp_ne_gt {a b : Nat} : natCmp a b ≠ .gt ↔ a ≤ b := by
  unfold natCmp
  by_cases h1 : a < b
  · simp [h1]; omega
  · by_cases h2 : b < a
    · simp [h1, h2]
    · simp [h1, h2]; omega

theorem natCmp_tp : TotalPreorder natCmp where
  refl a := by simp [natCmp]
  swap a b := by
    unfold natCmp
    by_cases h1 : a < b
    · have : ¬ b < a := by omega
      simp [h1, this, Ordering.swap]
    · by_cases h2 : b < a
      · simp [h1, h2, Ordering.swap]
      · simp [h1, h2, Ordering.swap]
  trans a b d h1 h2 := by
    rw [natCmp_ne_gt] at *; omega

/-- Options: `none` (the end) below every `some`, `some`s compared by `c`. -/
def optCmp {α : Type} (c : α → α → Ordering) : Option α → Option α → Ordering
  | none, none => .eq
  | none, some _ => .lt
  | some _, none => .gt
  | some x, some y => c x y

theorem optCmp_tp {α : Type} {c : α → α → Ordering} (h : TotalPreorder c) : TotalPreorder (optCmp c) where
  refl a := by cases a <;> simp [optCmp, h.refl]
  swap a b := by
    cases a <;> cases b <;> simp only [optCmp, Ordering.swap]
    exact h.swap _ _
  trans a b d := by
    cases a <;> cases b <;> cases d <;> simp [optCmp] <;> exact h.trans _ _ _

/-! ### Element-by-element comparison of lists, the shorter padded with an end element `e` -/

/-- `then` as in `Ordering.then`: the first answer unless it is `.eq`. -/
theorem then_ne_gt {o o' : Ordering} : (o.then o') ≠ .gt ↔ (o = .lt ∨ (o = .eq ∧ o' ≠ .gt)) := by
  cases o <;> simp [Ordering.then]

theorem swap_then (o o' : Ordering) : (o.then o').swap = o.swap.then o'.swap := by
  cases o <;> cases o' <;> rfl

def hd {β : Type} (e : β) : List β → β
  | [] => e
  | x :: _ => x

def tl {β : Type} : List β → List β
  | [] => []
  | _ :: xs => xs

/-- Lists compared element by element; a list that has run out reads as `e` from then on. -/
def lexE {β : Type} (c : β → β → Ordering) (e : β) : List β → List β → Ordering
  | [], [] => .eq
  | x :: xs, [] => (c x e).then (lexE c e xs [])
  | [], y :: ys => (c e y).then (lexE c e [] ys)
  | x :: xs, y :: ys => (c x y).then (lexE c e xs ys)

variable {β : Type} {c : β → β → Ordering} {e : β}

/-- One step of the comparison, for every pair of lists (two empty lists included, since `c e e = .eq`). -/
theorem lexE_unfold (h : TotalPreorder c) (a b : List β) :
    lexE c e a b = (c (hd e a) (hd e b)).then (lexE c e (tl a) (tl b)) := by
  cases a <;> cases b <;> simp [lexE, hd, tl, h.refl, Ordering.then]

theorem lexE_refl (h : TotalPreorder c) : ∀ a : List β, lexE c e a a = .eq
  | [] => by simp [lexE]
  | x :: xs => by simp [lexE, h.refl, Ordering.then, lexE_refl h xs]

theorem lexE_swap (h : TotalPreorder c) : ∀ a b : List β, lexE c e a b = (lexE c e b a).swap
  | [], [] => by simp [lexE, Ordering.swap]
  | x :: xs, [] => by rw [lexE, lexE, swap_then, ← h.swap, ← lexE_swap h xs []]
  | [], y :: ys => by rw [lexE, lexE, swap_then, ← h.swap, ← lexE_swap h [] ys]
  | x :: xs, y :: ys => by rw [lexE, lexE, swap_then, ← h.swap, ← lexE_swap h xs ys]

theorem lexE_trans (h : TotalPreorder c) :
    ∀ (n : Nat) (a b d : List β), a.length + b.length + d.length ≤ n →
      lexE c e a b ≠ .gt → lexE c e b d ≠ .gt → lexE c e a d ≠ .gt
  | 0, a, b, d, hn, _, _ => by
    have ha : a = [] := List.eq_nil_of_length_eq_zero (by omega)
    have hd' : d = [] := List.eq_nil_of_length_eq_zero (by omega)
    subst ha; subst hd'; simp [lexE]
  | n + 1, a, b, d, hn, h1, h2 => by
    by_cases hz : a = [] ∧ b = [] ∧ d = []
    · obtain ⟨rfl, rfl, rfl⟩ := hz; simp [lexE]
    · rw [lexE_unfold h] at h1 h2 ⊢
      rw [then_ne_gt] at h1 h2 ⊢
      have hdec : (tl a).length + (tl b).length + (tl d).length ≤ n := by
        cases a <;> cases b <;> cases d <;> simp_all [tl] <;> omega
      rcases h1 with p | ⟨p, x⟩
      · -- a's head below b's, b's at most d's: a's head below d's
        left
        rcases h2 with q | ⟨q, _⟩
        · exact h.lt_of_lt_le p (by simp [q])
        · exact h.lt_of_lt_le p (by simp [q])
      · rcases h2 with q | ⟨q, y⟩
        · left; exact h.lt_of_le_lt (by simp [p]) q
        · right; exact ⟨h.eq_trans p q, lexE_trans h n _ _ _ hdec x y⟩

theorem lexE_tp (h : TotalPreorder c) (e : β) : TotalPreorder (lexE c e) where
  refl := lexE_refl h
  swap := lexE_swap h
  trans a b d := lexE_trans h _ a b d (Nat.le_refl _)

end OSVA
