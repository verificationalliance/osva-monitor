/-
  Percent-encoding of one URL path component (C: osva_pct_encode).

  Every request the app makes is the fixed base https://verificationalliance.org/ followed by path components
  encoded here. RFC 3986 unreserved bytes (A-Z a-z 0-9 - . _ ~) are kept and every other byte becomes %XX.

  Theorems: the output contains only unreserved bytes, '%' and upper-case hex digits, so never '/', '?', '#', '@' or
  ':' — a package name cannot change the host, the path or the query of a request; decoding the output gives back
  the input, so two different names never encode alike; the output is at most three times as long as the input.
-/
import OSVACore.Version

namespace OSVA

def unreserved (c : UInt8) : Bool := isAlpha c || isDigit c || c == 45 || c == 46 || c == 95 || c == 126
def isHexUpper (c : UInt8) : Bool := (48 ≤ c && c ≤ 57) || (65 ≤ c && c ≤ 70)
def hexDigit (n : UInt8) : UInt8 := if n < 10 then 48 + n else 55 + n
def hexValRaw (h : UInt8) : UInt8 := if h ≤ 57 then h - 48 else h - 55

def encByte (c : UInt8) : Bytes := if unreserved c then [c] else [37, hexDigit (c / 16), hexDigit (c % 16)]

def pctEncode : Bytes → Bytes
  | [] => []
  | c :: t => encByte c ++ pctEncode t

/-- The inverse, used only to state what the encoding preserves. -/
def pctDecode : Bytes → Option Bytes
  | [] => some []
  | c :: t =>
    if c = 37 then
      match t with
      | h :: l :: r =>
        if isHexUpper h && isHexUpper l then (pctDecode r).map (fun rest => (hexValRaw h * 16 + hexValRaw l) :: rest)
        else none
      | _ => none
    else (pctDecode t).map (c :: ·)

/-- The decoder's two steps, as equations. -/
theorem pctDecode_cons_ne {c : UInt8} {t : Bytes} (hc : c ≠ 37) : pctDecode (c :: t) = (pctDecode t).map (c :: ·) := by
  rw [pctDecode.eq_def]; simp [hc]

theorem pctDecode_esc (h l : UInt8) (r : Bytes) :
    pctDecode (37 :: h :: l :: r) =
      if (isHexUpper h && isHexUpper l) = true then (pctDecode r).map (fun rest => (hexValRaw h * 16 + hexValRaw l) :: rest)
      else none := by
  rw [pctDecode.eq_2]; simp

/-! Facts about single bytes, checked by the kernel for all 256 values. -/
theorem forall_uint8 {P : UInt8 → Prop} (h : ∀ n : Fin 256, P (UInt8.ofNat n.val)) : ∀ c, P c := by
  intro c
  have := h ⟨c.toNat, c.toNat_lt⟩
  simpa using this

theorem hi_digit : ∀ c : UInt8, isHexUpper (hexDigit (c / 16)) = true ∧ hexValRaw (hexDigit (c / 16)) = c / 16 := by
  apply forall_uint8; decide +kernel

theorem lo_digit : ∀ c : UInt8, isHexUpper (hexDigit (c % 16)) = true ∧ hexValRaw (hexDigit (c % 16)) = c % 16 := by
  apply forall_uint8; decide +kernel

theorem split_byte : ∀ c : UInt8, c / 16 * 16 + c % 16 = c := by
  apply forall_uint8; decide +kernel

theorem percent_reserved : unreserved 37 = false := by decide

/-- No byte that may appear in the output is a delimiter. -/
def isDelimiter (c : UInt8) : Bool := c == 47 || c == 63 || c == 35 || c == 64 || c == 58   -- / ? # @ :

theorem unreserved_not_delimiter : ∀ c : UInt8, unreserved c = true → isDelimiter c = false := by
  apply forall_uint8; decide +kernel

theorem hex_not_delimiter : ∀ c : UInt8, isHexUpper c = true → isDelimiter c = false := by
  apply forall_uint8; decide +kernel

/-! The theorems. -/

/-- Decoding the encoding gives back the input: the encoding loses nothing and is injective. -/
theorem decode_encode : ∀ s : Bytes, pctDecode (pctEncode s) = some s
  | [] => rfl
  | c :: t => by
    have ih := decode_encode t
    unfold pctEncode encByte
    by_cases hu : unreserved c = true
    · have hc : c ≠ 37 := by intro h; subst h; simp [percent_reserved] at hu
      simp only [hu, ite_true, List.singleton_append]
      rw [pctDecode_cons_ne hc, ih]; rfl
    · have h1 := hi_digit c
      have h2 := lo_digit c
      simp only [hu, Bool.false_eq_true, ite_false, List.cons_append, List.nil_append]
      rw [pctDecode_esc]; simp [h1.1, h2.1, h1.2, h2.2, split_byte, ih]

theorem encode_injective {s t : Bytes} (h : pctEncode s = pctEncode t) : s = t := by
  have := decode_encode s
  rw [h, decode_encode t] at this
  exact (Option.some.inj this).symm

/-- The output alphabet: unreserved bytes, '%' and upper-case hex digits. -/
theorem encode_alphabet : ∀ (s : Bytes) (b : UInt8), b ∈ pctEncode s →
    unreserved b = true ∨ b = 37 ∨ isHexUpper b = true
  | [], _, h => by simp [pctEncode] at h
  | c :: t, b, h => by
    simp only [pctEncode, List.mem_append] at h
    rcases h with h | h
    · unfold encByte at h
      by_cases hu : unreserved c = true
      · simp [hu] at h; subst h; exact Or.inl hu
      · simp [hu] at h
        rcases h with h | h | h
        · exact Or.inr (Or.inl h)
        · subst h; exact Or.inr (Or.inr (hi_digit c).1)
        · subst h; exact Or.inr (Or.inr (lo_digit c).1)
    · exact encode_alphabet t b h

/-- So no output byte is '/', '?', '#', '@' or ':'. -/
theorem encode_no_delimiters (s : Bytes) (b : UInt8) (h : b ∈ pctEncode s) : isDelimiter b = false := by
  rcases encode_alphabet s b h with h | h | h
  · exact unreserved_not_delimiter b h
  · subst h; decide
  · exact hex_not_delimiter b h

theorem encode_length : ∀ s : Bytes, (pctEncode s).length ≤ 3 * s.length
  | [] => by simp [pctEncode]
  | c :: t => by
    have := encode_length t
    unfold pctEncode encByte
    split <;> simp <;> omega

#guard pctEncode (bytes "@scope/name") == bytes "%40scope%2Fname"
#guard pctEncode (bytes "1.2.3-rc.1") == bytes "1.2.3-rc.1"
#guard pctEncode (bytes "a b?#") == bytes "a%20b%3F%23"

end OSVA
