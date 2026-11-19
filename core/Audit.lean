/-
  Which axioms each theorem rests on. scripts/check-core.sh fails unless every one uses only Lean's standard axioms
  (propext, Quot.sound, Classical.choice): no `sorry`, and no trust in compiled code (Lean.ofReduceBool).
-/
import OSVACore
open OSVA

#print axioms vcmp_refl
#print axioms vcmp_antisymm
#print axioms vcmp_trans
#print axioms vcmp_lt_trans
#print axioms affected_has_upgrade
#print axioms affected_not_when_fixed_on_branch
#print axioms affected_not_when_newest
#print axioms affected_unknown_without_fixes
#print axioms select_spec
#print axioms select_sound
#print axioms decode_encode
#print axioms encode_injective
#print axioms encode_alphabet
#print axioms encode_no_delimiters
#print axioms encode_length
#print axioms ffiVcmp_spec
#print axioms ffiAffected_one_iff
#print axioms ffiEncode_spec
#print axioms ffiSelect_length
