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
#print axioms affectedIn_unknown_iff
#print axioms affectedIn_sound
#print axioms affectedIn_complete
#print axioms affectedIn_outside
#print axioms affectedIn_fixed_above
#print axioms upgradeIn_above
#print axioms upgradeIn_clears
#print axioms upgradeIn_nearest
#print axioms upgradeIn_exists
#print axioms verdict_inRange_sound
#print axioms verdict_inRange_complete
#print axioms verdict_likely_spec
#print axioms leaves_sound
#print axioms upgradeFor_leaves
#print axioms upgradeFor_nearest
#print axioms judge_spec
#print axioms select_spec
#print axioms select_sound
#print axioms decode_encode
#print axioms encode_injective
#print axioms encode_alphabet
#print axioms encode_no_delimiters
#print axioms encode_length
#print axioms ffiVcmp_spec
#print axioms ffiAffected_one_iff
#print axioms ffiAffectedRanges_one_iff
#print axioms ffiUpgradeRanges_spec
#print axioms decodeRanges_get
#print axioms ffiEncode_spec
#print axioms ffiSelect_length
