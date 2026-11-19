/-
  The privacy filter (C: osva_select).

  The app downloads the public index of packages that have known problems and keeps everything else on the Mac:
  a package from the user's inventory may be sent to the API only if its key ("<ecosystem>\x1f<name>") is in that
  index. The theorem says the mask the app acts on is exactly that: true for an inventory key if and only if the key
  equals an index entry byte for byte. No other package can ever be marked for sending.

  The index is put into a hash set once (Lean's own `Std.HashSet`, whose lemmas are proved in Lean's library), so a
  scan of thousands of packages against tens of thousands of index entries stays fast.
-/
import Std.Data.HashSet
import OSVACore.Version

namespace OSVA

/-- For each inventory key: may it be sent (is it in the public index)? -/
def select (index inventory : List Bytes) : List Bool :=
  let s : Std.HashSet Bytes := Std.HashSet.ofList index
  inventory.map (fun k => s.contains k)

theorem select_length (index inventory : List Bytes) : (select index inventory).length = inventory.length := by
  simp [select]

/-- The mask is true exactly for the inventory keys that are in the index. -/
theorem select_spec (index inventory : List Bytes) (i : Nat) (h : i < inventory.length) :
    (select index inventory)[i]'(by simpa [select_length] using h) = true ↔ inventory[i] ∈ index := by
  simp [select]

/-- So whatever is marked for sending is in the public index. -/
theorem select_sound (index inventory : List Bytes) (i : Nat) (h : i < inventory.length)
    (hm : (select index inventory)[i]'(by simpa [select_length] using h) = true) : inventory[i] ∈ index :=
  (select_spec index inventory i h).1 hm

#guard select [bytes "npm\x1faxios", bytes "PyPI\x1frequests"] [bytes "npm\x1faxios", bytes "npm\x1fmy-private-thing"] == [true, false]
#guard select [] [bytes "npm\x1faxios"] == [false]

end OSVA
