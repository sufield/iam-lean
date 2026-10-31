import Lean.Data.Json

/-! obs.v0.1 asset — the universal output type for all extractors.
Shared JSON-navigation helpers live here so every transform file imports
one module instead of redefining private functions. -/

open Lean (Json ToJson FromJson)

-- JSON helpers (same signatures as KMS/Json.lean but not private)

def getOptBool (j : Json) (key : String) : Option Bool :=
  match j.getObjValAs? Bool key with
  | .ok v => some v
  | .error _ => none

def getOptStr (j : Json) (key : String) : Option String :=
  match j.getObjValAs? String key with
  | .ok v => some v
  | .error _ => none

def getOptNat (j : Json) (key : String) : Option Nat :=
  match j.getObjValAs? Nat key with
  | .ok v => some v
  | .error _ => none

def getObj (j : Json) (key : String) : Json :=
  match j.getObjValAs? Json key with
  | .ok v => v
  | .error _ => .null

def getArr (j : Json) (key : String) : List Json :=
  match j.getObjValAs? (Array Json) key with
  | .ok a => a.toList
  | .error _ => []

/-- An obs.v0.1 asset. -/
structure ObsAsset where
  id : String
  assetType : String
  vendor : String
  properties : Json
  deriving BEq

instance : ToJson ObsAsset where
  toJson a := Json.mkObj [
    ("id", .str a.id),
    ("type", .str a.assetType),
    ("vendor", .str a.vendor),
    ("properties", a.properties)
  ]

def ObsAsset.structurallyValid (a : ObsAsset) : Bool :=
  !a.id.isEmpty && !a.assetType.isEmpty && !a.vendor.isEmpty

/-- Build an asset with vendor fixed to "aws". -/
def awsAsset (id assetType : String) (properties : Json) : ObsAsset :=
  { id, assetType, vendor := "aws", properties }
