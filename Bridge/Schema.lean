/-! Unified schema types for the cross-repo bridge layer.
Wraps each per-domain bridge record under a common envelope
with schema version tracking. -/

namespace Bridge.Schema

structure SchemaVersion where
  domain : String
  major  : Nat
  minor  : Nat
  deriving Repr, DecidableEq, Inhabited

instance : ToString SchemaVersion where
  toString v := s!"{v.domain}.v{v.major}.{v.minor}"

def SchemaVersion.parse (s : String) : Option SchemaVersion :=
  -- Expected format: "domain.vMAJOR.MINOR"
  let parts := s.splitOn "."
  match parts with
  | [domain, vMajor, minor] =>
    if vMajor.startsWith "v" then
      match vMajor.drop 1 |>.toNat?, minor.toNat? with
      | some maj, some min => some ⟨domain, maj, min⟩
      | _, _ => none
    else none
  | _ => none

def supportedVersions : List SchemaVersion := [
  ⟨"compose", 0, 1⟩,
  ⟨"network", 0, 1⟩,
  ⟨"iam", 0, 1⟩,
  ⟨"xaccount", 0, 1⟩,
  ⟨"celtype", 0, 1⟩
]

def isSupported (v : SchemaVersion) : Bool :=
  supportedVersions.any fun s =>
    s.domain == v.domain && s.major == v.major && s.minor >= v.minor

def isCompatible (v : SchemaVersion) : Bool :=
  supportedVersions.any fun s =>
    s.domain == v.domain && s.major == v.major

inductive Domain where
  | compose
  | network
  | iam
  | xaccount
  | celtype
  deriving Repr, DecidableEq, Inhabited

def Domain.toString : Domain → String
  | .compose  => "compose"
  | .network  => "network"
  | .iam      => "iam"
  | .xaccount => "xaccount"
  | .celtype  => "celtype"

instance : ToString Domain where
  toString := Domain.toString

def Domain.fromString : String → Option Domain
  | "compose"  => some .compose
  | "network"  => some .network
  | "iam"      => some .iam
  | "xaccount" => some .xaccount
  | "celtype"  => some .celtype
  | _          => none

end Bridge.Schema
