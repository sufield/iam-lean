import Stave.Extract.Asset

/-! Exfiltration extractor — reverse reachability from sensitive resources
through compute to the internet. Pure function over already-collected data.
Produces properties.reachability.exfiltration.* for CTL.EXPOSURE.EXFIL controls. -/

open Lean (Json)

namespace Extract.Exfiltration

/-- Egress type for a compute instance's subnet. -/
inductive EgressType where
  | internetGateway
  | natGateway
  | vpcPeering
  | none
  deriving BEq

def EgressType.toString : EgressType → String
  | .internetGateway => "internet_gateway"
  | .natGateway => "nat_gateway"
  | .vpcPeering => "vpc_peering"
  | .none => "none"

def EgressType.hasInternet : EgressType → Bool
  | .internetGateway => true
  | .natGateway => true
  | .vpcPeering => true
  | .none => false

/-- A sensitive resource with its data classification. -/
structure SensitiveResource where
  arn : String
  assetType : String
  classification : String
  deriving BEq

/-- A compute instance that can read a sensitive resource. -/
structure ComputeReader where
  computeArn : String
  roleArn : String
  egress : EgressType
  hasWildcardWrite : Bool
  deriving BEq

/-- An exfiltration path: sensitive resource → compute → internet. -/
structure ExfilPath where
  resource : SensitiveResource
  reader : ComputeReader
  deriving BEq

/-- Identify sensitive resources from tagged assets. -/
def identifySensitive (assets : List Json) : List SensitiveResource :=
  let sensitiveValues := ["phi", "pii", "confidential"]
  assets.filterMap fun asset =>
    match getOptStr asset "id", getOptStr asset "type" with
    | some arn, some typ =>
      let tags := getArr (getObj asset "properties") "tags"
      let classification := tags.findSome? fun tag =>
        let key := (getOptStr tag "Key").getD ""
        let keyLower := String.ofList (key.toList.map Char.toLower)
        if keyLower == "data-classification" || keyLower == "data_classification" then
          getOptStr tag "Value"
        else none
      match classification with
      | some c => if sensitiveValues.contains (String.ofList (c.toList.map Char.toLower))
                  then some { arn, assetType := typ, classification := String.ofList (c.toList.map Char.toLower) }
                  else none
      | none => none
    | _, _ => none

/-- Determine egress type from route table routes. -/
def classifyEgress (routes : List Json) : EgressType :=
  let hasIgw := routes.any fun r =>
    match getOptStr r "GatewayId" with
    | some gw => "igw-".isPrefixOf gw
    | none => false
  let hasNat := routes.any fun r =>
    (getOptStr r "NatGatewayId").isSome
  let hasPeer := routes.any fun r =>
    (getOptStr r "VpcPeeringConnectionId").isSome
  if hasIgw then .internetGateway
  else if hasNat then .natGateway
  else if hasPeer then .vpcPeering
  else .none

/-- Transform exfiltration paths into obs.v0.1 assets. -/
def transformExfiltration (paths : List ExfilPath) : List ObsAsset :=
  paths.filterMap fun p =>
    if !p.reader.egress.hasInternet then none
    else some (awsAsset p.resource.arn p.resource.assetType
      (Json.mkObj [("reachability", Json.mkObj [
        ("kind", .str "exfiltration_path"),
        ("exfiltration", Json.mkObj [
          ("path_to_internet_exists", .bool true),
          ("vector", .str (if p.reader.hasWildcardWrite
            then "compute_with_igw_plus_wildcard_write"
            else "compute_with_internet_egress")),
          ("egress_type", .str p.reader.egress.toString),
          ("compute_id", .str p.reader.computeArn),
          ("has_wildcard_write", .bool p.reader.hasWildcardWrite),
          ("sensitive_data_readable", .bool true),
          ("target_data_classification", .str p.resource.classification)
        ])
      ])]))

end Extract.Exfiltration

-- Self-tests

open Extract.Exfiltration in
#guard classifyEgress [Json.mkObj [("GatewayId", .str "igw-abc123")]] == .internetGateway

open Extract.Exfiltration in
#guard classifyEgress [Json.mkObj [("NatGatewayId", .str "nat-xyz")]] == .natGateway

open Extract.Exfiltration in
#guard classifyEgress [Json.mkObj [("GatewayId", .str "local")]] == .none

open Extract.Exfiltration in
#guard
  let paths : List ExfilPath := [{
    resource := { arn := "arn:aws:s3:::phi-records", assetType := "aws_s3_bucket", classification := "phi" },
    reader := { computeArn := "arn:aws:ec2:us-east-1:123:instance/i-abc", roleArn := "arn:aws:iam::123:role/r", egress := .internetGateway, hasWildcardWrite := true }
  }]
  match transformExfiltration paths with
  | [a] => a.id == "arn:aws:s3:::phi-records" && a.assetType == "aws_s3_bucket"
  | _ => false

-- No internet egress → filtered out
open Extract.Exfiltration in
#guard
  let paths : List ExfilPath := [{
    resource := { arn := "arn:aws:s3:::data", assetType := "aws_s3_bucket", classification := "pii" },
    reader := { computeArn := "arn:aws:ec2:us-east-1:123:instance/i-xyz", roleArn := "arn:aws:iam::123:role/r", egress := .none, hasWildcardWrite := false }
  }]
  (transformExfiltration paths).isEmpty
