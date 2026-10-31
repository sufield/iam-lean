import Stave.Extract.Asset

/-! EC2 transforms — 3 jq filter equivalents:
  ec2-volumes, ec2-instances, ec2-security-groups.
  Account ID is required for ARN construction. -/

open Lean (Json)

-- Drop the last character of a string (AZ letter → region)
private def dropLast (s : String) : String :=
  if s.isEmpty then s
  else String.ofList (s.toList.dropLast)

-- ec2-volumes.jq: .Volumes[] → one aws_ebs_volume per volume
def transformEC2Volumes (raw : Json) (account : String) : List ObsAsset :=
  (getArr raw "Volumes").filterMap fun vol =>
    match getOptStr vol "VolumeId", getOptStr vol "AvailabilityZone" with
    | some vid, some az =>
      let region := dropLast az
      let attached := (getArr vol "Attachments").length > 0
      let isError := getOptStr vol "State" == some "error"
      let isGp2 := getOptStr vol "VolumeType" == some "gp2"
      let encrypted := (getOptBool vol "Encrypted").getD false
      some (awsAsset
        ("arn:aws:ec2:" ++ region ++ ":" ++ account ++ ":volume/" ++ vid)
        "aws_ebs_volume"
        (Json.mkObj [("compute", Json.mkObj [
          ("kind", .str "volume"),
          ("ebs", Json.mkObj [
            ("attached", .bool attached),
            ("is_error_state", .bool isError),
            ("is_gp2", .bool isGp2),
            ("encrypted", .bool encrypted)
          ])
        ])]))
    | _, _ => none

-- ec2-instances.jq: .Reservations[].Instances[] → one aws_ec2_instance per instance
def transformEC2Instances (raw : Json) (account : String) : List ObsAsset :=
  (getArr raw "Reservations").flatMap fun reservation =>
    (getArr reservation "Instances").filterMap fun inst =>
      match getOptStr inst "InstanceId" with
      | none => none
      | some iid =>
        let az := (getOptStr (getObj inst "Placement") "AvailabilityZone").getD ""
        let region := dropLast az
        let hasPublicIp := (getOptStr inst "PublicIpAddress").isSome
        let metaOpts := getObj inst "MetadataOptions"
        let imdsv2 := getOptStr metaOpts "HttpTokens" == some "required"
        some (awsAsset
          ("arn:aws:ec2:" ++ region ++ ":" ++ account ++ ":instance/" ++ iid)
          "aws_ec2_instance"
          (Json.mkObj [("compute", Json.mkObj [
            ("kind", .str "instance"),
            ("network", Json.mkObj [
              ("has_public_ip", .bool hasPublicIp),
              ("imdsv2_required", .bool imdsv2)
            ])
          ])]))

-- ec2-security-groups.jq: .SecurityGroups[] → one aws_ec2_security_group per SG

private def isInternet (perm : Json) : Bool :=
  (getArr perm "IpRanges").any fun r =>
    getOptStr r "CidrIp" == some "0.0.0.0/0"

private def highRiskPorts : List Nat := [22, 3389, 3306, 5432, 1433, 1521, 27017, 2049]

private def parseCidrMask (cidr : String) : Option Nat :=
  let parts := cidr.splitOn "/"
  match parts with
  | [_, mask] => String.toNat? mask
  | _ => none

def transformEC2SecurityGroups (raw : Json) : List ObsAsset :=
  (getArr raw "SecurityGroups").filterMap fun sg =>
    match getOptStr sg "SecurityGroupArn" with
    | none => none
    | some arn =>
      let perms := getArr sg "IpPermissions"
      let hasBroadPortRange := perms.any fun r =>
        let proto := (getOptStr r "IpProtocol").getD ""
        (proto == "tcp" || proto == "udp") &&
        getOptNat r "FromPort" != getOptNat r "ToPort" &&
        isInternet r
      let highRiskExposed := perms.any fun r =>
        match getOptNat r "FromPort", getOptNat r "ToPort" with
        | some fp, some tp =>
          fp == tp && isInternet r && highRiskPorts.contains fp
        | _, _ => false
      let icmpAll := perms.any fun r =>
        getOptStr r "IpProtocol" == some "icmp" && isInternet r
      let hasBroadCidr := perms.any fun r =>
        getOptStr r "IpProtocol" == some "-1" &&
        (getArr r "IpRanges").any fun range =>
          match getOptStr range "CidrIp" with
          | some cidr =>
            match parseCidrMask cidr with
            | some n => n < 32
            | none => false
          | none => false
      some (awsAsset arn "aws_ec2_security_group"
        (Json.mkObj [("network", Json.mkObj [
          ("kind", .str "security_group"),
          ("security_group", Json.mkObj [
            ("has_broad_port_range", .bool hasBroadPortRange),
            ("high_risk_ports_exposed", .bool highRiskExposed),
            ("icmp_all_types_from_internet", .bool icmpAll),
            ("has_broad_cidr", .bool hasBroadCidr)
          ])
        ])]))

-- Self-tests

#guard
  let raw := Json.mkObj [("Volumes", Json.arr #[
    Json.mkObj [
      ("VolumeId", .str "vol-123"),
      ("AvailabilityZone", .str "us-east-1a"),
      ("Encrypted", .bool true),
      ("VolumeType", .str "gp3"),
      ("State", .str "available"),
      ("Attachments", Json.arr #[])
    ]
  ])]
  match transformEC2Volumes raw "123456789012" with
  | [a] => a.id == "arn:aws:ec2:us-east-1:123456789012:volume/vol-123" &&
            a.assetType == "aws_ebs_volume" && a.vendor == "aws"
  | _ => false

#guard
  let raw := Json.mkObj [("SecurityGroups", Json.arr #[
    Json.mkObj [
      ("SecurityGroupArn", .str "arn:aws:ec2:us-east-1:123:security-group/sg-abc"),
      ("IpPermissions", Json.arr #[
        Json.mkObj [
          ("IpProtocol", .str "tcp"),
          ("FromPort", .num 22),
          ("ToPort", .num 22),
          ("IpRanges", Json.arr #[Json.mkObj [("CidrIp", .str "0.0.0.0/0")]])
        ]
      ])
    ]
  ])]
  match transformEC2SecurityGroups raw with
  | [a] => a.assetType == "aws_ec2_security_group" && a.vendor == "aws"
  | _ => false
