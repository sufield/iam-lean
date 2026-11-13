import Stave.Extract.S3
import Stave.Extract.IAM
import Stave.Extract.EC2
import Stave.Extract.KMS
import Stave.Extract.CloudTrail
import Stave.Extract.RDS
import Stave.Extract.VPC
import Stave.Extract.Misc
import Stave.Extract.Escalation

/-! extract-cli — convert a directory of raw AWS CLI JSON into obs.v0.1 snapshots.

Usage:
  extract-cli <input-dir> <output-dir> [--account-id ID] [--region REGION]

Reads every .json file in <input-dir>, routes each to the appropriate
extractor by filename pattern, merges enrichment assets by ID, and writes
two obs.v0.1 snapshots (one hour apart) to <output-dir>.

Exit codes: 0 = wrote observations, 1 = no assets extracted, 2 = usage error -/

open Lean (Json ToJson)

/-- Get all key-value pairs from a JSON object via the public API. -/
private def jsonObjPairs (j : Json) : List (String × Json) :=
  match j with
  | .obj m => m.toArray.toList
  | _ => []

/-- Look up a key in a JSON object. -/
private def jsonObjGet (j : Json) (key : String) : Option Json :=
  match j.getObjValAs? Json key with
  | .ok v => some v
  | .error _ => none

/-- Deep-merge two JSON objects: when both sides have the same key and both
    values are objects, recurse; otherwise right wins. -/
partial def jsonDeepMerge (a b : Json) : Json :=
  match a, b with
  | .obj _, .obj _ =>
    let aPairs := jsonObjPairs a
    let bPairs := jsonObjPairs b
    let allKeys := (aPairs.map (·.1) ++ bPairs.map (·.1)).eraseDups
    let pairs := allKeys.map fun k =>
      let va := (jsonObjGet a k).getD Json.null
      let vb := (jsonObjGet b k).getD Json.null
      (k, match va, vb with
        | .obj _, .obj _ => jsonDeepMerge va vb
        | _, .null => va
        | _, _ => vb)
    Json.mkObj pairs
  | _, _ => b

/-- Merge an asset into an accumulator list. If an asset with the same
    id+type exists, deep-merge properties; otherwise append. -/
def mergeOne (acc : List ObsAsset) (a : ObsAsset) : List ObsAsset :=
  let key := a.id ++ ":" ++ a.assetType
  if acc.any (fun x => x.id ++ ":" ++ x.assetType == key) then
    acc.map fun x =>
      if x.id ++ ":" ++ x.assetType == key then
        { x with properties := jsonDeepMerge x.properties a.properties }
      else x
  else
    acc ++ [a]

def mergeAssets (assets : List ObsAsset) : List ObsAsset :=
  assets.foldl mergeOne []

/-- Strip a prefix and the .json suffix from a filename to get the entity name. -/
private def entityFromFilename (filename pfx : String) : String :=
  let s := (filename.drop pfx.length).toString
  if s.endsWith ".json" then
    String.ofList (s.toList.take (s.length - 5))
  else s

/-- Route a filename to the appropriate extractor(s). Returns extracted assets. -/
def extractFile (filename : String) (raw : Json) (accountId : String) : List ObsAsset :=
  -- S3
  if filename == "s3_buckets.json" then transformS3Buckets raw
  else if filename.startsWith "s3-encryption-" then
    (transformS3Encryption raw (entityFromFilename filename "s3-encryption-")).toList
  else if filename.startsWith "s3-public-access-" then
    (transformS3PublicAccessBlock raw (entityFromFilename filename "s3-public-access-")).toList
  else if filename.startsWith "s3-tags-" then
    (transformS3Tags raw (entityFromFilename filename "s3-tags-")).toList
  else if filename.startsWith "s3-versioning-" then
    (transformS3Versioning raw (entityFromFilename filename "s3-versioning-")).toList
  else if filename.startsWith "s3-logging-" then
    (transformS3Logging raw (entityFromFilename filename "s3-logging-")).toList
  else if filename.startsWith "s3-policy-" then
    (transformS3BucketPolicy raw (entityFromFilename filename "s3-policy-")).toList
  else if filename.startsWith "s3-lifecycle-" then
    (transformS3Lifecycle raw (entityFromFilename filename "s3-lifecycle-")).toList
  -- IAM
  else if filename == "iam_roles.json" then transformIAMRoles raw
  else if filename == "iam_users.json" then transformIAMUsers raw
  else if filename == "iam_groups.json" then transformIAMGroups raw
  else if filename == "iam_password_policy.json" then (transformIAMPasswordPolicy raw accountId).toList
  else if filename.startsWith "role-detail-" then
    let roleName := entityFromFilename filename "role-detail-"
    (transformIAMRoleAttachedPolicies raw ("arn:aws:iam::" ++ accountId ++ ":role/" ++ roleName)).toList
  else if filename.startsWith "role-attached-" then
    let roleName := entityFromFilename filename "role-attached-"
    (transformIAMRoleAttachedPolicies raw ("arn:aws:iam::" ++ accountId ++ ":role/" ++ roleName)).toList
  else if filename.startsWith "user-attached-" then
    let userName := entityFromFilename filename "user-attached-"
    (transformIAMUserAttachedPolicies raw ("arn:aws:iam::" ++ accountId ++ ":user/" ++ userName)).toList
  else if filename.startsWith "role-inline-" then
    let roleName := entityFromFilename filename "role-inline-"
    (transformIAMRoleInline raw ("arn:aws:iam::" ++ accountId ++ ":role/" ++ roleName)).toList
  else if filename.startsWith "group-inline-" then
    let groupName := entityFromFilename filename "group-inline-"
    (transformIAMGroupInline raw accountId ("arn:aws:iam::" ++ accountId ++ ":group/" ++ groupName)).toList
  else if filename.startsWith "user-inline-" then
    let userName := entityFromFilename filename "user-inline-"
    (transformIAMUserInline raw accountId ("arn:aws:iam::" ++ accountId ++ ":user/" ++ userName)).toList
  else if filename.startsWith "user-policy-" || filename.startsWith "group-policy-" || filename.startsWith "role-policy-" then
    (transformIAMInlinePolicy raw accountId).toList
  else if filename.startsWith "policy-doc-" then
    let policyName := entityFromFilename filename "policy-doc-"
    (transformManagedPolicyDoc raw accountId policyName).toList
  -- EC2
  else if filename == "ec2_volumes.json" then transformEC2Volumes raw accountId
  else if filename == "ec2_instances.json" then transformEC2Instances raw accountId
  else if filename == "ec2_security_groups.json" then transformEC2SecurityGroups raw
  else if filename.startsWith "sg-rules-" then
    let sgId := entityFromFilename filename "sg-rules-"
    let sgArn := "arn:aws:ec2:us-east-1:" ++ accountId ++ ":security-group/" ++ sgId
    (transformEC2SGRules raw sgArn).toList
  -- KMS
  else if filename == "kms_keys.json" then transformKMSKeys raw
  else if filename.startsWith "kms-rotation-" then
    let keyId := entityFromFilename filename "kms-rotation-"
    (transformKMSKeyRotation raw ("arn:aws:kms:us-east-1:" ++ accountId ++ ":key/" ++ keyId)).toList
  else if filename.startsWith "kms-key-" then
    let keyId := entityFromFilename filename "kms-key-"
    let keyArn := "arn:aws:kms:us-east-1:" ++ accountId ++ ":key/" ++ keyId
    -- kms-key-* can be describe-key (KeyMetadata) or get-key-policy (Policy)
    let describeAssets := (transformKMSDescribeKey raw).toList
    let policyAssets := (transformKMSKeyPolicy raw keyArn).toList
    describeAssets ++ policyAssets
  -- CloudTrail
  else if filename == "cloudtrail_trails.json" then transformCloudTrailTrails raw
  -- RDS
  else if filename == "rds_instances.json" then transformRDSInstances raw accountId
  else if filename.startsWith "rds-instance-" then transformRDSInstances raw accountId
  -- VPC
  else if filename == "vpc_flow_logs.json" then transformVPCFlowLogs raw accountId
  else if filename.startsWith "flow-logs-" then transformVPCFlowLogs raw accountId
  -- CloudFormation
  else if filename == "cfn_stacks.json" then transformCloudFormationStacks raw
  -- CloudWatch / Config / Lambda / OpenSearch
  else if filename == "cloudwatch_alarms.json" then transformCloudWatchAlarms raw
  else if filename == "config_recorders.json" then transformConfigRecorders raw accountId
  else if filename.startsWith "es_domain_" then (transformOpenSearchDomain raw).toList
  else if filename == "lambda_functions.json" then transformLambdaFunctions raw
  -- Unrecognized → skip
  else []

/-- Build an obs.v0.1 snapshot JSON. -/
def buildSnapshot (assets : List ObsAsset) (capturedAt : String) : Json :=
  Json.mkObj [
    ("schema_version", .str "obs.v0.1"),
    ("source", .str "deployed"),
    ("generated_by", Json.mkObj [
      ("source_type", .str "aws.cli")
    ]),
    ("captured_at", .str capturedAt),
    ("assets", Json.arr (assets.map ToJson.toJson).toArray)
  ]

/-- Parse --flag value pairs from args. -/
def parseFlag (args : List String) (flag : String) (default : String) : String :=
  match args.dropWhile (· != flag) with
  | _ :: v :: _ => v
  | _ => default

def main (args : List String) : IO UInt32 := do
  let positional := args.filter (!·.startsWith "--")
  if positional.length < 2 then
    IO.eprintln "Usage: extract-cli <input-dir> <output-dir> [--account-id ID] [--region REGION]"
    IO.eprintln ""
    IO.eprintln "Converts raw AWS CLI JSON files to obs.v0.1 observations."
    IO.eprintln "Reads every .json file in <input-dir>, writes two snapshots to <output-dir>."
    return 2
  let inputDir := positional[0]!
  let outputDir := positional[1]!
  let accountId := parseFlag args "--account-id" "unknown"
  let _region := parseFlag args "--region" "us-east-1"

  -- Read all .json files from input directory
  let entries ← System.FilePath.readDir inputDir
  let jsonFiles := entries.filter fun e => e.fileName.endsWith ".json"

  if jsonFiles.isEmpty then
    IO.eprintln s!"No .json files found in {inputDir}"
    return 2

  -- Extract assets from each file
  let mut allAssets : List ObsAsset := []
  let mut processed : Nat := 0
  let mut skipped : Nat := 0

  for entry in jsonFiles do
    let content ← IO.FS.readFile entry.path
    match Json.parse content with
    | .ok raw =>
      let assets := extractFile entry.fileName raw accountId
      if assets.isEmpty then
        skipped := skipped + 1
      else
        allAssets := allAssets ++ assets
        processed := processed + 1
    | .error e =>
      IO.eprintln s!"Parse error in {entry.fileName}: {e}"
      skipped := skipped + 1

  -- Merge enrichment assets by ID
  let merged := mergeAssets allAssets

  if merged.isEmpty then
    IO.eprintln s!"No assets extracted from {processed + skipped} files"
    return 1

  -- Post-processing: compute escalation paths from user→policy→actions
  -- Collect actions from both managed policies (by ARN) and inline policies (by principal name in ARN)
  let policyActions : List (String × List String) := merged.filterMap fun a =>
    if a.assetType == "aws_iam_policy" then
      let actions := getArr (getObj (getObj a.properties "identity") "policy") "actions"
      let strs := actions.filterMap fun j => match j with | Json.str s => some s | _ => none
      if strs.isEmpty then none else some (a.id, strs)
    else none
  -- Extract inline policy owner: arn:aws:iam::ACCT:inline-policy/PRINCIPAL/POLICY → PRINCIPAL
  let inlinePolicyOwner (policyArn : String) : Option String :=
    let parts := policyArn.splitOn ":inline-policy/"
    match parts with
    | [_, rest] => (rest.splitOn "/").head?
    | _ => none
  let principals : List Extract.Escalation.PrincipalPerms := merged.filterMap fun a =>
    if a.assetType == "aws_iam_user" || a.assetType == "aws_iam_role" then
      let identity := getObj a.properties "identity"
      -- Name from identity, or extract from ARN (arn:…:user/NAME or arn:…:role/NAME)
      let principalName := match getOptStr identity "name" with
        | some n => n
        | none => match (a.id.splitOn "/").getLast? with
          | some n => n
          | none => ""
      -- Actions from attached managed policies
      -- Match by policy name suffix because AWS-managed policies use
      -- arn:aws:iam::aws:policy/Name but we store them as arn:aws:iam::<acct>:policy/Name
      let policyNameOf (arn : String) : String :=
        match (arn.splitOn "/").getLast? with | some n => n | none => arn
      let attachedArns := (getArr identity "attached_policy_arns").filterMap fun j =>
        match j with | Json.str s => some s | _ => none
      let managedActions := attachedArns.flatMap fun pArn =>
        let pName := policyNameOf pArn
        match policyActions.find? (fun (storedArn, _) => policyNameOf storedArn == pName) with
        | some (_, acts) => acts
        | none => []
      -- Actions from inline policies (matched by principal name in ARN)
      let inlineActions := policyActions.flatMap fun (pArn, acts) =>
        match inlinePolicyOwner pArn with
        | some owner => if owner == principalName then acts else []
        | none => []
      let effectiveActions := managedActions ++ inlineActions
      if effectiveActions.isEmpty then none
      else
        let pType := if a.assetType == "aws_iam_user" then "user" else "role"
        let adminRoleArns := merged.filterMap fun r =>
          if r.assetType == "aws_iam_role" then
            let isAdmin := (getOptBool (getObj r.properties "identity") "is_admin_equivalent").getD false
            if isAdmin then some r.id else none
          else none
        some { arn := a.id, principalType := pType, effectiveActions, adminRoleArns }
    else none
  let escalationAssets := Extract.Escalation.transformEscalation principals

  -- Derive has_wildcard_s3_resource on user/role assets from policy actions+resource
  -- A principal has wildcard S3 resource if any of its policies grants s3:* on Resource: *
  let wildcardS3Assets : List ObsAsset := merged.filterMap fun a =>
    if a.assetType == "aws_iam_user" || a.assetType == "aws_iam_role" then
      let kind := if a.assetType == "aws_iam_user" then "user" else "role"
      let identity := getObj a.properties "identity"
      let principalName := match getOptStr identity "name" with
        | some n => n
        | none => match (a.id.splitOn "/").getLast? with
          | some n => n
          | none => ""
      -- Check inline policies for s3:* + Resource: *
      let hasWildcard := merged.any fun p =>
        if p.assetType != "aws_iam_policy" then false
        else
          let ownerMatch := match (p.id.splitOn ":inline-policy/") with
            | [_, rest] => (rest.splitOn "/").head? == some principalName
            | _ => false
          if !ownerMatch then false
          else
            let policy := getObj (getObj p.properties "identity") "policy"
            let actions := (getArr policy "actions").filterMap fun j =>
              match j with | .str s => some s | _ => none
            actions.any fun act => act == "s3:*" || act == "*"
      if hasWildcard then
        some (awsAsset a.id a.assetType
          (Json.mkObj [("identity", Json.mkObj [
            ("kind", .str kind),
            ("policies", Json.mkObj [
              ("has_wildcard_s3_resource", .bool true)
            ])
          ])]))
      else none
    else none

  -- Derive has_admin_policy on group assets from their inline policy actions
  let groupAdminAssets : List ObsAsset := merged.filterMap fun a =>
    if a.assetType != "aws_iam_group" then none
    else
      let groupName := match getOptStr (getObj (getObj a.properties "identity") "group") "name" with
        | some n => n
        | none => match (a.id.splitOn "/").getLast? with
          | some n => n
          | none => ""
      if groupName.isEmpty then none
      else
        let hasAdmin := merged.any fun p =>
          if p.assetType != "aws_iam_policy" then false
          else
            let ownerMatch := match (p.id.splitOn ":inline-policy/") with
              | [_, rest] => (rest.splitOn "/").head? == some groupName
              | _ => false
            if !ownerMatch then false
            else
              let policy := getObj (getObj p.properties "identity") "policy"
              let actions := (getArr policy "actions").filterMap fun j =>
                match j with | .str s => some s | _ => none
              actions.any (· == "*")
        if hasAdmin then
          some (awsAsset a.id "aws_iam_group"
            (Json.mkObj [("identity", Json.mkObj [("group", Json.mkObj [
              ("has_admin_policy", .bool true)
            ])])]))
        else none

  let final := mergeAssets (merged ++ escalationAssets ++ wildcardS3Assets ++ groupAdminAssets)
  let invalid := final.filter (!·.structurallyValid)
  if !invalid.isEmpty then
    IO.eprintln s!"Validation failed: {invalid.length} invalid asset(s)"
    for a in invalid do
      IO.eprintln s!"  id={a.id} type={a.assetType} vendor={a.vendor}"
    IO.eprintln "Fix the input files and re-run."
    return 1

  -- Write two snapshots (one hour apart, for duration-based controls)
  let t1 := "2026-01-01T12:00:00Z"
  let t2 := "2026-01-01T13:00:00Z"

  -- Ensure output directory exists
  IO.FS.createDirAll outputDir

  let snap1 := buildSnapshot final t1
  let snap2 := buildSnapshot final t2

  let path1 := s!"{outputDir}/2026-01-01T120000Z.json"
  let path2 := s!"{outputDir}/2026-01-01T130000Z.json"

  IO.FS.writeFile path1 (snap1.pretty 2 ++ "\n")
  IO.FS.writeFile path2 (snap2.pretty 2 ++ "\n")

  IO.println s!"Extracted {final.length} assets from {processed} files ({skipped} skipped)"
  IO.println s!"Wrote: {path1}"
  IO.println s!"Wrote: {path2}"
  return 0
