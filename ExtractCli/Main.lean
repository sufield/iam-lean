import Stave.Extract.S3
import Stave.Extract.IAM
import Stave.Extract.EC2
import Stave.Extract.KMS
import Stave.Extract.CloudTrail
import Stave.Extract.Misc

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

/-- Route a filename to the appropriate extractor(s). Returns extracted assets. -/
def extractFile (filename : String) (raw : Json) (accountId : String) : List ObsAsset :=
  -- S3
  if filename == "s3_buckets.json" then transformS3Buckets raw
  else if filename.startsWith "s3-encryption-" then (transformS3Encryption raw).toList
  else if filename.startsWith "s3-public-access-" then (transformS3PublicAccessBlock raw).toList
  else if filename.startsWith "s3-tags-" then (transformS3Tags raw).toList
  -- IAM
  else if filename == "iam_roles.json" then transformIAMRoles raw
  else if filename == "iam_users.json" then transformIAMUsers raw
  else if filename == "iam_groups.json" then transformIAMGroups raw
  else if filename == "iam_password_policy.json" then (transformIAMPasswordPolicy raw accountId).toList
  else if filename.startsWith "role-detail-" then (transformIAMRoleAttachedPolicies raw).toList
  else if filename.startsWith "group-inline-" then (transformIAMGroupInline raw accountId).toList
  else if filename.startsWith "user-inline-" then (transformIAMUserInline raw accountId).toList
  else if filename.startsWith "user-policy-" || filename.startsWith "group-policy-" || filename.startsWith "role-policy-" then
    (transformIAMInlinePolicy raw accountId).toList
  -- EC2
  else if filename == "ec2_volumes.json" then transformEC2Volumes raw accountId
  else if filename == "ec2_instances.json" then transformEC2Instances raw accountId
  else if filename == "ec2_security_groups.json" then transformEC2SecurityGroups raw
  -- KMS
  else if filename == "kms_keys.json" then transformKMSKeys raw
  else if filename.startsWith "kms-rotation-" then (transformKMSKeyRotation raw).toList
  else if filename.startsWith "kms-key-" then
    -- kms-key-<uuid>.json is describe-key; extract KeyArn for policy merge
    (transformKMSKeyPolicy raw).toList
  -- CloudTrail
  else if filename == "cloudtrail_trails.json" then transformCloudTrailTrails raw
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

  -- Write two snapshots (one hour apart, for duration-based controls)
  let t1 := "2026-01-01T12:00:00Z"
  let t2 := "2026-01-01T13:00:00Z"

  -- Ensure output directory exists
  IO.FS.createDirAll outputDir

  let snap1 := buildSnapshot merged t1
  let snap2 := buildSnapshot merged t2

  let path1 := s!"{outputDir}/2026-01-01T120000Z.json"
  let path2 := s!"{outputDir}/2026-01-01T130000Z.json"

  IO.FS.writeFile path1 (snap1.pretty 2 ++ "\n")
  IO.FS.writeFile path2 (snap2.pretty 2 ++ "\n")

  IO.println s!"Extracted {merged.length} assets from {processed} files ({skipped} skipped)"
  IO.println s!"Wrote: {path1}"
  IO.println s!"Wrote: {path2}"
  return 0
