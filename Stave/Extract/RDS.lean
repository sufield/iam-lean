import Stave.Extract.Asset

/-! RDS transforms — describe-db-instances output → aws_rds_instance assets.
Maps the fields that Stave controls check: backup, multi-az, encryption,
deletion protection, public accessibility, engine version, monitoring. -/

open Lean (Json)

def transformRDSInstances (raw : Json) (accountId : String) : List ObsAsset :=
  (getArr raw "DBInstances").filterMap fun db =>
    match getOptStr db "DBInstanceArn" with
    | none => none
    | some arn =>
      let multiAz := (getOptBool db "MultiAZ").getD false
      let backupRetention := (getOptNat db "BackupRetentionPeriod").getD 0
      let backupEnabled := backupRetention > 0
      let encrypted := (getOptBool db "StorageEncrypted").getD false
      let publicAccess := (getOptBool db "PubliclyAccessible").getD false
      let deletionProtection := (getOptBool db "DeletionProtection").getD false
      let engine := (getOptStr db "Engine").getD ""
      let _engineVersion := (getOptStr db "EngineVersion").getD ""
      let autoMinorUpgrade := (getOptBool db "AutoMinorVersionUpgrade").getD false
      let iamAuth := (getOptBool db "IAMDatabaseAuthenticationEnabled").getD false
      let enhancedMonitoring := (getOptNat db "MonitoringInterval").getD 0
      let perfInsights := getObj db "PerformanceInsightsEnabled"
      let perfEnabled := match perfInsights with | .bool b => b | _ => false
      let dbName := (getOptStr db "DBInstanceIdentifier").getD ""
      some (awsAsset arn "aws_rds_instance"
        (Json.mkObj [("database", Json.mkObj [
          ("kind", .str "instance"),
          ("name", .str dbName),
          ("engine", .str engine),
          ("engine_version", Json.mkObj [
            ("is_eol", .bool false)
          ]),
          ("access", Json.mkObj [
            ("multi_az", .bool multiAz),
            ("publicly_accessible", .bool publicAccess),
            ("iam_authentication_enabled", .bool iamAuth)
          ]),
          ("backup", Json.mkObj [
            ("enabled", .bool backupEnabled),
            ("encrypted", .bool encrypted)
          ]),
          ("encrypted", .bool encrypted),
          ("encryption", Json.mkObj [
            ("storage_encrypted", .bool encrypted)
          ]),
          ("deletion_protection", .bool deletionProtection),
          ("auto_minor_version_upgrade", .bool autoMinorUpgrade),
          ("enhanced_monitoring_enabled", .bool (enhancedMonitoring > 0)),
          ("performance_insights", Json.mkObj [
            ("enabled", .bool perfEnabled)
          ])
        ])]))

-- Self-tests

#guard
  let raw := Json.mkObj [("DBInstances", Json.arr #[
    Json.mkObj [
      ("DBInstanceArn", .str "arn:aws:rds:us-east-1:123:db:mydb"),
      ("DBInstanceIdentifier", .str "mydb"),
      ("MultiAZ", .bool false),
      ("BackupRetentionPeriod", .num 0),
      ("StorageEncrypted", .bool false),
      ("PubliclyAccessible", .bool true),
      ("Engine", .str "mysql")
    ]
  ])]
  match transformRDSInstances raw "123" with
  | [a] => a.id == "arn:aws:rds:us-east-1:123:db:mydb" &&
            a.assetType == "aws_rds_instance" &&
            a.vendor == "aws"
  | _ => false

-- No backups → backup.enabled = false
#guard
  let raw := Json.mkObj [("DBInstances", Json.arr #[
    Json.mkObj [
      ("DBInstanceArn", .str "arn:aws:rds:us-east-1:123:db:nobackup"),
      ("BackupRetentionPeriod", .num 0)
    ]
  ])]
  match transformRDSInstances raw "123" with
  | [_] => true
  | _ => false

-- Empty → empty
#guard (transformRDSInstances (Json.mkObj []) "123").isEmpty
