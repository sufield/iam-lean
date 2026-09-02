import IamExplainer.Match
import IamExplainer.Checks
import IamExplainer.Policy

#guard matchPattern "s3:GetObject" "s3:GetObject" == true
#guard matchPattern "iam:PassRole" "iam:PassRole" == true
#guard matchPattern "" "" == true
#guard matchPattern "a" "a" == true

#guard matchActionPattern "IAM:PassRole" "iam:passrole" == true

#guard matchResourcePattern "arn:aws:s3:::Bucket" "arn:aws:s3:::bucket" == false

-- stmtGrantsAction: Action path
#guard stmtGrantsAction
  { effect := .allow, actions := some ["iam:PassRole"], index := 0 }
  "iam:PassRole" == true

-- stmtGrantsAction: NotAction complement grants PassRole
#guard stmtGrantsAction
  { effect := .allow, notActions := some ["s3:*"], index := 0 }
  "iam:PassRole" == true

-- stmtGrantsAction: NotAction excludes PassRole when iam:* listed
#guard stmtGrantsAction
  { effect := .allow, notActions := some ["iam:*"], index := 0 }
  "iam:PassRole" == false

-- stmtGrantsAction: bare wildcard matches PassRole
#guard stmtGrantsAction
  { effect := .allow, actions := some ["*"], index := 0 }
  "iam:PassRole" == true

-- Wildcard pattern matching
#guard matchPattern "*" "anything" == true
#guard matchPattern "s3:*" "s3:GetObject" == true
#guard matchPattern "s3:*" "iam:PassRole" == false
#guard matchPattern "?" "a" == true

-- Pin: star-skip (consume one input without advancing pattern)
#guard matchPattern "a*b" "axxxb" == true
#guard matchPattern "a*b" "ab" == true

-- Pin: star-consume (try consuming more input)
#guard matchPattern "a*" "aaa" == true
#guard matchPattern "*b" "xxxb" == true

-- Pin: consecutive stars
#guard matchPattern "**" "anything" == true
#guard matchPattern "a**b" "axxxb" == true

-- Pin: trailing star
#guard matchPattern "s3:Get*" "s3:GetObject" == true
#guard matchPattern "s3:Get*" "s3:Get" == true

-- Pin: empty pattern, empty input
#guard matchPattern "" "" == true

-- Pin: empty pattern, non-empty input
#guard matchPattern "" "something" == false

-- Pin: non-empty pattern, empty input
#guard matchPattern "a" "" == false

-- Pin: wildcard-free reflexivity (case-sensitive resource)
#guard matchResourcePattern "arn:aws:s3:::my-bucket" "arn:aws:s3:::my-bucket" == true
#guard matchResourcePattern "arn:aws:s3:::MyBucket" "arn:aws:s3:::mybucket" == false
