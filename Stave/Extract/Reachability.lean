import Stave.Extract.Asset

/-! Reachability extractor — BFS from anonymous principal through access
graph with auth/inspection boundary detection.
Produces properties.reachability.anonymous_path.* for CTL.EXPOSURE.ANON controls. -/

open Lean (Json)

namespace Extract.Reachability

/-- Node types in the access graph. -/
inductive NodeType where
  | anonymous
  | entryPoint
  | compute
  | identity
  | storage
  | network
  deriving BEq, DecidableEq

def NodeType.toString : NodeType → String
  | .anonymous => "anonymous"
  | .entryPoint => "entry_point"
  | .compute => "compute"
  | .identity => "identity"
  | .storage => "storage"
  | .network => "network"

/-- A node in the access graph. -/
structure GraphNode where
  nodeId : String
  nodeType : NodeType
  dataClassification : Option String := none
  fixHint : Option String := none
  deriving BEq

/-- An edge in the access graph (accessor → resource). -/
structure GraphEdge where
  source : String
  target : String
  deriving BEq

/-- Authentication boundary types. -/
inductive AuthBoundary where
  | cognito
  | lambdaAuthorizer
  | iam
  | mtls
  deriving BEq

def AuthBoundary.toString : AuthBoundary → String
  | .cognito => "cognito"
  | .lambdaAuthorizer => "lambda_authorizer"
  | .iam => "iam"
  | .mtls => "mtls"

/-- Inspection boundary types. -/
inductive InspectionBoundary where
  | waf
  | requestValidation
  deriving BEq

def InspectionBoundary.toString : InspectionBoundary → String
  | .waf => "waf"
  | .requestValidation => "api_gateway_request_validation"

/-- Result of BFS: a reachable path from anonymous to a target. -/
structure ReachablePath where
  target : GraphNode
  path : List GraphNode
  hopCount : Nat
  authBoundaries : List AuthBoundary
  inspectionBoundaries : List InspectionBoundary
  isFullyResolved : Bool
  unresolvedReason : Option String
  entryPointType : Option String
  deriving BEq

/-- A blocked path — BFS could not reach the target. -/
structure BlockedPath where
  target : GraphNode
  blockedAtId : String
  blockedAtType : NodeType
  reason : String
  deriving BEq

/-- BFS from the anonymous node.
Returns all reachable storage nodes with their shortest paths. -/
def bfsFromAnonymous (nodes : List GraphNode) (edges : List GraphEdge) (fuel : Nat := 100) :
    List ReachablePath :=
  let nodeMap := nodes.map fun n => (n.nodeId, n)
  let lookupNode (nid : String) : Option GraphNode := (nodeMap.find? fun (k, _) => k == nid).map (·.2)
  let rec go (queue : List (String × List GraphNode)) (visited : List String)
      (results : List ReachablePath) (remaining : Nat) :=
    match remaining, queue with
    | 0, _ => results
    | _, [] => results
    | remaining + 1, (current, pathSoFar) :: rest =>
      let neighbors := edges.filter (·.source == current) |>.map (·.target)
      let unvisited := neighbors.filter (!visited.contains ·)
      let newVisited := visited ++ unvisited
      let newEntries := unvisited.filterMap fun nid =>
        match lookupNode nid with
        | some node => some (nid, pathSoFar ++ [node])
        | none => none
      let newResults := newEntries.filterMap fun (_, p) =>
        match p.getLast? with
        | some last =>
          if last.nodeType == .storage then
            let entryPt := p.find? (·.nodeType == .entryPoint)
            some {
              target := last
              path := p
              hopCount := p.length
              authBoundaries := []
              inspectionBoundaries := []
              isFullyResolved := true
              unresolvedReason := none
              entryPointType := entryPt.map (·.nodeId)
            }
          else none
        | none => none
      go (rest ++ newEntries) newVisited (results ++ newResults) remaining
  let anonNode := nodes.find? (·.nodeType == .anonymous)
  match anonNode with
  | none => []
  | some anon => go [(anon.nodeId, [])] [anon.nodeId] [] fuel

/-- Annotate a path with detected auth and inspection boundaries. -/
def annotateBoundaries (p : ReachablePath) (authMap : List (String × AuthBoundary))
    (inspMap : List (String × InspectionBoundary)) : ReachablePath :=
  let nodeIds := p.path.map (·.nodeId)
  let authHits := authMap.filter fun (nid, _) => nodeIds.contains nid
  let inspHits := inspMap.filter fun (nid, _) => nodeIds.contains nid
  { p with
    authBoundaries := authHits.map (·.2)
    inspectionBoundaries := inspHits.map (·.2) }

/-- Transform reachable paths into obs.v0.1 assets. -/
def transformReachability (paths : List ReachablePath) : List ObsAsset :=
  paths.map fun p =>
    let pathSummary := p.path.map fun node =>
      Json.mkObj [
        ("node_type", .str node.nodeType.toString),
        ("id", .str node.nodeId),
        ("fix_hint", match node.fixHint with | some h => .str h | none => .null)
      ]
    let hasAuth := !p.authBoundaries.isEmpty
    let hasInsp := !p.inspectionBoundaries.isEmpty
    let classification := (p.target.dataClassification).getD "none"
    awsAsset p.target.nodeId "aws_s3_bucket"
      (Json.mkObj [("reachability", Json.mkObj [
        ("kind", .str "anonymous_path"),
        ("anonymous_path", Json.mkObj [
          ("reachable", .bool true),
          ("path_hop_count", .num p.hopCount),
          ("path_summary", Json.arr pathSummary.toArray),
          ("target_data_classification", .str classification),
          ("has_auth_boundary", .bool hasAuth),
          ("auth_boundary_types", Json.arr (p.authBoundaries.map fun b => .str b.toString).toArray),
          ("has_inspection_boundary", .bool hasInsp),
          ("inspection_boundary_types", Json.arr (p.inspectionBoundaries.map fun b => .str b.toString).toArray),
          ("is_fully_resolved", .bool p.isFullyResolved),
          ("unresolved_reason", match p.unresolvedReason with | some r => .str r | none => .null),
          ("entry_point_type", match p.entryPointType with | some e => .str e | none => .null),
          ("blocked_at", .null)
        ])
      ])])

/-- Transform blocked paths into negative-assurance assets. -/
def transformBlocked (blocked : List BlockedPath) : List ObsAsset :=
  blocked.map fun b =>
    awsAsset b.target.nodeId "aws_s3_bucket"
      (Json.mkObj [("reachability", Json.mkObj [
        ("kind", .str "anonymous_path"),
        ("anonymous_path", Json.mkObj [
          ("reachable", .bool false),
          ("blocked_at", Json.mkObj [
            ("node_type", .str b.blockedAtType.toString),
            ("id", .str b.blockedAtId),
            ("reason", .str b.reason)
          ])
        ])
      ])])

end Extract.Reachability

-- Self-tests

open Extract.Reachability in
#guard
  let nodes : List GraphNode := [
    { nodeId := "anonymous", nodeType := .anonymous },
    { nodeId := "apigateway:my-api", nodeType := .entryPoint },
    { nodeId := "lambda:my-fn", nodeType := .compute },
    { nodeId := "s3:my-bucket", nodeType := .storage, dataClassification := some "phi" }
  ]
  let edges : List GraphEdge := [
    { source := "anonymous", target := "apigateway:my-api" },
    { source := "apigateway:my-api", target := "lambda:my-fn" },
    { source := "lambda:my-fn", target := "s3:my-bucket" }
  ]
  let results := bfsFromAnonymous nodes edges
  match results with
  | [r] => r.hopCount == 3 && r.target.nodeId == "s3:my-bucket"
  | _ => false

-- No path to storage → empty
open Extract.Reachability in
#guard
  let nodes : List GraphNode := [
    { nodeId := "anonymous", nodeType := .anonymous },
    { nodeId := "apigateway:my-api", nodeType := .entryPoint }
  ]
  let edges : List GraphEdge := [
    { source := "anonymous", target := "apigateway:my-api" }
  ]
  (bfsFromAnonymous nodes edges).isEmpty

-- Boundary annotation
open Extract.Reachability in
#guard
  let p : ReachablePath := {
    target := { nodeId := "s3:bucket", nodeType := .storage }
    path := [
      { nodeId := "apigw:api", nodeType := .entryPoint },
      { nodeId := "lambda:fn", nodeType := .compute },
      { nodeId := "s3:bucket", nodeType := .storage }
    ]
    hopCount := 3
    authBoundaries := []
    inspectionBoundaries := []
    isFullyResolved := true
    unresolvedReason := none
    entryPointType := some "apigw:api"
  }
  let annotated := annotateBoundaries p [("apigw:api", .cognito)] [("apigw:api", .waf)]
  annotated.authBoundaries.length == 1 && annotated.inspectionBoundaries.length == 1
