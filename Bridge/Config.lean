import Bridge.Schema

/-! Contract version pin and fixture path conventions. -/

namespace Bridge.Config

def contractVersion : Bridge.Schema.SchemaVersion := ⟨"bridge", 0, 1⟩

def defaultFixtureDir : System.FilePath := "fixtures"

def fixturePaths : List (Bridge.Schema.Domain × System.FilePath) := [
  (.compose,  "fixtures/compose.jsonl"),
  (.network,  "fixtures/network.jsonl"),
  (.iam,      "fixtures/iam.jsonl"),
  (.xaccount, "fixtures/xaccount.jsonl"),
  (.celtype,  "fixtures/celtype.jsonl")
]

end Bridge.Config
