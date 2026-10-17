import Stave.Compose.Bridge

/-- CLI wrapper for the bridge checker.
    Go source: bridge_gen.py produces the JSONL consumed here. -/
def main (args : List String) : IO UInt32 := do
  match args with
  | [path] => Compose.Bridge.bridgeCheck path
  | _ =>
    IO.eprintln "Usage: bridge-check <path-to-bridge.jsonl>"
    return 2
