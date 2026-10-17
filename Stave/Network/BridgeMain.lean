import Stave.Network.Bridge

/-- CLI wrapper for the network bridge checker.
    Go source: bridge.jsonl produced from Go test expectations. -/
def main (args : List String) : IO UInt32 := do
  match args with
  | [path] => Network.Bridge.bridgeCheck path
  | _ =>
    IO.eprintln "Usage: network-bridge-check <path-to-bridge.jsonl>"
    return 2
