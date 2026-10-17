import Stave.Schema.Bridge

def main (args : List String) : IO UInt32 := do
  match args with
  | [path] => CelType.Bridge.bridgeCheck path
  | _ =>
    IO.eprintln "Usage: celtype-bridge-check <path-to-bridge.jsonl>"
    return 2
