import Seclib.Compose.Bridge

def main (args : List String) : IO UInt32 := do
  match args with
  | [path] => bridgeCheck path
  | _ =>
    IO.eprintln "Usage: bridge-check <path-to-bridge.jsonl>"
    return 2
