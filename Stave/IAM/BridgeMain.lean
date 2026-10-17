import Stave.IAM.Bridge

def main (args : List String) : IO UInt32 := do
  match args with
  | [path] => IAM.Bridge.bridgeCheck path
  | _ =>
    IO.eprintln "Usage: iam-bridge-check <path-to-bridge.jsonl>"
    return 2
