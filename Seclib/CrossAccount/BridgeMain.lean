import Seclib.CrossAccount.Bridge

def main (args : List String) : IO UInt32 := do
  match args with
  | [path] => bridgeCheck path
  | _ =>
    IO.eprintln "Usage: xaccount-bridge-check <path-to-bridge.jsonl>"
    return 2
