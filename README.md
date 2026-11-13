# gadgethunt

A static gadget-chain hunter for a small deserialized-object IR (binobj). It has to follow field stores, polymorphism, magic aliases, and sanitizer kinds.

`python -m gadgethunt inspect --program fixtures/programs/direct-exec.json --policy fixtures/policy.json` already lists classes. `hunt` is still a stub.

Standard library only. No Docker, no pickle, do not eval the IR as Python.
