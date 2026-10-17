Prebuilt binaries for Linux, macOS and Windows on amd64 and arm64. Every archive is a single static binary built with `-tags with_utls`, plus the licence, both READMEs and the example configurations.

### Install

1. Download the archive for your platform below and unpack it.
2. Check it against `SHA256SUMS.txt`.
3. Run `shellshift doctor` to confirm the proof path works from your machine, then `shellshift run -config config.json -dry-run`.

You don't need a binary to *use* ShellShift: the subscriptions are published at https://tuftytech.github.io/ShellShift and work in any client that understands subscription URLs.

See the [README](https://github.com/TuftyTech/ShellShift#readme) for configuration and deployment.
