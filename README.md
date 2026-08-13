# encrypt-mule

A small web UI for encrypting and decrypting Mule YAML properties using the MuleSoft
`SecurePropertiesTool` (Blowfish/CBC). Paste plaintext YAML to encrypt, or ciphertext to decrypt.

## Download

Prebuilt binaries for Linux, macOS, and Windows are on the
[Releases](https://github.com/TylerTwoForks/encrypt-mule/releases) page.

1. Download the archive for your OS/arch (e.g. `encrypt-mule_1.0.1_darwin_arm64.tar.gz`, or the
   `.zip` on Windows).
2. Extract it.
3. Run the `encrypt` binary (double-click, or run it from a terminal).

The app starts a local server and **automatically opens your default browser** to
<http://localhost:1323>. If it doesn't, open that URL manually.

Check the version at any time:

```sh
./encrypt --version
```

## Requirements

- **Java must be installed** and on your `PATH`. The tool shells out to `java` to run the MuleSoft
  `SecurePropertiesTool`; it is not bundled. Verify with `java -version`.

## Development

```sh
make run        # templ generate + go run
make build      # generate templates and build the binary
```

Releases are produced automatically by [GoReleaser](https://goreleaser.com) via GitHub Actions
whenever a `v*` tag is pushed (see `.goreleaser.yaml` and `.github/workflows/release.yml`).
