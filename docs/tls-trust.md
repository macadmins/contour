# TLS trust after the eMudhra/emSign incident

Rebuild Contour from the committed `Cargo.lock` and redistribute the new
binary. Release builds use `--locked` so an old developer lockfile cannot
silently select a different TLS graph. The lock includes
`rustls-webpki 0.103.16` and `webpki-root-certs 1.0.10`, the fixed releases
for the compromised emSign paths. Updating Rust alone does not update
already shipped binaries.

There are also native trust paths:

* mSCP's Git HTTPS uses libgit2. Its Apple build uses Secure Transport and
  the macOS trust service; Windows uses WinHTTP. Apply current OS trust
  updates. On Linux it uses OpenSSL and the local CA store, which must be
  updated separately from the Contour binary.
* Build-time schema downloads invoke `curl`, which uses the build host's
  trust store. macOS's command-line PEM bundle can differ from the native
  trust service. Update the actual curl/OpenSSL bundle used by the builder.
* Custom CA files, additional roots, and explicit environment overrides need
  separate review. Rebuilding a binary does not repair them.

Use the distribution's patched `ca-certificates` package (or Homebrew's
updated `ca-certificates`) and verify both the direct and AAA cross-sign
paths are rejected by the actual client. A generic connection failure is
not proof of certificate rejection; establish that normal HTTPS works and
inspect the TLS error. Do not bypass certificate validation to make a
download succeed.

Fixed versions and test endpoints:
<https://emudhra.we-have-a-problem.com/#developers>.
