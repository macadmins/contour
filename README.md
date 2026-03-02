# Contour

Unified macOS MDM configuration toolkit.

Contour consolidates domain-specific tools into a single CLI for generating, validating, and managing macOS MDM configurations:

- **profile** — Apple configuration profile toolkit (normalize, validate, sign)
- **pppc** — Privacy/TCC mobileconfig profile generator
- **santa** — Santa allowlist/blocklist toolkit
- **mscp** — mSCP security baseline transformation toolkit
- **btm** — Background Task Management profile generator
- **notifications** — Notification settings profile generator
- **support** — Root3 Support App profile generator

## Install

Download the latest `.pkg` from [Releases](https://github.com/headmin/contour/releases) and install. The binary is signed and notarized by Apple.

```bash
# Or install manually
sudo installer -pkg contour-*.pkg -target /
```

## Usage

```bash
contour --help
contour profile --help
contour pppc --help
contour santa --help
contour mscp --help
```

## License

Apache-2.0
