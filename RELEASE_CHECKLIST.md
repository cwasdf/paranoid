# Release Checklist

## Before Tagging

1. `npm run lint`
2. `npm run test:syntax`
3. Validate scanner launch on a macOS host.
4. Confirm `.env` is not tracked and no keys are committed.
5. Update `README.md` and `CHANGELOG.md` (if used) for notable changes.
6. Verify `LICENSE`, `SECURITY.md`, and `CONTRIBUTING.md` are present.

## GitHub Release

1. Create an annotated tag (for example, `v3.0.1`).
2. Push the tag and confirm CI passes.
3. Create the GitHub Release notes with:
   - Summary of behavior changes
   - Breaking changes (if any)
   - Upgrade notes
