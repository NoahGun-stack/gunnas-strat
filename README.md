# Gunna's Strat

A local trading helper for TopstepX. Each user runs the app on their own
computer with their own TopstepX account — nothing trades from a server.
Access is controlled by a central license: the app validates every login
against the owner's server, so deactivating an account locks the app.

## Downloads

Grab the latest build from the **[Releases](../../releases/latest)** page:

- **Mac:** `Gunnas-Strat-mac.zip` — unzip, then right-click the app → **Open**
  → **Open** (first launch only, to get past the unidentified-developer notice).
- **Windows:** `Gunnas-Strat-windows.exe` — double-click. If SmartScreen warns,
  click **More info** → **Run anyway** (first launch only).

The app opens in your browser. Sign in with the username and password the
owner gave you.

## Building it yourself

Builds are produced automatically by GitHub Actions whenever a version tag
(e.g. `v1.0.0`) is pushed — see `.github/workflows/build.yml`. To build
locally instead:

- **Mac:** `bash build_mac.sh` → `dist/Gunnas Strat.app`
- **Windows:** run `build_windows.bat` → `dist\Gunnas Strat.exe`
