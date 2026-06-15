#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  Build "Gunna's Strat.app"  (run this ON A MAC)
#  Produces a double-clickable .app in the dist/ folder.
# ─────────────────────────────────────────────────────────────
set -e
cd "$(dirname "$0")"

echo "==> Installing dependencies..."
pip3 install -r requirements.txt --break-system-packages 2>/dev/null \
  || pip3 install -r requirements.txt

echo "==> Cleaning previous builds..."
rm -rf build dist "Gunnas Strat.spec"

echo "==> Building app (this can take a minute)..."
pyinstaller --onefile --windowed --name "Gunnas Strat" \
  --hidden-import websocket \
  --collect-submodules tzdata \
  main.py

echo ""
echo "✅ Done!  Your app is at:  dist/Gunnas Strat.app"
echo "   Drag it to your Applications folder or Dock to keep it handy."
echo ""
echo "Note: the first time you open it, macOS may warn it's from an"
echo "unidentified developer. Right-click the app → Open → Open to allow it."
