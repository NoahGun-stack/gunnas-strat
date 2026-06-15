#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  Publish Gunna's Strat to GitHub and trigger a build.
#  Double-click this file (or run: bash publish.command).
#
#  First time only, it will ask you to sign in to GitHub in your
#  browser (via the GitHub CLI). After that, every run just pushes
#  a new version and GitHub builds the Mac + Windows apps for you.
# ─────────────────────────────────────────────────────────────
set -e
cd "$(dirname "$0")"

OWNER="NoahGun-stack"
REPO_NAME="gunnas-strat"
REPO_URL="https://github.com/$OWNER/$REPO_NAME.git"

# 1. Make sure the GitHub CLI is installed
if ! command -v gh >/dev/null 2>&1; then
  echo "The GitHub CLI (gh) isn't installed."
  echo "Install it with Homebrew:  brew install gh"
  echo "Then double-click this file again."
  exit 1
fi

# 2. Sign in if needed (opens your browser; you click to approve)
if ! gh auth status >/dev/null 2>&1; then
  echo "==> Signing you in to GitHub (a browser window will open)..."
  gh auth login
fi

# Make sure git can authenticate to GitHub using the gh login
gh auth setup-git >/dev/null 2>&1 || true

# 3. Initialise git here if it isn't already
if [ ! -d .git ]; then
  git init -b main
fi

# 4. Commit everything in this folder
git add .
git commit -m "Gunna's Strat release" || echo "(nothing new to commit)"

# 5. Point at the repo you already created and push
if ! git remote get-url origin >/dev/null 2>&1; then
  git remote add origin "$REPO_URL"
fi
git branch -M main
echo "==> Pushing files to $REPO_URL ..."
git push -u origin main

# 6. Tag a version so GitHub Actions builds and publishes the apps
read -p "Version to release [v1.0.0]: " VER
VER="${VER:-v1.0.0}"
git tag -f "$VER"
git push -f origin "$VER"

echo ""
echo "✅ Pushed $VER. GitHub is now building the Mac and Windows apps."
echo "   Watch progress and grab the downloads here in ~5 min:"
echo "   https://github.com/$OWNER/$REPO_NAME/releases"
