# Running Gunna's Strat on a Chromebook

Chromebooks can't open the Mac (`.zip`) or Windows (`.exe`) versions. Instead, use
the **Linux** version, which runs inside the Chromebook's built-in Linux environment.
This is a one-time setup that takes about 10 minutes.

> Note: This works on most Chromebooks (Intel/AMD models). A small number of older or
> low-cost Chromebooks use ARM chips and may not run the Linux build — if it won't start,
> that's the likely reason.

---

## Step 1 — Turn on Linux (one time only)

1. Click the **clock** in the bottom-right corner, then the **gear** (Settings).
2. In the left menu, scroll down and click **Advanced → Developers**
   (on some Chromebooks it's just **About ChromeOS → Developers**).
3. Find **Linux development environment** and click **Turn on / Set up**.
4. Accept the defaults (username, and at least 10 GB of space) and let it install.
   A black **Terminal** window will open when it's done.

---

## Step 2 — Download the app

1. Open Chrome and go to:
   **https://github.com/NoahGun-stack/gunnas-strat/releases/latest**
2. Under **Assets**, download the file named **`Gunnas-Strat-linux`**.
3. Open the **Files** app. In the left sidebar you'll see **Linux files**.
4. Drag **`Gunnas-Strat-linux`** from your Downloads into **Linux files**.

---

## Step 3 — Run it

1. Open the **Terminal** app (search "Terminal" in your launcher; it appears after
   Step 1).
2. Type this and press Enter to allow the app to run:

   ```
   chmod +x Gunnas-Strat-linux
   ```

3. Then start it:

   ```
   ./Gunnas-Strat-linux
   ```

4. You'll see a line like:

   ```
   Gunna's Strat v5.4.0  →  http://127.0.0.1:5050
   ```

5. Open Chrome and go to **http://127.0.0.1:5050** — the app loads there.
   Log in, connect your TopstepX account, and trade as usual.

---

## Each day after that

You only do Steps 1 and 2 once. To use the app on later days:

1. Open the **Terminal** app.
2. Type:

   ```
   ./Gunnas-Strat-linux
   ```

3. Open Chrome to **http://127.0.0.1:5050**.

Keep the Terminal window open while you trade — closing it stops the app.

---

## Trouble?

- **"Permission denied"** when you run it → you skipped `chmod +x Gunnas-Strat-linux`. Run that first.
- **"cannot execute binary file"** → your Chromebook is likely an ARM model; the Linux
  build won't run on it. Use a Mac or Windows computer instead.
- **The page won't load at 127.0.0.1:5050** → make sure the Terminal still shows the app
  running and hasn't been closed.
