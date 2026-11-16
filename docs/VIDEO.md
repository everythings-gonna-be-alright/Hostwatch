# The demo film

A square (1080 × 1080, 30 fps, silent) film of Hostwatch for social posts, in two cuts: 40 seconds and 60 seconds.
Everything that makes it lives in `scripts/demo-video/`. The films themselves go to `dist/`, which git ignores.

## Make it again

```bash
./scripts/demo-video/build.sh 40       # dist/hostwatch-demo-1x1.mp4
./scripts/demo-video/build.sh 60       # dist/hostwatch-demo-1x1-60s.mp4
```

Needs `ffmpeg` (Homebrew) and the Command Line Tools. A build takes about a minute. With no fresh footage it uses
the website's images, which is enough for the 40-second cut. The 60-second cut needs `capture.sh` run once.

## After the UI changes

```bash
DEMO=1 ./scripts/build-app.sh          # the demo build with the new UI
./scripts/demo-video/capture.sh        # records the Protection tab, the network map and the live clip again
open .build/demo-video/shots           # look at every shot before building
./scripts/demo-video/build.sh 40 && ./scripts/demo-video/build.sh 60
```

Then watch both films. A scene that uses a real window pushes in on one part of it and draws rings, dots and a
pointer on top, so it depends on where things are in the picture:

| Scene | Depends on | Where to adjust in `movie.swift` |
|---|---|---|
| `live` | the list filling the window from the left | the scale and offset in `live` |
| `mapScene` | the program box, the red line and the blocked destination | `path` (the line's points), the ring's corners, the zoom target `fx`, `fy` |
| `protectScene` | the Network card and its Off / Watch / Ask / Strict switch | the zoom target and the ring's rectangle |
| `firewall` | the Block button | the button's centre and rectangle |

All of those numbers are pixels of the picture at a fixed width (the table below). `build.sh` resizes every shot
to that width first, so a capture from a screen of another scale still lines up. If only colours or small details
changed, capturing again is enough. If things moved, open the shot, read the new positions and change the numbers.

The drawn scenes (`learnScene`, `watchScene`, `storyScene`, `guardScene`, `privacyScene`, intro, outro) use no
screenshot. They need a change only when the words or the facts change.

## The files

| File | What it does |
|---|---|
| `movie.swift` | Draws every frame with Core Graphics and writes raw RGBA to stdout. All scenes, words and timings are here. |
| `build.sh` | Gathers the footage at the right sizes, runs `movie.swift`, pipes the frames into `ffmpeg` (H.264, CRF 18). |
| `capture.sh` | Opens the demo build on a scene, captures its window or records it, quits it. Name shots to retake only those. |
| `winid.swift` | Lists the demo's windows for `capture.sh`. |

Working files go to `.build/demo-video/`: `shots/` (captures), `footage/` (what the build used), `render.log`.

## Where the pictures come from

All data is the made-up Mac of "alex" from the demo build (`src/hostwatch/Views/Demo.swift`). Nothing shows a real
user.

| Scene | File in `shots/` | Demo scene | Width the numbers use | Without a capture |
|---|---|---|---|---|
| `live` | `live.mov` (9 s recording) | `live` | 1736 | `docs/images/site/live.mp4` |
| `mapScene` | `map-sent.png` | `map` with `HOSTWATCH_DEMO_MEASURE=sent` | 1800 | `docs/images/site/map-sent.png` |
| `protectScene` | `protection.png` | `protection` | 2784 | none, capture it |
| `firewall` | `firewall.png` | `firewall` | 932 | `docs/images/site/firewall.png` |

The intro and outro use `assets/AppIcon.png`. Every other scene is drawn with SF Symbols.

**The firewall question is not captured by default.** The film uses the website's `firewall.png`. The question is
a floating panel that `screencapture` cannot take by window id, so `capture.sh firewall` takes a piece of the
screen instead. That piece has the demo window showing through the glass around the panel, which looks wrong on the
film's dark background. If the question's design changes, retake the website's image the way it was made (the panel
over a dark backdrop, 23 points of margin) and the film follows.

## The two cuts

The 40-second cut is a set of separate points. The 60-second cut tells one story about one app, so it has its own
order, a longer headline with a second line under it, and scenes that hand over to each other.

**40 seconds** (the `short` list in `movie.swift`)

| Scene (function) | Length | Words on screen |
|---|---|---|
| `intro` | 3.0 | Hostwatch. Security that understands your Mac |
| `live` | 6.0 | Watches every app. Green is normal. New gets a closer look |
| `storyScene` | 7.0 | One app goes rogue. Skipped Apple's safety check. Read your browser logins. Called an unknown server. Dangerous |
| `firewall` | 6.0 | New connection? You decide. Blocked |
| `mapScene` | 6.0 | See where your data goes. Stopped here |
| `watchScene` | 6.5 | Not sure about an app? 5 red flags. 6 warnings |
| `outro` | 5.5 | Hostwatch. Free · macOS 26 or later. hostwatch.tech |

**60 seconds** (the `long` list, `connected` is true)

| Scene (function) | Length | Headline | Second line | Hands over to the next scene by |
|---|---|---|---|---|
| `intro` | 3.2 | Hostwatch | Security that understands your Mac | |
| `live` | 6.0 | It watches every app | Every program, file and connection, live | |
| `learnScene` | 6.6 | And learns what's normal | Trusted apps stay quiet in the background | the new app's tile moves to the middle |
| `watchScene` | 6.6 | Not sure about the new one? | Watch it closely for one minute | the tile becomes the ring, then its icon flies to the story's header |
| `storyScene` | 7.6 | Here is what it really did | Small signs, joined into one story | the header card is already where the icon landed |
| `mapScene` | 6.4 | Its connection is blocked | The map shows where your data tried to go | |
| `firewall` | 6.4 | Anything else new waits | Nothing unknown connects without your OK | |
| `protectScene` | 6.2 | You choose how strict | Only watch, ask first, or block the unknown | |
| `guardScene` | 6.2 | It guards your AI agent too | Risky Claude Code commands are checked first | |
| `privacyScene` | 3.4 | And it all stays on your Mac | Private and encrypted | |
| `outro` | 5.4 | Hostwatch | Free · macOS 26 or later. hostwatch.tech | |

The labels inside the scenes are the same as in the 40-second cut, plus "7 trusted" and "1 new" in `learnScene` and
"Blocked before it ran" in `guardScene`.

In the connected cut each scene fades in over the last 0.4 s of the one before it, so the lengths above add up to
64 for a 60-second film. A thin line along the bottom edge shows how far the film has run.

The firewall question in the film is about `node`, not the rogue app. That is on purpose: Hostwatch does not ask
about a program it already calls Dangerous, it blocks it. So the story goes "its connection is blocked" (the map)
and then "anything else new waits" (the question).

To add a cut, add a list and a case in `build.sh`.

## Rules we settled on

These came from review of earlier cuts. Keep them when changing the film.

- **In the 40-second cut: one headline per scene, and at most one short label on screen at a time.** Second lines
  under the headline were removed because there was too much to read in that time.
- **In the 60-second cut: the scenes are one story.** Each headline continues the sentence before it ("It watches",
  "And learns", "Not sure about the new one?"), a second line adds one fact, and where it can the same object is
  carried from one scene into the next. This came from the review that separate slides felt unconnected.
- **No dense screenshots.** A full window of small text is hard to follow in a square. The attack story and Watch
  Closely scenes were real windows at first and were replaced with simple drawn pictures for that reason. A real
  window is fine when the film pushes in on one readable part (the firewall question, the map's blocked line, the
  Network card).
- **Every scene moves.** Things appear one at a time, the view pushes in, a pointer clicks, dots travel. No still
  slide with a slow pan.
- **Plain words for people who are not technical.** "Skipped Apple's safety check", not "quarantine removed".
- **The claims must be true of the app.** The numbers in the Watch scene (5 red flags, 6 warnings) are the demo's
  Watch Closely result. `rm -rf ~/Documents` is on the Claude Code guard's block list in
  `docs/reference/03-features.md`.
- **The outro holds for several seconds** so the name and the address can be read.

## How a scene is built

Each scene is a function of `t`, the seconds since the scene began. It draws the whole frame for that moment, so
there is no state between frames.

- `prog(t, start, duration)` gives 0 to 1 for one movement. `ease`, `easeOut` and `back` shape it.
- `caption(title, t:)` draws the headline band on top and a fade at the bottom. Call it after the picture and before
  the labels.
- `pill(...)` is a label, `card(...)` a rounded panel, `symbol(...)` an SF Symbol, `drawImg(...)` a screenshot with a
  scale, an offset and an optional clip.
- The timeline loop fades each scene in and out, so scenes need no transitions of their own.

The canvas is 1080 × 1080 with y growing downward. The headline band takes the top 212 pixels.

## Things that will trip you

- **Your own Hostwatch watches the capture.** With Protection on Ask, the real app can put a question about
  `screencapture` on screen in the middle of a shot. A shot of a piece of the screen then shows that question, with
  real session names in it. This happened once. Look at every shot before building, and never publish a film from
  shots you have not looked at.
- **Run the renderer through `swift`, not a compiled binary.** A binary built with `swiftc` in a temporary folder
  was killed at launch (exit 137) on the Mac this was made on. The cause was not found. `build.sh` uses the
  interpreter for that reason.
- **This `ffmpeg` has no `drawtext`.** That is why all text is drawn in Swift.
- **The demo window appears on screen while capturing.** Run `capture.sh` from the main terminal, which needs Screen
  Recording allowed. It takes about fifteen seconds per shot, and waits for a freshly built demo to show its window.
- **Pausing the script by hand leaves the demo open.** `pkill -f "Hostwatch Demo.app"` closes it.
