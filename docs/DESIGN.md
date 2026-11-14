# Hostwatch design rules

Read this before adding or changing anything you can see. The basis is Apple's Human Interface Guidelines for macOS
26 and later (Liquid Glass): <https://developer.apple.com/design/human-interface-guidelines>. These rules are what the
guidelines mean in this app, and what we learned building it. `DesignRules` in the test suite fails the merge gate on
the ones a machine can check.

## 1. Controls

- **Native first.** Use the system control that already does the job: Toggle for on and off, Picker for one of a few
  choices, Menu for several related actions, a Button for an action.
- **An action is a button, never a link.** Blue link text means "go somewhere" (a web page, help). Secondary actions
  use `.buttonStyle(.glass)` at `.controlSize(.small)`, and a view has at most one prominent action
  (`.glassProminent`). `.buttonStyle(.link)` fails the gate.
- **Two or more related actions on a row are one menu** with a labelled button ("Add Program" opening "Always Allow a
  Program…" and "Always Block a Program…"), not a row of buttons or links.
- **Segmented switches that need icons use `IconSegments`.** SwiftUI's segmented picker on macOS draws a label's text
  and drops its icon.
- **No unlabelled icon-only controls for a feature people must find.** A toolbar's standard icons are fine. Every
  icon-only control has `.help` and an accessibility label.
- **Destructive actions confirm** (an alert naming what goes and what stays), unless they're harmless and say so
  (Forget: "decisions stay, and anything that happens again comes back").

## 2. Colour

- **Text uses the semantic colours:** primary, secondary, tertiary. Never encode meaning in grey shades alone.
- **Selection is raised in the text colour, not the accent colour:** `Color.primary.opacity(0.16)` behind full-strength
  text (the tab bar, `IconSegments`, the rail). The user's accent can be graphite, which made accent-tinted selection
  look unselected.
- **Status colours are reserved:** red for stopped, blocked or critical, orange for attention and warnings, green for
  allowed or safe, grey for pending or a question. Always with an icon or a word, never colour alone.

## 3. Type

- **SF Pro for names and words.** Monospaced only for data: paths, patterns, IP addresses, command lines.
  Numbers that change use `.monospacedDigit()`.
- **Hierarchy:** `.headline` for a section title, the body size for a row's name, `.caption` in secondary for its
  explanation. A page explains itself in one or two caption lines under its title.

## 4. Layout

- **One decision per card.** Every card has the same anatomy: icon, title, a subtitle that says what it covers, the
  on and off switch at the trailing edge, then a second line with the choices ("Any other program [Ask me ▾]" and
  "Add Program"), then chips for what you added. Places and destinations share `PlaceChoices` and `ExceptionChips`.
  A new feature of the same kind reuses them.
- **Every page works from the minimum window (1,240 × 720 points) to full screen.** Nothing of fixed width may make a
  row wider than the minimum. Bars choose between a full and a compact version with `ViewThatFits` (captions dropped,
  icons alone), and scroll sideways as a last resort. Captions keep one line (`.lineLimit(1).fixedSize()`).
- **Grids of cards measure their width** and choose their columns (`ProtectionOverview.columns`). `ViewThatFits`
  measures text as one unwrapped line and gets this wrong.
- **Fill the window where the content is a dashboard** (charts take the spare height). Lists and forms keep their
  natural height.
- **A sidebar collapses to a rail of icons**, never disappears: where you are and what waits stay in view.

## 5. Liquid Glass

- **Glass is for controls, navigation and panels that float**, and for content cards the way macOS draws widgets
  (`protectionGlass`). Group glass on one page in a `GlassEffectContainer`.
- **Don't put glass on glass.** A form inside a glass card uses a plain quaternary fill.
- **Tint glass only to carry state** (the status panel's green, purple or orange, an orange warning panel).

## 6. Words

- **Plain language, no jargon.** Say what happens: "Any other program: Ask me", not "Others: Ask". Name the thing
  the way the person thinks of it.
- **Title case for buttons and menu items** ("Add Folder or File…"), sentence case for everything else.
- **An ellipsis when more input follows** ("Allow a Program…" opens a panel), none when the action happens at once.
- **No semicolons** in anything a person reads. Use a period or a comma.
- **Empty and off states say what to do next** ("Turn on Watch to see, hour by hour, what would be stopped.").

## 7. Feedback

- **Show waiting.** A check that takes seconds shows it is working and how long it may take (the AI notice's progress
  ring filling around its pulsing icon).
- **One question at a time.** One action never opens two panels. A second question waits for the first answer and
  says how they relate ("You just allowed curl to run.").
- **Numbers agree with what they summarise.** A card's figures are the totals of its chart, a badge counts what the
  page lists.

## 8. Charts

- Follow the HIG chart guidance: a summary value that describes the chart above it, one shared scale for charts shown
  side by side, a legend, a readable top on the axis, hover detail, and VoiceOver (per-bar labels and an
  `AXChartDescriptor` for Audio Graphs).

## 9. Accessibility

- Every control has an accessibility label, a selected state uses `.isSelected`, related text is combined into one
  element, and nothing depends on colour or hover alone.

## 10. Checking your work

- Build in debug and release (the release optimiser catches what debug accepts), run the related tests, and let the
  merge gate run the rest. Don't take screenshots to check UI unless you're asked: describe what changed so the
  person can look.
