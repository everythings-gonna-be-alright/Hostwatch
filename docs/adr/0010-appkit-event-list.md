# 0010 The Events list is an AppKit outline view

**Context.** The Events list showed up to 5,000 rows in a SwiftUI `Table`. With a coding agent at work (50 events a
second and more) the window spent a quarter to half of a core on the list alone, measured with `sample`: each new
row at the top created eight `NSHostingView` cells, each row scrolling off tore eight down (`_removeRowsBeingAnimatedOff`,
`endUpdates`), and SwiftUI diffed the whole row list on every batch. Batching the updates (0.5 s) and caching the
derived rows cut the work around the list, not the list's own.

**Decision.** The live list is an `NSOutlineView` behind an `NSViewRepresentable` (`EventsTable`). Cells are plain
AppKit (`NSTextField`, `NSImageView`) that the outline view reuses; pills, tags and the agents' marks stay SwiftUI
views but are rendered once per look into images (`BadgeImages`) and shown in image views. Group rows use
AppKit's group-row style (one full-width cell, a band, floating while scrolling). The outline keeps selection and
expansion by row id across reloads, so a batch is one `reloadData()` with no animation. Sorting, selection and the
right-click menus go through the same model as before (`eventOrder`, `eventSelection`, `NSMenu`s built from the
same actions).

**Consequences.** Patterns, Rules, Stories and Network keep their SwiftUI tables: they don't churn. A badge whose
text varies (a heavy process's "380% · 2.1 GB") costs one render per distinct text, bounded by the cache. The list
no longer takes SwiftUI's `.contextMenu`/`.help` modifiers: tooltips are set on the cells, menus in
`EventMenus.swift`. Column widths are saved by AppKit (`autosaveName`).
