#!/bin/zsh
# Records all the app footage the film uses, from the demo build. Run it again after the UI changes.
# Needs dist/Hostwatch Demo.app (DEMO=1 ./scripts/build-app.sh) and Screen Recording allowed for this terminal.
# The demo window opens on screen for about ten seconds per shot. Output: .build/demo-video/shots/
set -e
R=${0:a:h:h:h}; D=${0:a:h}; W=$R/.build/demo-video
mkdir -p $W/shots

# start <scene> [ENV=VALUE ...]: opens the demo on a scene and waits for it to settle.
start() {
  local scene=$1; shift
  local envs=(); for e in "$@"; do envs+=(--env "$e"); done
  rm -rf $W/demo-data
  open -n "$R/dist/Hostwatch Demo.app" $envs --args --demo $W/demo-data $scene
  # A fresh build can take a while to show its window. Wait for it, then let the scene settle.
  for i in {1..20}; do
    swift $D/winid.swift "Hostwatch Demo" > $W/wins.txt
    [ -s $W/wins.txt ] && break
    sleep 1
  done
  sleep ${WAIT:-6}
  swift $D/winid.swift "Hostwatch Demo" > $W/wins.txt
}
stop() { pkill -f "Hostwatch Demo.app/Contents/MacOS/Hostwatch" || true; sleep 1 }
# The main window is on layer 0. A question panel floats above it on another layer.
main() { awk '$4 == 0' $W/wins.txt | sort -k2 -n -r | head -1 }
panel() { awk '$4 != 0' $W/wins.txt | sort -k2 -n -r | head -1 }
# still <name> <main|panel>: the window with its shadow, at the screen's own scale.
still() {
  local id=$($2 | cut -d' ' -f1)
  [ -n "$id" ] || { echo "no $2 window for $1"; stop; exit 1 }
  screencapture -x -l$id $W/shots/$1.png
  echo "captured $1"
}
# region <name> <main|panel> <margin>: the window's rectangle on screen plus a margin, for a floating panel that
# screencapture cannot take by window id. What is behind the panel shows in the margin.
region() {
  local w=($($2))
  [ -n "$w" ] || { echo "no $2 window for $1"; stop; exit 1 }
  screencapture -x -R$((w[5] - $3)),$((w[6] - $3)),$((w[2] + 2 * $3)),$((w[3] + 2 * $3)) $W/shots/$1.png
  echo "captured $1"
}
# clip <name> <seconds>: a recording of the main window's rectangle, without the shadow.
clip() {
  local w=($(main))
  [ -n "$w" ] || { echo "no window for $1"; stop; exit 1 }
  rm -f $W/shots/$1.mov
  screencapture -x -v -V $2 -R$w[5],$w[6],$w[2],$w[3] $W/shots/$1.mov
  echo "recorded $1"
}

# With no arguments the three shots the film takes fresh. Or name the ones to retake: capture.sh map live
# The firewall question is not in the default set: see docs/VIDEO.md before retaking it.
for shot in ${@:-protection map live}; do
  case $shot in
    protection) start protection;                      still protection main ;;
    map)        start map HOSTWATCH_DEMO_MEASURE=sent; still map-sent main ;;
    firewall)   start firewall;                        region firewall panel 23 ;;
    live)       start live;                            clip live 9 ;;
    *)          echo "unknown shot $shot"; exit 1 ;;
  esac
  stop
done
echo "Look at every file in $W/shots before building."
