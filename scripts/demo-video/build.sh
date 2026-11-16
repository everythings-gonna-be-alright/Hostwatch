#!/bin/zsh
# Builds the square demo film. Usage: scripts/demo-video/build.sh [40|60]   (default 40)
# Output: dist/hostwatch-demo-1x1.mp4 (40 s) or dist/hostwatch-demo-1x1-60s.mp4. Needs ffmpeg.
# Footage comes from capture.sh (.build/demo-video/shots), or from the website's images where a shot is missing.
# docs/VIDEO.md has the whole story.
set -e
R=${0:a:h:h:h}; D=${0:a:h}; W=$R/.build/demo-video; V=${1:-40}
F=$W/footage; SITE=$R/docs/images/site
rm -rf $F; mkdir -p $F/live $R/dist

# pick <file> <width>: a fresh capture if there is one, else the website's image, resized to the width the scene's
# coordinates in movie.swift were measured at. So a capture from a screen of another scale still lines up.
pick() {
  local src=$W/shots/$1; [ -f $src ] || src=$SITE/$1
  [ -f $src ] && sips --resampleWidth $2 $src --out $F/$1 >/dev/null
  return 0
}
pick firewall.png 932
pick map-sent.png 1800
pick protection.png 2784
if [ $V = 60 ] && [ ! -f $F/protection.png ]; then echo "run scripts/demo-video/capture.sh first"; exit 1; fi

# The live scene plays 6.2 s of the recording, from second 1, at the width its coordinates were measured at.
live=$W/shots/live.mov; [ -f $live ] || live=$SITE/live.mp4
ffmpeg -v error -y -ss 1 -t 6.2 -i $live -vf scale=1736:-2 -r 30 -q:v 2 $F/live/%04d.jpg

out=$R/dist/hostwatch-demo-1x1.mp4; [ $V = 60 ] && out=$R/dist/hostwatch-demo-1x1-60s.mp4
# Through the interpreter on purpose: a compiled copy of the renderer was killed at launch on the Mac this was made on.
swift -O $D/movie.swift $F $R/assets/AppIcon.png $V 2>$W/render.log \
  | ffmpeg -v error -y -f rawvideo -pix_fmt rgba -s 1080x1080 -r 30 -i - \
      -c:v libx264 -preset slow -crf 18 -pix_fmt yuv420p -movflags +faststart $out
grep "frames done" $W/render.log || { grep -v warning $W/render.log | tail -20; exit 1 }
echo "wrote $out"
