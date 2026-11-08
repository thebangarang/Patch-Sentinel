# Video

The demo lives here. `raw/` is where a recording lands before it is edited — it is gitignored, because a
screen capture is large and disposable. The finished file is what ships.

## What a recording has to look like to be editable

- **1920×1080** (2560×1440 is fine too; it gets downscaled). 30 or 60 fps.
- **One continuous take.** Pauses are good, dead air is cut. Leave about a second of stillness at the
  start and two at the end, so the edit has handles.
- **No audio required.** If you narrate, the narration stays and the music is ducked under it. If you
  do not, the music carries it and the cards say the words.
- **Hide what is not the product:** public IPs, tokens, ssh keys, notification popups, other windows.
  The pane and one terminal are the whole set.
- **Terminal at 16 pt or larger.** Half the demo is commands being pasted, and a 10 pt terminal is
  unreadable after compression.

## What the edit adds, and what it never does

- an intro card (2.5 s) and an end card (4 s) — title, one line, repository URL, MIT;
- one music bed, faded in and out, ducked under any speech;
- nothing over the pane while something is being read: no callouts, no zooms, no cursor effects. The
  claim of the plugin is "look at what it actually says", and an overlay is the opposite of that.

## Encoding

`ffmpeg` on this machine, H.264 in MP4, `-crf 20`, 1920×1080, audio AAC 128 kb/s. Target under 40 MB —
GitHub refuses a single file over 100 MB, and a repository should not be a video host. If the finished
file is larger, the release page hosts it and the README links there instead.
