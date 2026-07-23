# How the README's demo assets were made

`demo.gif`, embedded in the README just above the static terminal
output, is a screen recording of the three-command sequence: a strict
scan that comes back `BLOCKED`, writing a baseline over those findings,
then a re-scan that comes back `PASS` because the baseline mode
grandfathers the pre-existing findings and only blocks on regressions.

It's a QuickTime Player screen recording, converted to GIF with
`ffmpeg` — not a [vhs](https://github.com/charmbracelet/vhs) tape.
`vhs` depends on `ttyd`, which is Tier 3 on Homebrew for macOS 13
(the OS this was recorded on); the dependency chain wouldn't build
here. Rather than block the demo on fixing that, it was recorded by
hand.

The tradeoff worth knowing: this means the demo isn't regenerated from
a checked-in script, so it can silently drift from the CLI's actual
output over time (flag names, formatting, etc.). If the CLI's output
changes in a way that makes the demo misleading, re-record it — there
is no `make demo` to just re-run.

## `pr-comment.png` and `code-scanning-alert.png`

Same story as `demo.gif`, not generated from a script: these are
hand-captured screenshots taken against `mobilegate-action-test`, a
throwaway repo with the GitHub Action wired up, used specifically to
produce real PR-comment and Code Scanning UI to screenshot. Same
staleness risk applies — if the PR comment format or the Code Scanning
alert layout changes, these need to be re-captured by hand, not
regenerated.
