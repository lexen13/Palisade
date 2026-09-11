#!/usr/bin/env bash
# Palisade CSP surface lint.
#
# Counts the constructs that a hash-based script-src either kills outright or
# that would give an injected string a way to become code. It is a ratchet, not
# a build step: every metric has a locked baseline and the script exits non-zero
# the moment a count goes ABOVE it. Counts going DOWN are the whole point and
# never fail — lower the baseline here in the same commit that lowers the count.
#
#   tools/csp-lint.sh                          # lints ./palisade.html (repo root)
#   tools/csp-lint.sh path/to/file.html
#   tools/csp-lint.sh --baseline path/to/file  # print the file's counts as a
#                                              # ready-to-paste baseline block
#
# Run it from the repository root. CI passes the path explicitly, so the default
# below only matters when a human runs it by hand.
#
# ---------------------------------------------------------------------------
# BASELINE — measured 2026-09-11 against pristine/palisade-v2.7-ORIGINAL.html
# (498,880 bytes, sha256 8918858eb91e864fb5901bb1d7351483467a237bcae5b67ad872bdf18ee49978).
# Palisade/palisade.html was byte-identical to it at the time of measurement.
#
#   inline_on_handlers        192   144 static body + 48 emitted by the script
#                                   (27 onclick + 21 onchange). NOTE: 192, not
#                                   191 — one onchange at pristine line 4277 is
#                                   concatenated straight onto a string literal
#                                   ("+'onchange=\"toggleRptSection(") so it has
#                                   no whitespace in front of it and a naive
#                                   / on[a-z]+=/ pattern walks past it.
#   javascript_urls             0
#   setattribute_on             0
#   setattribute_style          0
#   style_csstext               0
#   string_arg_timers           0   5 setTimeout calls, all function-argument
#   script_tags                 1   the single inline block at line 1153
#   absolute_http_urls          0
#
# The HARDENING-LEDGER C0 row predicted 192/0/0/0/0/0/1/16. Seven of eight are
# confirmed. The 16 is WRONG: the ledger attributes it to
# xmlns="http://www.w3.org/2000/svg", but this file has no xmlns attribute
# anywhere — its 16 <svg> elements are HTML-parsed inline SVG, which does not
# need one. The true absolute-URL count is 0, and that is what is locked here.
#
# POST-BLOCK-C TARGET (do not set these until Block C has actually landed and
# the harness gate passes — see HARDENING-LEDGER section 3 row 10):
#   inline_on_handlers 1, of which 0 in the static body and 1 in the script
#   carrying the /*EXPORT-ONLY-HANDLER*/ marker; everything else unchanged.
# ---------------------------------------------------------------------------
set -u

BL_INLINE_ON_HANDLERS=192
BL_JAVASCRIPT_URLS=0
BL_SETATTRIBUTE_ON=0
BL_SETATTRIBUTE_STYLE=0
BL_STYLE_CSSTEXT=0
BL_STRING_ARG_TIMERS=0
BL_SCRIPT_TAGS=1
BL_ABSOLUTE_HTTP_URLS=0

# Inline handler attributes. The leading class is "any character that cannot be
# part of a JS identifier or member access", NOT plain whitespace: it has to
# catch handlers glued to a quote inside a template/concatenation, and it has to
# NOT catch el.onclick= / obj.onchange= property assignments.
RX_ON_HANDLER='(^|[^A-Za-z0-9_.$-])on[a-z][a-z0-9]*[[:space:]]*='
# A string first argument to setTimeout/setInterval is an eval() in disguise.
RX_STRING_TIMER='\bset(Timeout|Interval)[[:space:]]*\([[:space:]]*["'"'"'`]'

BASELINE_MODE=0
if [ "${1-}" = "--baseline" ]; then BASELINE_MODE=1; shift; fi
FILE="${1-palisade.html}"
[ -r "$FILE" ] || { echo "csp-lint: cannot read $FILE" >&2; exit 2; }

# count <extended-regex> [file] — occurrences, not matching lines.
count() { grep -oEi -- "$1" "${2-$FILE}" 2>/dev/null | grep -c . ; }
countf() { grep -oF -- "$1" "$FILE" 2>/dev/null | grep -c . ; }

# The static body is everything before the first <script tag. Under a hash-based
# script-src nothing in it can execute, so its handler count must reach 0.
SPLIT=$(grep -n -m1 '<script' "$FILE" | cut -d: -f1)
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
if [ -n "${SPLIT:-}" ]; then
  head -n "$((SPLIT - 1))" "$FILE" > "$TMP/body"
  tail -n "+$SPLIT"        "$FILE" > "$TMP/script"
else
  : > "$TMP/body"; cp "$FILE" "$TMP/script"
fi

inline_on_handlers=$(count "$RX_ON_HANDLER")
body_handlers=$(count "$RX_ON_HANDLER" "$TMP/body")
script_handlers=$(count "$RX_ON_HANDLER" "$TMP/script")
exempt_handlers=$(grep -E -- "$RX_ON_HANDLER" "$FILE" 2>/dev/null | grep -cF '/*EXPORT-ONLY-HANDLER*/')
javascript_urls=$(count 'javascript:')
setattribute_on=$(countf 'setAttribute("on')
setattribute_style=$(countf 'setAttribute("style')
style_csstext=$(count '\.style\.cssText')
string_arg_timers=$(count "$RX_STRING_TIMER")
script_tags=$(countf '<script')
absolute_http_urls=$(count 'https?://')

if [ "$BASELINE_MODE" = 1 ]; then
  cat <<EOF
BL_INLINE_ON_HANDLERS=$inline_on_handlers
BL_JAVASCRIPT_URLS=$javascript_urls
BL_SETATTRIBUTE_ON=$setattribute_on
BL_SETATTRIBUTE_STYLE=$setattribute_style
BL_STYLE_CSSTEXT=$style_csstext
BL_STRING_ARG_TIMERS=$string_arg_timers
BL_SCRIPT_TAGS=$script_tags
BL_ABSOLUTE_HTTP_URLS=$absolute_http_urls
EOF
  exit 0
fi

fails=0
# row <name> <count> <baseline>
row() {
  local verdict="ok"
  if [ "$2" -gt "$3" ]; then verdict="FAIL"; fails=$((fails + 1))
  elif [ "$2" -lt "$3" ]; then verdict="ok-improved"; fi
  printf '%-22s %6d  baseline %-6d %s\n' "$1" "$2" "$3" "$verdict"
}

echo "# csp-lint $FILE"
row inline_on_handlers  "$inline_on_handlers"  "$BL_INLINE_ON_HANDLERS"
printf '#   static body %d / script %d / %s-exempt %d\n' \
  "$body_handlers" "$script_handlers" 'EXPORT-ONLY-HANDLER' "$exempt_handlers"
row javascript_urls     "$javascript_urls"     "$BL_JAVASCRIPT_URLS"
row setattribute_on     "$setattribute_on"     "$BL_SETATTRIBUTE_ON"
row setattribute_style  "$setattribute_style"  "$BL_SETATTRIBUTE_STYLE"
row style_csstext       "$style_csstext"       "$BL_STYLE_CSSTEXT"
row string_arg_timers   "$string_arg_timers"   "$BL_STRING_ARG_TIMERS"
row script_tags         "$script_tags"         "$BL_SCRIPT_TAGS"
row absolute_http_urls  "$absolute_http_urls"  "$BL_ABSOLUTE_HTTP_URLS"

if [ "$fails" -gt 0 ]; then
  echo "# RESULT: FAIL ($fails metric(s) above baseline)"
  exit 1
fi
echo "# RESULT: PASS"
