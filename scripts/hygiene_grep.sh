#!/bin/sh
# Privacy hygiene grep. Prints ONLY file + pattern-name on a hit, never the matched
# text. Patterns are built with the split-word idiom (printf) so this public file
# never materializes the forbidden strings themselves. Exit 1 on any hit.
set -u
cd "$(dirname "$0")/.." || exit 2

hits=0
report() { # report <file> <pattern-name>
    printf 'HIT %s [%s]\n' "$1" "$2"
    hits=$((hits + 1))
}

# --- pattern table: name|printf-fragment-format|fragment
pat_token_gho=$(printf 'gh%s_' 'o')
pat_token_ghp=$(printf 'gh%s_' 'p')
pat_token_pat=$(printf 'github_%s_' 'pat')
pat_token_ssh=$(printf 'BEGIN %s PRIVATE KEY' 'OPENSSH')
pat_token_rsa=$(printf 'BEGIN %s PRIVATE KEY' 'RSA')
pat_token_pk8=$(printf 'BEGIN %sKEY' 'PRIVATE ')
pat_token_aws=$(printf 'AK%sA0' 'IA')
pat_token_slack=$(printf 'xox%s-' 'b')

# personal-path/operator-name patterns come ONLY from the git-excluded denylist file;
# this script never carries them.
denylist='.hygiene-denylist'

scan_file() { # scan_file <file>
    f=$1
    for pair in \
        "token-gho|$pat_token_gho" "token-ghp|$pat_token_ghp" \
        "token-pat|$pat_token_pat" "token-ssh|$pat_token_ssh" \
        "token-rsa|$pat_token_rsa" "token-pk8|$pat_token_pk8" \
        "token-aws|$pat_token_aws" "token-slack|$pat_token_slack"; do
        name=${pair%%|*}; pat=${pair#*|}
        if grep -Fq -- "$pat" "$f" 2>/dev/null; then report "$f" "$name"; fi
    done
    if [ -f "$denylist" ]; then
        i=0
        while IFS= read -r dpat; do
            [ -n "$dpat" ] || continue
            case $dpat in \#*) continue ;; esac
            i=$((i + 1))
            if grep -Fq -- "$dpat" "$f" 2>/dev/null; then report "$f" "denylist-entry-$i"; fi
        done < "$denylist"
    fi
}

# --- scan targets: tracked files, plus any files passed as arguments
targets=$(mktemp)
git ls-files > "$targets"
for arg in "$@"; do printf '%s\n' "$arg" >> "$targets"; done

while IFS= read -r f; do
    [ -f "$f" ] && scan_file "$f"
done < "$targets"
rm -f "$targets"

# --- tracked-file assertions: private-adjacent paths must never be tracked
for bad in '.noni-state/' '.superpowers/sdd/' '.hygiene-denylist' '.env' 'id_rsa' '.pem'; do
    if git ls-files | grep -Fq -- "$bad"; then report 'git-ls-files' "tracked:$bad"; fi
done

if [ "$hits" -eq 0 ]; then echo "hygiene: clean"; exit 0; fi
echo "hygiene: $hits hit(s)"
exit 1
