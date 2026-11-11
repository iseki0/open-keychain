#!/usr/bin/env bash
set -euo pipefail
module_dir=$(cd -- "$(dirname -- "$0")" && pwd)
test_dir=$(mktemp -d)
cleanup() {
    result=$?
    if [[ $result -ne 0 && -f "$test_dir/fixture.log" ]]; then cat "$test_dir/fixture.log" >&2; fi
    if [[ -n "${fixture_pid:-}" ]]; then kill "$fixture_pid" 2>/dev/null || true; fi
    if [[ -d "$test_dir/reference" ]]; then gpgconf --homedir "$test_dir/reference" --kill gpg-agent || true; fi
    rm -rf -- "$test_dir"
}
trap cleanup EXIT
mkdir -p "$test_dir/classes"
mapfile -t production_sources < <(find "$module_dir/src/main/java" -name '*.java' -print)
mapfile -t test_sources < <(find "$module_dir/src/test/java" -name '*.java' -print)
java com.sun.tools.javac.Main -Xlint:-options -source 8 -target 8 -d "$test_dir/classes" "${production_sources[@]}"
java com.sun.tools.javac.Main -Xlint:-options -source 17 -target 17 -cp "$test_dir/classes" -d "$test_dir/classes" "${test_sources[@]}"
java -cp "$test_dir/classes" org.sufficientlysecure.keychain.remote.agent.AssuanSessionTest
if ! command -v gpg >/dev/null || ! command -v gpg-connect-agent >/dev/null; then
    echo 'GnuPG not installed; skipped full GnuPG integration' >&2
    exit 0
fi
mkdir -m 700 "$test_dir/reference" "$test_dir/client"
gpg --homedir "$test_dir/reference" --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key 'Protocol Fixture <protocol@example.invalid>' rsa2048 sign 0
fingerprint=$(gpg --homedir "$test_dir/reference" --with-colons --list-keys | awk -F: '$1 == "fpr" { print $10; exit }')
keygrip=$(gpg --homedir "$test_dir/reference" --with-colons --with-keygrip --list-keys | awk -F: '$1 == "grp" { print $10; exit }')
gpg --homedir "$test_dir/reference" --export "$fingerprint" > "$test_dir/public.pgp"
gpg --homedir "$test_dir/client" --batch --no-autostart --import "$test_dir/public.pgp"
socket_path=$(gpgconf --homedir "$test_dir/client" --list-dirs agent-socket)
java -cp "$test_dir/classes" org.sufficientlysecure.keychain.remote.agent.TestAgentServer \
    "$test_dir/reference" "$keygrip" "$socket_path" > "$test_dir/fixture.log" 2>&1 &
fixture_pid=$!
for ((attempt=0; attempt<100; attempt++)); do
    if [[ -S "$socket_path" ]]; then break; fi
    if ! kill -0 "$fixture_pid" 2>/dev/null; then cat "$test_dir/fixture.log"; exit 1; fi
    sleep 0.05
done
printf 'OpenKeychain remote signing protocol integration\n' > "$test_dir/message"
gpg --homedir "$test_dir/client" --batch --no-autostart --digest-algo SHA256 \
    --local-user "$fingerprint" --detach-sign --output "$test_dir/message.sig" "$test_dir/message"
gpg --homedir "$test_dir/client" --batch --verify "$test_dir/message.sig" "$test_dir/message"
# Neither importing the public key nor remote signing writes a private-key stub.
if [[ -d "$test_dir/client/private-keys-v1.d" ]] && find "$test_dir/client/private-keys-v1.d" -type f | read -r ignored; then
    echo 'Unexpected private key in client home' >&2
    exit 1
fi
git init -q "$test_dir/repository"
git -C "$test_dir/repository" config user.name 'Protocol Fixture'
git -C "$test_dir/repository" config user.email protocol@example.invalid
git -C "$test_dir/repository" config user.signingkey "$fingerprint"
printf 'Signed commit test\n' > "$test_dir/repository/content"
git -C "$test_dir/repository" add content
GNUPGHOME="$test_dir/client" git -C "$test_dir/repository" commit -q -S -m 'Sign through OpenKeychain agent protocol'
GNUPGHOME="$test_dir/client" git -C "$test_dir/repository" verify-commit HEAD
echo 'GnuPG integration: detached RSA signature and signed Git commit verified through AssuanSession'
