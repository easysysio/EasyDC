#!/bin/sh
# The check expressions are single-quoted on purpose: they are eval'd after the
# script under test has run, so $T and $(...) must not expand when defined.
# shellcheck disable=SC2016
# Tests for packaging/migrate-legacy, run against a throwaway directory tree
# and a stub systemctl, so no real system is touched:
#
#   sh packaging/tests/migrate-legacy.sh
#
# Each case builds a fake root, runs the script against it, and checks the
# files it leaves and the systemctl calls it made.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/../migrate-legacy"
failures=0
passes=0

pass() { passes=$((passes + 1)); echo "  ok   $1"; }
fail() { failures=$((failures + 1)); echo "  FAIL $1"; }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

# A fresh fake root with a stub systemctl. $1 = "active enabled" state words.
setup() {
    T=$(mktemp -d)
    mkdir -p "$T/etc/systemd/system" "$T/bin"
    cat > "$T/bin/systemctl" <<STUB
#!/bin/sh
echo "\$*" >> "$T/systemctl.log"
case "\$1" in
    is-active)  grep -qw active  "$T/state" ;;
    is-enabled) grep -qw enabled "$T/state" ;;
    *) exit 0 ;;
esac
STUB
    chmod 755 "$T/bin/systemctl"
    echo "$1" > "$T/state"
    : > "$T/systemctl.log"
}

run() {
    EASYDC_MIGRATE_ROOT="$T" EASYDC_MIGRATE_USER="$(id -un)" EASYDC_MIGRATE_GROUP="$(id -gn)" \
        SYSTEMCTL="$T/bin/systemctl" SYSTEMCTL_FORCE=1 sh "$SCRIPT" > "$T/out" 2>&1
    echo $? > "$T/rc"
}

unit() { printf '%s\n' "[Unit]" "Description=EasyDC" "[Service]" "$@" "[Install]" "WantedBy=multi-user.target" \
    > "$T/etc/systemd/system/easydc.service"; }

echo "1. the /opt install that was migrated by hand on dc1"
setup "active enabled"
unit "Type=simple" "WorkingDirectory=/opt/easydc" "ExecStart=/opt/easydc/easydc-linux-arm64"
mkdir -p "$T/opt/easydc"; echo "DB-CONTENT" > "$T/opt/easydc/easydc.db"
run
check "exits 0"                          '[ "$(cat $T/rc)" = 0 ]'
check "database copied"                  '[ "$(cat $T/var/lib/easydc/easydc.db)" = DB-CONTENT ]'
check "original database left in place"  '[ -f $T/opt/easydc/easydc.db ]'
check "new database is mode 600"         '[ "$(ls -ld $T/var/lib/easydc/easydc.db | cut -c1-10)" = "-rw-------" ]'
check "state dir is mode 700"            '[ "$(ls -ld $T/var/lib/easydc | cut -c1-10)" = "drwx------" ]'
check "old unit renamed, not deleted"    '[ ! -f $T/etc/systemd/system/easydc.service ] && [ -f $T/etc/systemd/system/easydc.service.pre-package ]'
check "no port file (default port)"      '[ ! -e $T/etc/default/easydc ]'
check "stopped before disabling"         '[ "$(grep -n "^stop" $T/systemctl.log | cut -d: -f1)" -lt "$(grep -n "^disable" $T/systemctl.log | cut -d: -f1)" ]'
check "re-enabled and started"           'grep -q "^enable" $T/systemctl.log && grep -q "^start" $T/systemctl.log'
check "stop happens before the copy"     'grep -q "stopping the old service" $T/out'
rm -rf "$T"

echo "2. the old README layout, on a custom port"
setup "active enabled"
unit "User=easydc" "WorkingDirectory=/var/lib/easydc" "ExecStart=/usr/local/bin/easydc --port 8080"
mkdir -p "$T/var/lib/easydc"; echo "SAME-PLACE" > "$T/var/lib/easydc/easydc.db"
run
check "database already in place, kept"  '[ "$(cat $T/var/lib/easydc/easydc.db)" = SAME-PLACE ]'
check "port carried over"                'grep -qx "EASYDC_PORT=8080" $T/etc/default/easydc'
check "unit renamed"                     '[ -f $T/etc/systemd/system/easydc.service.pre-package ]'
rm -rf "$T"

echo "3. the port in other spellings, and RHEL's sysconfig"
for spelling in "--port=9090" "-p 9090"; do
    setup "active enabled"; mkdir -p "$T/etc/sysconfig"
    unit "WorkingDirectory=/opt/easydc" "ExecStart=/opt/easydc/easydc $spelling"
    run
    check "port from '$spelling' -> sysconfig" 'grep -qx "EASYDC_PORT=9090" $T/etc/sysconfig/easydc && [ ! -e $T/etc/default/easydc ]'
    rm -rf "$T"
done
setup "inactive disabled"
unit "Environment=EASYDC_PORT=7070" "WorkingDirectory=/opt/easydc" "ExecStart=/opt/easydc/easydc"
run
check "port from Environment="           'grep -qx "EASYDC_PORT=7070" $T/etc/default/easydc'
rm -rf "$T"

echo "4. an administrator's deliberate override of the packaged unit"
setup "active enabled"
unit "WorkingDirectory=/var/lib/easydc" "ExecStart=/usr/bin/easydc" "Environment=RUST_LOG=debug"
run
check "unit left alone"                  '[ -f $T/etc/systemd/system/easydc.service ] && [ ! -e $T/etc/systemd/system/easydc.service.pre-package ]'
check "service not touched"              '[ ! -s $T/systemctl.log ] || ! grep -qE "^(stop|disable|start)" $T/systemctl.log'
rm -rf "$T"

echo "5. a fresh install with no legacy unit"
setup "inactive disabled"
run
check "does nothing, exits 0"            '[ "$(cat $T/rc)" = 0 ] && [ ! -s $T/out ] && [ ! -s $T/systemctl.log ]'
rm -rf "$T"

echo "6. a database already in /var/lib/easydc is never overwritten"
setup "active enabled"
unit "WorkingDirectory=/opt/easydc" "ExecStart=/opt/easydc/easydc"
mkdir -p "$T/opt/easydc" "$T/var/lib/easydc"
echo "OLD" > "$T/opt/easydc/easydc.db"; echo "NEWER" > "$T/var/lib/easydc/easydc.db"
run
check "existing database kept"           '[ "$(cat $T/var/lib/easydc/easydc.db)" = NEWER ]'
check "says where the old one is"        'grep -q "still at" $T/out'
rm -rf "$T"

echo "7. no WorkingDirectory: a system service runs in /"
setup "active enabled"
unit "ExecStart=-/opt/easydc/easydc"
echo "ROOT-DB" > "$T/easydc.db"
run
check "database found in / and copied"   '[ "$(cat $T/var/lib/easydc/easydc.db)" = ROOT-DB ]'
check "ExecStart prefix '-' handled"     'grep -q "runs /opt/easydc/easydc" $T/out'
rm -rf "$T"

echo "8. WAL files travel with the database"
setup "active enabled"
unit "WorkingDirectory=/opt/easydc" "ExecStart=/opt/easydc/easydc"
mkdir -p "$T/opt/easydc"; for f in easydc.db easydc.db-wal easydc.db-shm; do echo "$f" > "$T/opt/easydc/$f"; done
run
check "db, -wal and -shm all copied"     '[ -f $T/var/lib/easydc/easydc.db-wal ] && [ -f $T/var/lib/easydc/easydc.db-shm ]'
rm -rf "$T"

echo "9. a drop-in directory is moved aside with the unit"
setup "active enabled"
unit "WorkingDirectory=/opt/easydc" "ExecStart=/opt/easydc/easydc"
mkdir -p "$T/etc/systemd/system/easydc.service.d"; echo "[Service]" > "$T/etc/systemd/system/easydc.service.d/override.conf"
run
check "drop-in renamed"                  '[ -d $T/etc/systemd/system/easydc.service.d.pre-package ] && [ ! -e $T/etc/systemd/system/easydc.service.d ]'
rm -rf "$T"

echo "10. a stopped, disabled old service stays that way"
setup "inactive disabled"
unit "WorkingDirectory=/opt/easydc" "ExecStart=/opt/easydc/easydc"
mkdir -p "$T/opt/easydc"; echo "X" > "$T/opt/easydc/easydc.db"
run
check "not started or enabled"           '! grep -qE "^(start|enable)" $T/systemctl.log'
check "database still migrated"          '[ -f $T/var/lib/easydc/easydc.db ]'
rm -rf "$T"

echo "11. running it twice"
setup "active enabled"
unit "WorkingDirectory=/opt/easydc" "ExecStart=/opt/easydc/easydc --port 8080"
mkdir -p "$T/opt/easydc"; echo "X" > "$T/opt/easydc/easydc.db"
run; : > "$T/systemctl.log"; run
check "second run is a no-op"            '[ ! -s $T/out ] && [ ! -s $T/systemctl.log ]'
check "port written once"                '[ "$(grep -c EASYDC_PORT $T/etc/default/easydc)" = 1 ]'
rm -rf "$T"

echo
echo "$passes passed, $failures failed"
[ "$failures" -eq 0 ]
