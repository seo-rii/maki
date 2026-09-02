#!/usr/bin/env bash
# Validate Maki through a disposable kernel NBD device, LVM, and XFS.
#
# The script deliberately refuses non-NBD targets and requires the selected
# device path to be repeated with --confirm-wipe.  It never unloads the NBD
# module, touches an already-connected device, or runs crash/OOM/power-loss
# tests.

set -Eeuo pipefail
IFS=$'\n\t'

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
readonly SCRIPT_PATH
REPO_ROOT="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd -P)"
readonly REPO_ROOT
readonly VIRTUAL_SIZE_BYTES=$((512 * 1024 * 1024))
readonly RAW_FIO_SIZE="64M"
readonly FILE_FIO_SIZE="64M"
readonly LV_SIZE="384M"
readonly MIN_WORK_FREE_BYTES=$((768 * 1024 * 1024))

device="/dev/nbd15"
confirmed_device=""
work_root=""
run_dir=""
background=false
install_missing=false
preflight=false

usage() {
    cat <<'EOF'
Usage:
  scripts/privileged-linux-validation.sh --preflight [--device /dev/nbdN]
  scripts/privileged-linux-validation.sh --background [--install-missing] \
      --device /dev/nbdN --confirm-wipe /dev/nbdN [--work-root DIR]

Options:
  --device PATH          Dedicated kernel NBD device (default: /dev/nbd15).
  --confirm-wipe PATH    Must exactly repeat --device. The exported test
                         volume is overwritten by fio, LVM, and mkfs.xfs.
  --work-root DIR        Filesystem used for disposable encrypted backing.
                         By default, choose /data or /var/tmp with enough room.
  --install-missing      On Debian, apt-install the native test dependencies.
  --background           Run under nohup and write a stable latest-log link.
  --preflight            Show checks and missing commands without sudo or I/O.
  -h, --help             Show this help.

The run excludes forced crashes, OOM tests, power interruption, and any real
disk. Only an unused /dev/nbdN is accepted.
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

log() {
    printf '[%s] %s\n' "$(date --iso-8601=seconds)" "$*"
}

pass_count=0
pass() {
    pass_count=$((pass_count + 1))
    log "PASS: $*"
}

while (($#)); do
    case "$1" in
        --device)
            (($# >= 2)) || die "--device requires a value"
            device="$2"
            shift 2
            ;;
        --confirm-wipe)
            (($# >= 2)) || die "--confirm-wipe requires a value"
            confirmed_device="$2"
            shift 2
            ;;
        --work-root)
            (($# >= 2)) || die "--work-root requires a value"
            work_root="$2"
            shift 2
            ;;
        --install-missing)
            install_missing=true
            shift
            ;;
        --background)
            background=true
            shift
            ;;
        --preflight)
            preflight=true
            shift
            ;;
        --run-dir)
            (($# >= 2)) || die "--run-dir requires a value"
            run_dir="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

[[ "$device" =~ ^/dev/nbd([0-9]+)$ ]] ||
    die "--device must be an explicit /dev/nbdN path"
readonly nbd_index=$((10#${BASH_REMATCH[1]}))
((nbd_index <= 255)) || die "NBD index is unreasonably large: $nbd_index"

required_commands=(
    blockdev cargo df findmnt fio lsblk lvcreate lvremove mkfs.xfs modprobe
    nbd-client nbdinfo nbdkit nm pvcreate pvremove sqlite3 sync vgchange
    vgcreate vgremove
)

missing_commands() {
    local command_name
    for command_name in "${required_commands[@]}"; do
        command -v "$command_name" >/dev/null 2>&1 || printf '%s\n' "$command_name"
    done
}

if [[ "$preflight" == true ]]; then
    [[ "$background" == false ]] || die "--preflight and --background are mutually exclusive"
    printf 'Repository: %s\n' "$REPO_ROOT"
    printf 'Device:     %s\n' "$device"
    printf 'Scope:      kernel NBD -> raw fio -> LVM -> XFS -> file fio/SQLite\n'
    printf 'Excluded:   forced crash, OOM, power interruption, real disks\n'
    mapfile -t preflight_missing < <(missing_commands)
    if ((${#preflight_missing[@]})); then
        printf 'Missing commands:\n'
        printf '  %s\n' "${preflight_missing[@]}"
        printf 'Use --install-missing on Debian to install their packages.\n'
    else
        printf 'All required commands are installed.\n'
    fi
    exit 0
fi

[[ "$confirmed_device" == "$device" ]] ||
    die "repeat the exact target with --confirm-wipe $device"
((EUID != 0)) || die "run this script as your normal user; it invokes sudo only where needed"

user_home="$(getent passwd "$(id -u)" | cut -d: -f6)"
[[ -n "$user_home" && -d "$user_home" ]] || die "cannot resolve the invoking user's home directory"
log_root="${user_home}/logs"

if [[ "$background" == true ]]; then
    [[ -z "$run_dir" ]] || die "--run-dir is internal and cannot be combined with --background"
    umask 077
    mkdir -p "$log_root"
    chmod 0700 "$log_root"
    run_stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    run_dir="${log_root}/maki-privileged-validation-${run_stamp}"
    mkdir "$run_dir"
    : >"$run_dir/run.log"
    printf 'state=starting\n' >"$run_dir/status"
    chmod 0600 "$run_dir/run.log" "$run_dir/status"
    ln -sfn "$(basename "$run_dir")" "${log_root}/maki-privileged-validation.latest"

    printf 'sudo authentication is required once before the background run starts.\n'
    if ! sudo -v; then
        printf 'state=not-started\nexit_code=1\nreason=sudo-authentication-failed\n' \
            >"$run_dir/status"
        exit 1
    fi

    child_args=(
        --device "$device"
        --confirm-wipe "$confirmed_device"
        --run-dir "$run_dir"
    )
    [[ -z "$work_root" ]] || child_args+=(--work-root "$work_root")
    [[ "$install_missing" == false ]] || child_args+=(--install-missing)

    printf 'state=running\n' >"$run_dir/status"
    nohup "$SCRIPT_PATH" "${child_args[@]}" \
        >"$run_dir/run.log" 2>&1 </dev/null &
    child_pid=$!
    printf '%s\n' "$child_pid" >"$run_dir/pid"
    chmod 0600 "$run_dir/pid"

    printf 'Started PID %s\n' "$child_pid"
    printf 'Log:    %s/run.log\n' "$run_dir"
    printf 'Status: %s/status\n' "$run_dir"
    printf 'Latest: %s/maki-privileged-validation.latest\n' "$log_root"
    exit 0
fi

umask 077
if [[ -z "$run_dir" ]]; then
    mkdir -p "$log_root"
    chmod 0700 "$log_root"
    run_stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    run_dir="${log_root}/maki-privileged-validation-${run_stamp}"
    mkdir "$run_dir"
    ln -sfn "$(basename "$run_dir")" "${log_root}/maki-privileged-validation.latest"
    : >"$run_dir/run.log"
    exec > >(tee -a "$run_dir/run.log") 2>&1
    sudo -v
fi

[[ "$run_dir" == "$log_root"/maki-privileged-validation-* ]] ||
    die "invalid run directory: $run_dir"
mkdir -p "$run_dir"
chmod 0700 "$run_dir"
status_path="$run_dir/status"
printf 'state=running\npid=%s\n' "$$" >"$status_path"

work_dir=""
runtime_dir=""
runtime_parent_created=false
nbdkit_pid=""
duplicate_pid=""
sudo_keeper_pid=""
nbd_connection_attempted=false
nbd_connected=false
mount_active=false
vg_created=false
pv_created=false
cleanup_safe=true
volume_name="privval-$(id -u)-$$"
vg_name="maki_validation_$(id -u)_$$"
lv_name="data"
mountpoint=""
socket_path=""

stop_process_normally() {
    local pid="$1"
    local label="$2"
    [[ -n "$pid" ]] || return 0
    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null || true
        return 0
    fi
    log "cleanup: sending SIGTERM to $label (PID $pid)"
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 100); do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null || true
            return 0
        fi
        sleep 0.1
    done
    log "cleanup warning: $label did not stop after SIGTERM; no SIGKILL was sent"
    return 1
}

nbd_has_pid() {
    local pid_file
    pid_file="/sys/block/$(basename "$device")/pid"
    [[ -r "$pid_file" ]] || return 1
    local value
    value="$(<"$pid_file")"
    [[ "$value" =~ ^[1-9][0-9]*$ ]]
}

disconnect_test_nbd() {
    if [[ "$nbd_connected" == true ]] ||
        { [[ "$nbd_connection_attempted" == true ]] && nbd_has_pid; }; then
        log "cleanup: disconnecting $device"
        if sudo -n nbd-client -d "$device"; then
            nbd_connected=false
            return 0
        fi
        log "cleanup warning: could not disconnect $device"
        return 1
    fi
}

cleanup() {
    local cleanup_rc=0
    set +e

    if [[ "$mount_active" == true ]] ||
        { [[ -n "$mountpoint" ]] && findmnt -rn -M "$mountpoint" >/dev/null 2>&1; }; then
        log "cleanup: unmounting $mountpoint"
        if sudo -n umount "$mountpoint"; then
            mount_active=false
        else
            log "cleanup warning: mount remains active; leaving NBD, nbdkit, and backing in place"
            cleanup_safe=false
            cleanup_rc=1
        fi
    fi

    if [[ "$cleanup_safe" == false ]]; then
        if [[ -n "$sudo_keeper_pid" ]]; then
            : >"$run_dir/stop-sudo-keeper"
            kill -TERM "$sudo_keeper_pid" 2>/dev/null || true
            wait "$sudo_keeper_pid" 2>/dev/null || true
        fi
        return "$cleanup_rc"
    fi

    if [[ "$vg_created" == true || "$pv_created" == true ]]; then
        if ! nbd_has_pid && [[ -n "$nbdkit_pid" ]] && kill -0 "$nbdkit_pid" 2>/dev/null; then
            log "cleanup: reconnecting $device to remove disposable LVM metadata"
            if sudo -n nbd-client -unix "$socket_path" "$device" -b 4096; then
                nbd_connected=true
            else
                log "cleanup warning: could not reconnect $device for LVM cleanup"
                cleanup_safe=false
                cleanup_rc=1
            fi
        fi

        if nbd_has_pid; then
            if [[ "$vg_created" == true ]]; then
                sudo -n vgchange -ay "$vg_name" >/dev/null 2>&1 || true
                sudo -n lvremove --yes --force "/dev/$vg_name/$lv_name" >/dev/null 2>&1 || true
                if sudo -n vgremove --yes --force "$vg_name" >/dev/null 2>&1; then
                    vg_created=false
                else
                    log "cleanup warning: could not remove test VG $vg_name"
                    cleanup_safe=false
                    cleanup_rc=1
                fi
            fi
            if [[ "$pv_created" == true ]]; then
                if sudo -n pvremove --yes --force "$device" >/dev/null 2>&1; then
                    pv_created=false
                else
                    log "cleanup warning: could not remove test PV on $device"
                    cleanup_safe=false
                    cleanup_rc=1
                fi
            fi
        else
            log "cleanup warning: test LVM metadata remains but $device is disconnected"
            cleanup_safe=false
            cleanup_rc=1
        fi
    fi

    disconnect_test_nbd || cleanup_rc=1

    stop_process_normally "$duplicate_pid" "duplicate nbdkit" || cleanup_rc=1
    duplicate_pid=""
    if ! stop_process_normally "$nbdkit_pid" "nbdkit"; then
        cleanup_rc=1
        cleanup_safe=false
    fi
    nbdkit_pid=""

    if [[ -n "$runtime_dir" && "$runtime_dir" == /run/maki/privval-* ]]; then
        sudo -n rmdir "$runtime_dir" 2>/dev/null || true
    fi
    if [[ "$runtime_parent_created" == true ]]; then
        sudo -n rmdir /run/maki 2>/dev/null || true
    fi

    if [[ -n "$work_dir" && "$cleanup_safe" == true ]]; then
        case "$work_dir" in
            "$work_root"/maki-privileged-validation.*)
                log "cleanup: deleting disposable work tree $work_dir"
                find "$work_dir" -xdev -depth -delete || cleanup_rc=1
                ;;
            *)
                log "cleanup warning: refusing unexpected work path $work_dir"
                cleanup_rc=1
                ;;
        esac
    elif [[ -n "$work_dir" ]]; then
        log "cleanup warning: preserved $work_dir because nbdkit is still running"
    fi

    if [[ -n "$sudo_keeper_pid" ]]; then
        : >"$run_dir/stop-sudo-keeper"
        kill -TERM "$sudo_keeper_pid" 2>/dev/null || true
        wait "$sudo_keeper_pid" 2>/dev/null || true
    fi
    return "$cleanup_rc"
}

finish() {
    local run_rc=$?
    trap - EXIT INT TERM HUP
    local cleanup_rc=0
    cleanup || cleanup_rc=$?
    if ((run_rc == 0 && cleanup_rc != 0)); then
        run_rc=$cleanup_rc
    fi
    if ((run_rc == 0)); then
        printf 'state=passed\nexit_code=0\nchecks=%s\nfinished=%s\n' \
            "$pass_count" "$(date --iso-8601=seconds)" >"$status_path"
        log "RESULT: PASS ($pass_count checks)"
    else
        printf 'state=failed\nexit_code=%s\nchecks=%s\nfinished=%s\n' \
            "$run_rc" "$pass_count" "$(date --iso-8601=seconds)" >"$status_path"
        log "RESULT: FAIL (exit $run_rc after $pass_count checks)"
    fi
    exit "$run_rc"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

log "Maki privileged Linux validation"
log "repository: $REPO_ROOT"
log "revision: $(git -C "$REPO_ROOT" rev-parse HEAD)"
log "device: $device"
log "kernel: $(uname -srvm)"
log "run artifacts: $run_dir"

sudo -n true || die "sudo credential is unavailable; start with --background or run sudo -v"
(
    while [[ ! -e "$run_dir/stop-sudo-keeper" ]]; do
        sudo -n -v || exit 1
        for _ in $(seq 1 45); do
            [[ -e "$run_dir/stop-sudo-keeper" ]] && exit 0
            sleep 1
        done
    done
) >>"$run_dir/sudo-keeper.log" 2>&1 &
sudo_keeper_pid=$!

if [[ "$install_missing" == true ]]; then
    [[ -r /etc/os-release ]] || die "cannot identify the operating system"
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ "${ID:-}" == "debian" || "${ID_LIKE:-}" == *debian* ]] ||
        die "--install-missing currently supports Debian-family systems only"
    log "installing native validation dependencies with apt"
    sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update
    sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        binutils fio kmod libnbd-bin lvm2 nbd-client nbdkit nbdkit-plugin-dev \
        sqlite3 util-linux xfsprogs
    pass "native validation dependencies installed"
fi

mapfile -t still_missing < <(missing_commands)
((${#still_missing[@]} == 0)) ||
    die "missing commands: ${still_missing[*]} (rerun with --install-missing on Debian)"
[[ "$(fio --version)" =~ ^fio-[0-9] ]] || die "fio resolves to an unexpected executable: $(fio --version)"
pass "required native tools available"

log "building release binaries and nbdkit plugin"
cargo build --manifest-path "$REPO_ROOT/Cargo.toml" --release --locked \
    -p maki -p maki-attach -p maki-nbdkit
readonly maki_bin="$REPO_ROOT/target/release/maki"
readonly attach_bin="$REPO_ROOT/target/release/maki-attach"
readonly plugin_path="$REPO_ROOT/target/release/libmaki_nbdkit.so"
[[ -x "$maki_bin" && -x "$attach_bin" && -f "$plugin_path" ]] ||
    die "release artifacts are incomplete"
nm -D --defined-only "$plugin_path" | grep -Eq '[[:space:]]T[[:space:]]plugin_init$' ||
    die "plugin_init is not exported by $plugin_path"
pass "release binaries and plugin_init export"

choose_work_root() {
    local candidate available
    if [[ -n "$work_root" ]]; then
        candidates=("$work_root")
    else
        candidates=(/data /var/tmp)
    fi
    for candidate in "${candidates[@]}"; do
        [[ -d "$candidate" && -w "$candidate" ]] || continue
        candidate="$(readlink -f "$candidate")"
        [[ "$candidate" != "/" && "$candidate" != "$user_home" && "$candidate" != "$REPO_ROOT" ]] || continue
        available="$(df -PB1 "$candidate" | awk 'NR == 2 {print $4}')"
        if [[ "$available" =~ ^[0-9]+$ ]] && ((available >= MIN_WORK_FREE_BYTES)); then
            work_root="$candidate"
            return 0
        fi
    done
    return 1
}

choose_work_root || die "no writable work root has at least $MIN_WORK_FREE_BYTES bytes free"
work_dir="$(mktemp -d "$work_root/maki-privileged-validation.XXXXXX")"
mountpoint="$work_dir/mnt"
mkdir "$mountpoint"
pass "disposable work tree allocated on $work_root"

if [[ -L /run/maki ]]; then
    die "/run/maki is a symlink; refusing to use it"
fi
if [[ ! -d /run/maki ]]; then
    sudo -n install -d -m 0755 /run/maki
    runtime_parent_created=true
fi
runtime_dir="/run/maki/$volume_name"
[[ ! -e "$runtime_dir" ]] || die "runtime collision: $runtime_dir"
sudo -n install -d -m 0700 -o "$(id -un)" -g "$(id -gn)" "$runtime_dir"
socket_path="$runtime_dir/nbd.sock"

config_path="$run_dir/volume.toml"
cat >"$config_path" <<EOF
config_schema_version = 1

[volume]
name = "$volume_name"
max_virtual_size = "512MiB"
device_block_size = 4096
crypto_unit_size = 4096
shard_logical_size = "16MiB"

[crypto]
provider = "fake"
crypto_compatibility_id = "privileged-validation-v1"

[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104

[backing]
root = "$work_dir/backing"

[nbd]
socket = "$socket_path"
device_block_size = 4096
minimum_io = 4096
preferred_io = 4096
maximum_io = "1MiB"
connections = 1
EOF

"$maki_bin" volume create "$config_path"
"$maki_bin" volume inspect "$config_path" | tee "$run_dir/volume-inspect.txt"
pass "disposable Maki volume created and inspected"

log "starting nbdkit as unprivileged user $(id -un)"
nbdkit --foreground -U "$socket_path" "$plugin_path" \
    config="$config_path" >"$run_dir/nbdkit.log" 2>&1 &
nbdkit_pid=$!
for _ in $(seq 1 200); do
    [[ -S "$socket_path" ]] && break
    kill -0 "$nbdkit_pid" 2>/dev/null || die "nbdkit exited before creating its socket"
    sleep 0.05
done
[[ -S "$socket_path" ]] || die "nbdkit socket did not become ready"
nbd_uri="nbd+unix:///?socket=$socket_path"
nbdinfo "$nbd_uri" >"$run_dir/nbdinfo-userspace.txt"
pass "nbdkit/libnbd negotiation over Unix socket"

effective_uid="$(awk '/^Uid:/ {print $3}' "/proc/$nbdkit_pid/status")"
effective_caps="$(awk '/^CapEff:/ {print $2}' "/proc/$nbdkit_pid/status")"
[[ "$effective_uid" == "$(id -u)" ]] || die "nbdkit effective UID is $effective_uid"
[[ "$effective_caps" == "0000000000000000" ]] || die "nbdkit CapEff is $effective_caps"
pass "nbdkit runs unprivileged with an empty effective capability set"

# The invoking user deliberately opens the log file so it is never root-owned.
# shellcheck disable=SC2024
if sudo -n -u nobody nbdinfo "$nbd_uri" >"$run_dir/unrelated-user-socket.txt" 2>&1; then
    die "unrelated user unexpectedly opened the protected NBD socket"
fi
pass "unrelated user is denied by the runtime-directory boundary"

duplicate_socket="$work_dir/duplicate.sock"
nbdkit --foreground -U "$duplicate_socket" "$plugin_path" \
    config="$config_path" >"$run_dir/duplicate-nbdkit.log" 2>&1 &
duplicate_pid=$!
for _ in $(seq 1 100); do
    [[ -S "$duplicate_socket" ]] && break
    kill -0 "$duplicate_pid" 2>/dev/null || break
    sleep 0.05
done
if [[ -S "$duplicate_socket" ]] &&
    nbdinfo "nbd+unix:///?socket=$duplicate_socket" >"$run_dir/duplicate-client.txt" 2>&1; then
    die "a second nbdkit process opened the already-attached Maki volume"
fi
stop_process_normally "$duplicate_pid" "duplicate nbdkit" || die "duplicate nbdkit did not stop"
duplicate_pid=""
pass "duplicate volume attach fails closed"

requested_devices=$((nbd_index + 1))
((requested_devices >= 16)) || requested_devices=16
sudo -n modprobe nbd "nbds_max=$requested_devices" max_part=8
[[ -b "$device" ]] ||
    die "$device was not created; if nbd was already loaded with fewer devices, choose an existing unused /dev/nbdN"
[[ ! -L "$device" ]] || die "$device is a symlink; refusing it"
device_major="$(lsblk -dn -o MAJ:MIN "$device" | awk -F: '{gsub(/[[:space:]]/, "", $1); print $1}')"
[[ "$device_major" == "43" ]] || die "$device has block major $device_major, expected Linux NBD major 43"

if findmnt -rn -S "$device" | grep -q .; then
    die "$device is already mounted"
fi
if lsblk -nr -o MOUNTPOINTS "$device" | grep -Eq '[^[:space:]]'; then
    die "$device or one of its children is already mounted"
fi
holders_dir="/sys/block/$(basename "$device")/holders"
if [[ -d "$holders_dir" ]] && find "$holders_dir" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    die "$device has block-device holders"
fi
if nbd_has_pid; then
    die "$device is already connected to an NBD server"
fi
existing_size="$(sudo -n blockdev --getsize64 "$device" 2>/dev/null || printf '0')"
[[ "$existing_size" == "0" ]] || die "$device already exposes $existing_size bytes"
pass "$device exists and is unused"

log "attaching the disposable export to $device"
nbd_connection_attempted=true
sudo -n nbd-client -unix "$socket_path" "$device" -b 4096
nbd_connected=true
for _ in $(seq 1 100); do
    attached_size="$(sudo -n blockdev --getsize64 "$device" 2>/dev/null || printf '0')"
    [[ "$attached_size" == "$VIRTUAL_SIZE_BYTES" ]] && break
    sleep 0.05
done
[[ "${attached_size:-0}" == "$VIRTUAL_SIZE_BYTES" ]] ||
    die "$device size is ${attached_size:-unknown}, expected $VIRTUAL_SIZE_BYTES"
pass "kernel NBD attach and 512 MiB geometry"

if nbd-client -d "$device" >"$run_dir/unprivileged-nbd-ioctl.txt" 2>&1; then
    nbd_connected=false
    die "the unprivileged invoking user unexpectedly disconnected $device"
fi
pass "unprivileged NBD disconnect ioctl is denied"

log "running CRC32C raw-device fio with periodic fsync"
# The invoking user deliberately opens the JSON output file.
# shellcheck disable=SC2024
sudo -n fio --name=maki-raw-verify --filename="$device" --ioengine=psync \
    --direct=1 --rw=write --bs=4k --size="$RAW_FIO_SIZE" --fsync=32 \
    --verify=crc32c --do_verify=1 --verify_fatal=1 --verify_state_save=0 \
    --output-format=json >"$run_dir/fio-raw.json"
sudo -n blockdev --flushbufs "$device"
pass "raw kernel-NBD fio write/read verification and flush"

log "creating disposable LVM and XFS layout on $device"
sudo -n pvcreate --yes --force "$device"
pv_created=true
sudo -n vgcreate "$vg_name" "$device"
vg_created=true
sudo -n lvcreate --yes -L "$LV_SIZE" -n "$lv_name" "$vg_name"
# The invoking user deliberately opens the log file.
# shellcheck disable=SC2024
sudo -n mkfs.xfs -f "/dev/$vg_name/$lv_name" >"$run_dir/mkfs-xfs.txt"
sudo -n vgchange -an "$vg_name"
sudo -n nbd-client -d "$device"
nbd_connected=false
pass "LVM physical/volume/logical volume and XFS creation"

"$attach_bin" attach --volume "$volume_name" --nbd-device "$device" \
    --vg "$vg_name" --lv "$lv_name" --mountpoint "$mountpoint" --plan \
    >"$run_dir/maki-attach-plan.txt"

log "running the real maki-attach helper"
nbd_connection_attempted=true
# The invoking user deliberately opens the log file.
# shellcheck disable=SC2024
sudo -n env PATH="$PATH" "$attach_bin" attach --volume "$volume_name" \
    --nbd-device "$device" --vg "$vg_name" --lv "$lv_name" --mountpoint "$mountpoint" \
    >"$run_dir/maki-attach.txt" 2>&1
nbd_connected=true
mount_active=true

mounted_fstype="$(findmnt -n -o FSTYPE -M "$mountpoint")"
mounted_source="$(findmnt -n -o SOURCE -M "$mountpoint")"
[[ "$mounted_fstype" == "xfs" ]] || die "mounted filesystem is $mounted_fstype, expected xfs"
[[ "$mounted_source" == "/dev/mapper/"* || "$mounted_source" == "/dev/$vg_name/$lv_name" ]] ||
    die "unexpected mount source: $mounted_source"
pass "maki-attach activated LVM and mounted XFS"

sudo -n install -d -m 0700 -o "$(id -un)" -g "$(id -gn)" "$mountpoint/work"
log "running filesystem fio as the unprivileged invoking user"
fio --name=maki-xfs-verify --filename="$mountpoint/work/fio.dat" --ioengine=psync \
    --direct=1 --rw=write --bs=4k --size="$FILE_FIO_SIZE" --fsync=32 \
    --verify=crc32c --do_verify=1 --verify_fatal=1 --verify_state_save=0 \
    --output-format=json >"$run_dir/fio-xfs.json"
pass "unprivileged fio verification through XFS"

log "running a safe SQLite WAL/integrity smoke test"
sqlite3 "$mountpoint/work/smoke.db" >"$run_dir/sqlite.txt" <<'SQL'
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
BEGIN IMMEDIATE;
CREATE TABLE payloads(id INTEGER PRIMARY KEY, payload BLOB NOT NULL);
WITH RECURSIVE seq(n) AS (
  VALUES(1)
  UNION ALL
  SELECT n + 1 FROM seq WHERE n < 10000
)
INSERT INTO payloads(id, payload) SELECT n, randomblob(256) FROM seq;
COMMIT;
PRAGMA wal_checkpoint(FULL);
PRAGMA integrity_check;
SQL
grep -qx 'ok' "$run_dir/sqlite.txt" || die "SQLite integrity_check did not return ok"
sync -f "$mountpoint/work"
pass "SQLite FULL-synchronous WAL checkpoint and integrity_check"

log "running the real maki-attach detach helper"
# The invoking user deliberately opens the log file.
# shellcheck disable=SC2024
sudo -n env PATH="$PATH" "$attach_bin" detach --volume "$volume_name" \
    --nbd-device "$device" --vg "$vg_name" --lv "$lv_name" --mountpoint "$mountpoint" \
    >"$run_dir/maki-detach.txt" 2>&1
mount_active=false
nbd_connected=false
pass "maki-attach clean unmount, LVM deactivation, and NBD disconnect"

log "removing the disposable LVM metadata"
sudo -n nbd-client -unix "$socket_path" "$device" -b 4096
nbd_connected=true
sudo -n vgchange -ay "$vg_name"
sudo -n lvremove --yes --force "/dev/$vg_name/$lv_name"
sudo -n vgremove --yes --force "$vg_name"
sudo -n pvremove --yes --force "$device"
vg_created=false
pv_created=false
sudo -n nbd-client -d "$device"
nbd_connected=false
pass "disposable LVM state removed"

stop_process_normally "$nbdkit_pid" "nbdkit" || die "nbdkit did not stop cleanly"
nbdkit_pid=""
"$maki_bin" check "$config_path" | tee "$run_dir/maki-check.txt"
pass "clean nbdkit shutdown and offline Maki check"

log "completed all non-crash privileged checks"
