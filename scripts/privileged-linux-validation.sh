#!/usr/bin/env bash
# Validate Maki through a disposable kernel NBD device, LVM, and XFS.
#
# The script deliberately refuses non-NBD targets and requires the selected
# device path to be repeated with --confirm-wipe.  It never unloads the NBD
# module, touches an already-connected device, or runs OOM or power-loss
# tests. Only --kill-daemon kills a process: the run's own nbdkit, with
# SIGKILL, under its mounted attachment.

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
# How often a release by hand looks, 100 ms apart, for the connection to go:
# the helper's own wait, 15 s.
readonly RELEASE_LOOKS=150

device="/dev/nbd15"
confirmed_device=""
work_root=""
run_dir=""
background=false
install_missing=false
preflight=false
discard=false
kill_daemon=false
prebuilt_dir=""

usage() {
    cat <<'EOF'
Usage:
  scripts/privileged-linux-validation.sh --preflight [--device /dev/nbdN]
  scripts/privileged-linux-validation.sh --background [--install-missing] \
      --device /dev/nbdN --confirm-wipe /dev/nbdN [--work-root DIR] [--discard] \
      [--kill-daemon] [--prebuilt DIR]

Options:
  --device PATH          Dedicated kernel NBD device (default: /dev/nbd15).
  --confirm-wipe PATH    Must exactly repeat --device. The exported test
                         volume is overwritten by fio, LVM, and mkfs.xfs.
  --work-root DIR        Filesystem used for disposable encrypted backing.
                         By default, choose /data or /var/tmp with enough room.
  --install-missing      On Debian, apt-install the native test dependencies.
  --background           Run under nohup and write a stable latest-log link.
  --discard              Create a v3 discard volume and check fstrim through
                         XFS, LVM and kernel NBD, then physical reclamation.
  --kill-daemon          After the detach and second attach, SIGKILL nbdkit
                         under the mounted attachment, require maki-attach
                         cleanup to release it, start a new nbdkit, attach a
                         third time and read the data back. Then SIGKILL it
                         again, disconnect the device over netlink and, while
                         it still shows the connection, unmount and remove
                         the mapping by hand, require cleanup's disconnected
                         recovery to retire the record, attach a fourth
                         time, read the data back and detach.
  --prebuilt DIR         Use DIR's maki, maki-attach and libmaki_nbdkit.so
                         (copied into the run directory) instead of building
                         them from the source snapshot; Cargo and rustc are
                         then not needed.
  --preflight            Show checks and missing commands without sudo or I/O.
  -h, --help             Show this help.

The run excludes OOM tests, power interruption, and any real disk, and
kills no process unless --kill-daemon is given. Only an unused /dev/nbdN is
accepted.
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
        --discard)
            discard=true
            shift
            ;;
        --kill-daemon)
            kill_daemon=true
            shift
            ;;
        --prebuilt)
            (($# >= 2)) || die "--prebuilt requires a value"
            prebuilt_dir="$2"
            shift 2
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
nbd_target="$(basename "$device")"
readonly nbd_target
((nbd_index <= 255)) || die "NBD index is unreasonably large: $nbd_index"

# Prebuilt artifacts are named by an absolute path, which the worker started
# from its source snapshot inherits, and must all be there.
readonly prebuilt_artifacts=(maki maki-attach libmaki_nbdkit.so)
if [[ -n "$prebuilt_dir" ]]; then
    prebuilt_dir="$(readlink -f -- "$prebuilt_dir")" || die "--prebuilt must name a directory"
    [[ -d "$prebuilt_dir" ]] || die "--prebuilt must name a directory"
    for artifact in "${prebuilt_artifacts[@]}"; do
        [[ -f "$prebuilt_dir/$artifact" ]] || die "--prebuilt $prebuilt_dir has no $artifact"
    done
fi

required_commands=(
    blkid blockdev dd df findmnt fio git lsblk lvcreate lvremove lvs mkfs.xfs
    modprobe nbdinfo nbdkit nm pvcreate pvremove pvs python3 setpriv sha256sum sqlite3
    sudo sync vgchange vgcreate vgremove vgs
)
if [[ -z "$prebuilt_dir" ]]; then
    required_commands+=(cargo rustc)
fi

if [[ "$discard" == true ]]; then
    required_commands+=(fstrim)
fi

# The release by hand before cleanup's disconnected recovery removes the
# mapping with it.
if [[ "$kill_daemon" == true ]]; then
    required_commands+=(dmsetup)
fi

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
    if [[ -n "$prebuilt_dir" ]]; then
        printf 'Artifacts:  prebuilt in %s\n' "$prebuilt_dir"
    else
        printf 'Artifacts:  built from the source snapshot\n'
    fi
    printf 'Scope:      kernel NBD -> raw fio -> LVM -> XFS -> file fio/SQLite\n'
    printf '            -> detach with an opener -> attach -> data read back\n'
    if [[ "$kill_daemon" == true ]]; then
        printf '            -> SIGKILL nbdkit -> cleanup -> new nbdkit -> attach\n'
        printf '            -> SIGKILL nbdkit -> disconnect, unmount, unmap by hand\n'
        printf '            -> cleanup (disconnected recovery) -> new nbdkit -> attach -> detach\n'
        printf 'Excluded:   OOM, power interruption, real disks\n'
    else
        printf 'Excluded:   forced crash, OOM, power interruption, real disks\n'
    fi
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

prepare_source_snapshot() {
    local revision
    mkdir "$run_dir/source" || return 1
    revision="$(python3 -B "$REPO_ROOT/scripts/qualification_source.py" --clean-head "$run_dir/source")" || return 1
    printf '%s\n' "$revision" > "$run_dir/source-revision"
}

umask 077
if [[ -z "$run_dir" ]]; then
    mkdir -p "$log_root"
    chmod 0700 "$log_root"
    run_stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    run_dir="${log_root}/maki-privileged-validation-${run_stamp}"
    mkdir "$run_dir"
    : >"$run_dir/run.log"
    printf 'state=starting\n' >"$run_dir/status"
    ln -sfn "$(basename "$run_dir")" "${log_root}/maki-privileged-validation.latest"

    if ! prepare_source_snapshot; then
        printf 'state=not-started\nexit_code=1\nreason=source-snapshot-failed\n' >"$run_dir/status"
        exit 1
    fi
    if [[ "$background" == true ]]; then
        printf 'sudo authentication is required once before the background run starts.\n'
    fi
    if ! sudo -v; then
        printf 'state=not-started\nexit_code=1\nreason=sudo-authentication-failed\n' \
            >"$run_dir/status"
        exit 1
    fi

    child_args=(--device "$device" --confirm-wipe "$confirmed_device" --run-dir "$run_dir")
    [[ -z "$work_root" ]] || child_args+=(--work-root "$work_root")
    [[ "$install_missing" == false ]] || child_args+=(--install-missing)
    [[ "$discard" == false ]] || child_args+=(--discard)
    [[ "$kill_daemon" == false ]] || child_args+=(--kill-daemon)
    [[ -z "$prebuilt_dir" ]] || child_args+=(--prebuilt "$prebuilt_dir")
    snapshot_runner="$run_dir/source/scripts/privileged-linux-validation.sh"
    if [[ "$background" == false ]]; then
        exec > >(tee -a "$run_dir/run.log") 2>&1
        exec "$snapshot_runner" "${child_args[@]}"
    fi
    nohup "$snapshot_runner" "${child_args[@]}" >"$run_dir/run.log" 2>&1 </dev/null &
    child_pid=$!
    printf '%s\n' "$child_pid" >"$run_dir/pid"

    printf 'Started PID %s\n' "$child_pid"
    printf 'Log:    %s/run.log\n' "$run_dir"
    printf 'Status: %s/status\n' "$run_dir"
    printf 'Latest: %s/maki-privileged-validation.latest\n' "$log_root"
    exit 0
fi

[[ "$background" == false ]] || die "--run-dir is internal and cannot be combined with --background"
[[ "$run_dir" == "$log_root"/maki-privileged-validation-* &&
   "$SCRIPT_PATH" == "$(readlink -f "$run_dir/source/scripts/privileged-linux-validation.sh")" ]] ||
    die "worker must run from its private source snapshot"
status_path="$run_dir/status"
printf 'state=running\npid=%s\n' "$$" >"$status_path"

work_dir=""
runtime_dir=""
runtime_parent_created=false
control_runtime_dir=""
control_runtime_parent_created=false
control_socket_path=""
attach_config_dir=""
attach_config_path=""
nbdkit_pid=""
duplicate_pid=""
opener_pid=""
sudo_keeper_pid=""
nbd_connection_id=""
helper_cleanup_needed=false
mount_active=false
vg_created=false
lv_created=false
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
    if kill -0 "$pid" 2>/dev/null; then
        log "cleanup: sending SIGTERM to $label (PID $pid)"
        kill -TERM "$pid" 2>/dev/null || true
        for _ in $(seq 1 100); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$pid" 2>/dev/null; then
            log "cleanup warning: $label did not stop after SIGTERM; no SIGKILL was sent"
            return 1
        fi
    fi
    local status=0
    wait "$pid" || status=$?
    if [[ "${3:-}" == clean && "$status" != 0 ]]; then
        log "$label exited with status $status"
        return 1
    fi
    return 0
}

nbd_has_pid() {
    local pid_file
    pid_file="/sys/block/$(basename "$device")/pid"
    [[ -r "$pid_file" ]] || return 1
    local value
    value="$(<"$pid_file")"
    [[ "$value" =~ ^[1-9][0-9]*$ ]]
}

test_nbd_action() {
    [[ -n "$nbd_connection_id" ]] || return 1
    sudo -n python3 "$REPO_ROOT/scripts/privileged_validation_nbd.py" \
        --device "$device" --identifier "$nbd_connection_id" --helper "$attach_bin" "$@"
}

connect_test_nbd() {
    # Record ownership before the helper's raw connect, including partial failures.
    # A disconnected phase gets a fresh identity; a cleanup retry keeps its own.
    if [[ -z "$nbd_connection_id" ]]; then
        nbd_connection_id="maki-privval-$(python3 -c 'import uuid; print(uuid.uuid4())')" || return 1
    fi
    test_nbd_action connect --socket "$socket_path"
}

disconnect_test_nbd() {
    [[ -n "$nbd_connection_id" ]] || return 0
    log "cleanup: disconnecting the owned backend on $device"
    if test_nbd_action disconnect; then
        nbd_connection_id=""
        return 0
    fi
    log "cleanup warning: could not prove or disconnect our backend on $device"
    return 1
}

remove_stale_test_socket() {
    local path="$1"
    if [[ -S "$path" && ! -L "$path" ]]; then
        log "cleanup: deleting stale test socket $path"
        unlink "$path"
    elif [[ -e "$path" || -L "$path" ]]; then
        log "cleanup warning: refusing unexpected runtime entry $path"
        return 1
    fi
}

cleanup() {
    local cleanup_rc=0 previous_connection_id
    set +e

    # An opener of the device that is still holding it would keep a
    # disconnect below from completing: ask it to let go, and wait for it.
    if [[ -n "${opener_pid:-}" ]]; then
        log "cleanup: asking the opener of $device (PID $opener_pid) to close it"
        : >"$run_dir/stop-opener"
        wait "$opener_pid" 2>/dev/null
        opener_pid=""
    fi

    # The helper's trusted record, not the raw connection identifier, owns this
    # phase. Never hold our attach lock while calling the helper itself.
    if [[ "$helper_cleanup_needed" == true ]]; then
        if sudo -n env PATH="$PATH" "$attach_bin" cleanup --volume "$volume_name" \
            --config "$attach_config_path" >"$run_dir/maki-cleanup-on-exit.txt" 2>&1; then
            helper_cleanup_needed=false
            mount_active=false
        else
            log "cleanup warning: helper cleanup failed; preserving its attachment and backing"
            cleanup_safe=false
            cleanup_rc=1
        fi
    fi

    if [[ "$cleanup_safe" == true ]] && { [[ "$mount_active" == true ]] ||
        { [[ -n "$mountpoint" ]] && findmnt -rn -M "$mountpoint" >/dev/null 2>&1; }; }; then
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
        if ! test_nbd_action check >/dev/null 2>&1; then
            previous_connection_id="$nbd_connection_id"
            log "cleanup: connecting our backend on $device to remove disposable LVM metadata"
            if [[ -z "$nbdkit_pid" ]] || ! kill -0 "$nbdkit_pid" 2>/dev/null || ! connect_test_nbd; then
                log "cleanup warning: could not reconnect $device for LVM cleanup"
                # A failed fresh connect can nevertheless have attached our
                # identifier. No LVM operation has used this connection yet.
                if [[ -z "$previous_connection_id" && -n "$nbd_connection_id" ]]; then
                    disconnect_test_nbd || true
                fi
                cleanup_safe=false
                cleanup_rc=1
            fi
        fi

        if [[ "$cleanup_safe" == true ]]; then
            if [[ "$lv_created" == true ]]; then
                test_nbd_action activate-vg --vg "$vg_name" >/dev/null 2>&1 || true
                if test_nbd_action remove-lv --vg "$vg_name" --lv "$lv_name" >/dev/null 2>&1; then
                    lv_created=false
                else
                    log "cleanup warning: preserving lower layers after LV removal failed"
                    cleanup_safe=false
                    cleanup_rc=1
                fi
            fi
            if [[ "$vg_created" == true && "$cleanup_safe" == true ]]; then
                if test_nbd_action remove-vg --vg "$vg_name" >/dev/null 2>&1; then
                    vg_created=false
                else
                    log "cleanup warning: could not remove test VG $vg_name"
                    cleanup_safe=false
                    cleanup_rc=1
                fi
            fi
            if [[ "$pv_created" == true && "$cleanup_safe" == true ]]; then
                if test_nbd_action remove-pv >/dev/null 2>&1; then
                    pv_created=false
                else
                    log "cleanup warning: could not remove test PV on $device"
                    cleanup_safe=false
                    cleanup_rc=1
                fi
            fi
        else
            log "cleanup warning: preserving test LVM metadata without a proven own connection"
            cleanup_safe=false
            cleanup_rc=1
        fi
    fi

    if [[ "$cleanup_safe" == true ]] && ! disconnect_test_nbd; then
        cleanup_safe=false
        cleanup_rc=1
    fi

    if [[ "$cleanup_safe" == false ]]; then
        if [[ -n "$sudo_keeper_pid" ]]; then
            : >"$run_dir/stop-sudo-keeper"
            kill -TERM "$sudo_keeper_pid" 2>/dev/null || true
            wait "$sudo_keeper_pid" 2>/dev/null || true
        fi
        return "$cleanup_rc"
    fi

    if stop_process_normally "$duplicate_pid" "duplicate nbdkit"; then
        duplicate_pid=""
    else
        cleanup_rc=1
        cleanup_safe=false
    fi
    if ! stop_process_normally "$nbdkit_pid" "nbdkit"; then
        cleanup_rc=1
        cleanup_safe=false
    fi
    nbdkit_pid=""

    if [[ "$cleanup_safe" == true && -n "$runtime_dir" && "$runtime_dir" == /run/maki/privval-* ]]; then
        remove_stale_test_socket "$runtime_dir/nbd.sock" || cleanup_rc=1
        remove_stale_test_socket "$runtime_dir/duplicate.sock" || cleanup_rc=1
        if ! sudo -n rmdir "$runtime_dir"; then
            log "cleanup warning: could not remove test runtime directory $runtime_dir"
            cleanup_rc=1
        fi
    fi
    if [[ "$runtime_parent_created" == true && ! -e "$runtime_dir" ]]; then
        if ! sudo -n rmdir /run/maki; then
            log "cleanup warning: could not remove test-created /run/maki"
            cleanup_rc=1
        fi
    fi

    if [[ "$cleanup_safe" == true && -n "$control_runtime_dir" && "$control_runtime_dir" == /run/maki-control/privval-* ]]; then
        remove_stale_test_socket "$control_runtime_dir/control.sock" || cleanup_rc=1
        remove_stale_test_socket "$control_runtime_dir/duplicate-control.sock" || cleanup_rc=1
        if ! sudo -n rmdir "$control_runtime_dir"; then
            log "cleanup warning: could not remove test control runtime directory $control_runtime_dir"
            cleanup_rc=1
        fi
    fi
    if [[ "$control_runtime_parent_created" == true && ! -e "$control_runtime_dir" ]]; then
        if ! sudo -n rmdir /run/maki-control; then
            log "cleanup warning: could not remove test-created /run/maki-control"
            cleanup_rc=1
        fi
    fi

    if [[ -n "$attach_config_dir" ]]; then
        case "$attach_config_dir" in
            /run/maki-attach-validation-*)
                if [[ -n "$attach_config_path" && "$attach_config_path" == "$attach_config_dir/attach.toml" ]]; then
                    sudo -n rm -f -- "$attach_config_path" || cleanup_rc=1
                else
                    log "cleanup warning: refusing unexpected attach config path $attach_config_path"
                    cleanup_rc=1
                fi
                sudo -n rmdir "$attach_config_dir" 2>/dev/null || cleanup_rc=1
                ;;
            *)
                log "cleanup warning: refusing unexpected attach config directory $attach_config_dir"
                cleanup_rc=1
                ;;
        esac
    fi

    if [[ -n "$mountpoint" && "$cleanup_safe" == true && "$mount_active" != true ]]; then
        case "$mountpoint" in
            /run/maki-validation-mnt.*)
                if ! findmnt -rn -M "$mountpoint" >/dev/null 2>&1; then
                    sudo -n rmdir "$mountpoint" 2>/dev/null || cleanup_rc=1
                fi
                ;;
            *)
                log "cleanup warning: refusing unexpected mountpoint $mountpoint"
                cleanup_rc=1
                ;;
        esac
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
    trap - EXIT INT TERM HUP ERR
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
# set -e stops at a failed command without naming it: say which one did.
trap 'log "FAILED: status $? at line $LINENO: $BASH_COMMAND"' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

log "Maki privileged Linux validation"
log "repository: $REPO_ROOT"
log "revision: $(<"$run_dir/source-revision")"
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

    apt_source_args=()
    if [[ "${ID:-}" == "debian" && -r /etc/apt/sources.list.d/debian.sources ]]; then
        # Ignore unrelated third-party repositories for this test-only install.
        # This avoids changing host configuration and keeps every package on
        # the distribution's signed Debian sources.
        apt_source_args=(
            -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/debian.sources
            -o Dir::Etc::sourceparts=-
        )
        log "using only /etc/apt/sources.list.d/debian.sources"
    fi

    log "installing native validation dependencies with apt"
    sudo -n env DEBIAN_FRONTEND=noninteractive apt-get "${apt_source_args[@]}" update
    sudo -n env DEBIAN_FRONTEND=noninteractive apt-get "${apt_source_args[@]}" \
        install -y --no-install-recommends binutils fio kmod libnbd-bin lvm2 \
        nbdkit nbdkit-plugin-dev python3 sqlite3 util-linux xfsprogs
    pass "native validation dependencies installed"
fi

mapfile -t still_missing < <(missing_commands)
((${#still_missing[@]} == 0)) ||
    die "missing commands: ${still_missing[*]} (rerun with --install-missing on Debian)"
[[ "$(fio --version)" =~ ^fio-[0-9] ]] || die "fio resolves to an unexpected executable: $(fio --version)"
pass "required native tools available"

readonly build_target_dir="$run_dir/target"
if [[ -n "$prebuilt_dir" ]]; then
    # Bind this run to its own copies, as a build binds it to its own outputs:
    # a later change in the given directory does not reach the run.
    log "copying the prebuilt release binaries and nbdkit plugin from $prebuilt_dir"
    release_dir="$build_target_dir/prebuilt"
    mkdir -p "$release_dir"
    install -m 0755 "$prebuilt_dir/maki" "$prebuilt_dir/maki-attach" "$release_dir/"
    install -m 0644 "$prebuilt_dir/libmaki_nbdkit.so" "$release_dir/"
    printf 'prebuilt %s\n' "$prebuilt_dir" >"$run_dir/artifact-origin"
else
log "building release binaries and nbdkit plugin"
# Bind this run to its own build outputs, even when Cargo configuration or
# environment variables select a shared directory or a cross-compilation target.
native_target="$(cd "$REPO_ROOT" && rustc -vV | sed -n 's/^host: //p')"
[[ "$native_target" =~ ^[a-zA-Z0-9_.-]+$ ]] || die "cannot determine native Rust target"
readonly native_target
log "native build target: $native_target ($build_target_dir)"
(
    cd "$REPO_ROOT"
    CARGO_BUILD_BUILD_DIR="$run_dir/build" \
    cargo build --manifest-path "$REPO_ROOT/Cargo.toml" --release --locked \
        --target-dir "$build_target_dir" --target "$native_target" \
        -p maki -p maki-attach -p maki-nbdkit
)
release_dir="$build_target_dir/$native_target/release"
printf 'built from the source snapshot for %s\n' "$native_target" >"$run_dir/artifact-origin"
fi
readonly release_dir
readonly maki_bin="$release_dir/maki"
readonly attach_bin="$release_dir/maki-attach"
readonly plugin_path="$release_dir/libmaki_nbdkit.so"
[[ -x "$maki_bin" && -x "$attach_bin" && -f "$plugin_path" ]] ||
    die "release artifacts are incomplete"
nm -D --defined-only "$plugin_path" | grep -Eq '[[:space:]]T[[:space:]]plugin_init$' ||
    die "plugin_init is not exported by $plugin_path"
(cd "$release_dir" &&
    sha256sum maki maki-attach libmaki_nbdkit.so) >"$run_dir/artifact-sha256"
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
# maki-attach mounts only onto a root-owned directory whose every ancestor is
# root-owned and not group/other writable (69514ea, R5-024): a user-owned
# work tree or /var/tmp (1777) never qualifies, so the mountpoint is a
# root-created directory under /run.
mountpoint="$(sudo -n mktemp -d /run/maki-validation-mnt.XXXXXX)" ||
    die "could not create a root-owned mountpoint under /run"
pass "disposable work tree allocated on $work_root, mountpoint $mountpoint"

if [[ -L /run/maki ]]; then
    die "/run/maki is a symlink; refusing to use it"
fi
if [[ ! -d /run/maki ]]; then
    sudo -n install -d -m 0755 /run/maki
    runtime_parent_created=true
fi
runtime_dir_candidate="/run/maki/$volume_name"
[[ ! -e "$runtime_dir_candidate" ]] || die "runtime collision: $runtime_dir_candidate"
sudo -n install -d -m 0700 -o "$(id -un)" -g "$(id -gn)" "$runtime_dir_candidate"
runtime_dir="$runtime_dir_candidate"
socket_path="$runtime_dir/nbd.sock"

if [[ -L /run/maki-control ]]; then
    die "/run/maki-control is a symlink; refusing to use it"
fi
if [[ ! -d /run/maki-control ]]; then
    sudo -n install -d -m 0755 /run/maki-control
    control_runtime_parent_created=true
fi
control_runtime_dir_candidate="/run/maki-control/$volume_name"
[[ ! -e "$control_runtime_dir_candidate" ]] ||
    die "control runtime collision: $control_runtime_dir_candidate"
sudo -n install -d -m 0700 -o "$(id -un)" -g "$(id -gn)" "$control_runtime_dir_candidate"
control_runtime_dir="$control_runtime_dir_candidate"
control_socket_path="$control_runtime_dir/control.sock"

config_path="$run_dir/volume.toml"
key_path="$work_dir/local-aes-gcm-siv.key"
dd if=/dev/urandom of="$key_path" bs=32 count=1 status=none
chmod 0600 "$key_path"
# Both daemons must reach the same backing with the same crypto identity.
# Only their NBD and control listener paths differ.
write_validation_config() {
python3 - "$1" "$volume_name" "$key_path" "$work_dir/backing" \
    "$2" "$3" <<'PY'
import json
import pathlib
import sys

config_path = pathlib.Path(sys.argv[1])
# JSON's quoted strings use TOML basic-string escapes. Preserve Unicode to avoid
# surrogate-pair escapes, and escape DEL, which JSON allows but TOML forbids.
volume_name, key_path, backing_root, socket_path, control_socket_path = (
    json.dumps(value, ensure_ascii=False).replace("\x7f", r"\u007f")
    for value in sys.argv[2:]
)
config_path.write_text(f"""config_schema_version = 1

[volume]
name = {volume_name}
max_virtual_size = "512MiB"
device_block_size = 4096
crypto_unit_size = 4096
shard_logical_size = "16MiB"

[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "privileged-validation-v1"
key = {{ source = "file", name = {key_path} }}

[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4124

[backing]
root = {backing_root}
journal_segment_size = "16MiB"
journal_max_bytes = "128MiB"
checkpoint_reserve_bytes = "16MiB"
journal_emergency_reserve_bytes = "8MiB"

[nbd]
socket = {socket_path}
device_block_size = 4096
minimum_io = 4096
preferred_io = 4096
maximum_io = "1MiB"
connections = 1

[control]
socket = {control_socket_path}
""", encoding="utf-8")
PY
}
write_validation_config "$config_path" "$socket_path" "$control_socket_path"

if [[ "$discard" == true ]]; then
    "$maki_bin" volume create "$config_path" --discard
else
    "$maki_bin" volume create "$config_path"
fi
"$maki_bin" volume inspect "$config_path" | tee "$run_dir/volume-inspect.txt"
volume_uuid="$(awk '$1 == "uuid:" { print $2 }' "$run_dir/volume-inspect.txt")"
[[ "$volume_uuid" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]] ||
    die "volume inspect returned an invalid UUID"
pass "disposable Maki volume created and inspected"

log "starting nbdkit as unprivileged user $(id -un) with no-new-privileges"
nbdkit_launcher=(setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all)
"${nbdkit_launcher[@]}" nbdkit --foreground -U "$socket_path" "$plugin_path" \
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
no_new_privileges="$(awk '/^NoNewPrivs:/ {print $2}' "/proc/$nbdkit_pid/status")"
[[ "$effective_uid" == "$(id -u)" ]] || die "nbdkit effective UID is $effective_uid"
[[ "$effective_caps" == "0000000000000000" ]] || die "nbdkit CapEff is $effective_caps"
[[ "$no_new_privileges" == "1" ]] || die "nbdkit NoNewPrivs is $no_new_privileges"
pass "nbdkit runs unprivileged with no-new-privileges and empty effective capabilities"

# The invoking user deliberately opens the log file so it is never root-owned.
# shellcheck disable=SC2024
if sudo -n -u nobody nbdinfo "$nbd_uri" >"$run_dir/unrelated-user-socket.txt" 2>&1; then
    die "unrelated user unexpectedly opened the protected NBD socket"
fi
# libnbd reports a failed connect(2) as "<call>: connect: <strerror>". Only
# EACCES is the boundary: a sudo policy or password refusal, a missing
# command, or a refused, absent or reset socket proves nothing about it.
grep -Eq '(^|[[:space:]])connect: Permission denied' "$run_dir/unrelated-user-socket.txt" ||
    die "unrelated user was not refused with EACCES on the NBD socket: $(cat "$run_dir/unrelated-user-socket.txt")"
pass "unrelated user is denied by the runtime-directory boundary"

duplicate_socket="$runtime_dir/duplicate.sock"
duplicate_config_path="$run_dir/duplicate-volume.toml"
write_validation_config "$duplicate_config_path" "$duplicate_socket" "$control_runtime_dir/duplicate-control.sock"
"${nbdkit_launcher[@]}" nbdkit --foreground -U "$duplicate_socket" "$plugin_path" \
    config="$duplicate_config_path" >"$run_dir/duplicate-nbdkit.log" 2>&1 &
duplicate_pid=$!
# nbdkit binds its socket before plugin startup. A socket or failed client
# negotiation alone cannot establish that recovery reached the volume lock.
for _ in $(seq 1 100); do
    kill -0 "$duplicate_pid" 2>/dev/null || break
    sleep 0.05
done
if kill -0 "$duplicate_pid" 2>/dev/null; then
    die "duplicate nbdkit did not exit after volume-lock rejection; see duplicate-nbdkit.log"
fi
duplicate_status=0
wait "$duplicate_pid" || duplicate_status=$?
duplicate_pid=""
printf '%s\n' "$duplicate_status" >"$run_dir/duplicate-nbdkit.exit"
[[ "$duplicate_status" == 1 ]] ||
    die "duplicate nbdkit exited with status $duplicate_status, expected startup failure status 1"
grep -Fxq 'maki-nbdkit: startup failed: adapter error (errno 5): VOLUME_ALREADY_ATTACHED' \
    "$run_dir/duplicate-nbdkit.log" ||
    die "duplicate nbdkit failed without the volume-lock rejection; see duplicate-nbdkit.log"
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
connect_test_nbd
for _ in $(seq 1 100); do
    attached_size="$(sudo -n blockdev --getsize64 "$device" 2>/dev/null || printf '0')"
    [[ "$attached_size" == "$VIRTUAL_SIZE_BYTES" ]] && break
    sleep 0.05
done
[[ "${attached_size:-0}" == "$VIRTUAL_SIZE_BYTES" ]] ||
    die "$device size is ${attached_size:-unknown}, expected $VIRTUAL_SIZE_BYTES"
pass "kernel NBD attach and 512 MiB geometry"

# The invoking user runs the helper's own disconnect, which reads the
# backend identifier and sends NBD_CMD_DISCONNECT over netlink: only the
# kernel's EPERM for a sender without CAP_SYS_ADMIN, with this run's backend
# still connected, is a denial. A usage, identity, module or executable error
# is not.
if "$attach_bin" nbd-disconnect --nbd-device "$device" --identifier "$nbd_connection_id" \
    >"$run_dir/unprivileged-nbd-disconnect.txt" 2>&1; then
    die "the unprivileged invoking user unexpectedly disconnected $device"
fi
grep -Fq "the kernel refused NBD_CMD_DISCONNECT for $nbd_target: Operation not permitted" \
    "$run_dir/unprivileged-nbd-disconnect.txt" ||
    die "unprivileged NBD disconnect failed without the kernel's permission denial: $(cat "$run_dir/unprivileged-nbd-disconnect.txt")"
test_nbd_action check ||
    die "our backend on $device did not survive the unprivileged disconnect attempt"
pass "the kernel denies an unprivileged NBD disconnect"

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
lv_created=true
sudo -n lvcreate --yes -L "$LV_SIZE" -n "$lv_name" "$vg_name"
# The invoking user deliberately opens the log file.
# shellcheck disable=SC2024
sudo -n mkfs.xfs -f "/dev/$vg_name/$lv_name" >"$run_dir/mkfs-xfs.txt"
pv_uuid="$(sudo -n pvs --readonly --noheadings -o pv_uuid "$device" | awk 'NF { print $1; exit }')"
vg_uuid="$(sudo -n vgs --readonly --noheadings -o vg_uuid "$vg_name" | awk 'NF { print $1; exit }')"
lv_uuid="$(sudo -n lvs --readonly --noheadings -o lv_uuid "$vg_name/$lv_name" | awk 'NF { print $1; exit }')"
fs_uuid="$(sudo -n blkid --probe --cache-file /dev/null --match-tag UUID --output value "/dev/$vg_name/$lv_name")"
for observed_uuid in "$pv_uuid" "$vg_uuid" "$lv_uuid"; do
    [[ "$observed_uuid" =~ ^[[:alnum:]]{6}(-[[:alnum:]]{4}){5}-[[:alnum:]]{6}$ ]] ||
        die "LVM inventory returned an invalid UUID"
done
[[ "$fs_uuid" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]] ||
    die "filesystem inventory returned an invalid UUID"
sudo -n vgchange -an "$vg_name"
disconnect_test_nbd
pass "LVM physical/volume/logical volume and XFS creation"

attach_config_dir_candidate="/run/maki-attach-validation-$volume_name"
[[ ! -e "$attach_config_dir_candidate" ]] || die "attach config runtime collision: $attach_config_dir_candidate"
sudo -n install -d -m 0700 -o root -g root "$attach_config_dir_candidate"
attach_config_dir="$attach_config_dir_candidate"
attach_config_path="$attach_config_dir/attach.toml"
cat >"$run_dir/attach.toml" <<EOF
volume_uuid = "$volume_uuid"
nbd_device = "$device"
nbd_socket = "$socket_path"
device_block_size = 4096
vg_name = "$vg_name"
lv_name = "$lv_name"
mountpoint = "$mountpoint"
fs_uuid = "$fs_uuid"
init_sentinel = true

[lvm_identity]
pv_uuids = ["$pv_uuid"]
vg_uuid = "$vg_uuid"
lv_uuid = "$lv_uuid"
EOF
sudo -n install -m 0600 -o root -g root "$run_dir/attach.toml" "$attach_config_path"

sudo -n env PATH="$PATH" "$attach_bin" attach --volume "$volume_name" \
    --config "$attach_config_path" --plan \
    >"$run_dir/maki-attach-plan.txt"

log "running the real maki-attach helper"
helper_cleanup_needed=true
# The invoking user deliberately opens the log file.
# shellcheck disable=SC2024
sudo -n env PATH="$PATH" "$attach_bin" attach --volume "$volume_name" \
    --config "$attach_config_path" \
    >"$run_dir/maki-attach.txt" 2>&1
mount_active=true

mounted_fstype="$(findmnt -n -o FSTYPE -M "$mountpoint")"
mounted_source="$(findmnt -n -o SOURCE -M "$mountpoint")"
[[ "$mounted_fstype" == "xfs" ]] || die "mounted filesystem is $mounted_fstype, expected xfs"
[[ "$mounted_source" == "/dev/mapper/"* || "$mounted_source" == "/dev/$vg_name/$lv_name" ]] ||
    die "unexpected mount source: $mounted_source"
pass "maki-attach activated LVM and mounted XFS"

# R5-002: the volume's bytes come from the unprivileged daemon, so setuid
# bits and device nodes on it must never take effect.
mount_options="$(findmnt -n -o OPTIONS -M "$mountpoint")"
for required in nosuid nodev; do
    [[ ",$mount_options," == *",$required,"* ]] ||
        die "mount options lack $required: $mount_options"
done
pass "XFS is mounted nosuid,nodev ($mount_options)"

# R5-030: executing verbs refuse an attach config a non-root user controls,
# before touching any state (a second attach would otherwise be refused for
# the live record, not for the config).
untrusted_config="$run_dir/untrusted-attach.toml"
sudo -n cat "$attach_config_path" >"$untrusted_config"
chmod 0600 "$untrusted_config"
if sudo -n env PATH="$PATH" "$attach_bin" attach --volume "$volume_name" \
    --config "$untrusted_config" >"$run_dir/maki-untrusted-config.txt" 2>&1; then
    die "maki-attach accepted an attach config owned by $(id -un)"
fi
grep -q 'root-owned' "$run_dir/maki-untrusted-config.txt" ||
    die "untrusted attach config was refused for another reason: $(cat "$run_dir/maki-untrusted-config.txt")"
pass "maki-attach refuses an attach config a non-root user controls"

sudo -n env PATH="$PATH" "$attach_bin" verify --volume "$volume_name" \
    --config "$attach_config_path" >"$run_dir/maki-verify-before-workload.txt" 2>&1
pass "root-controlled workload gate verified pinned storage identity"

sudo -n install -d -m 0700 -o "$(id -un)" -g "$(id -gn)" "$mountpoint/work"
log "running filesystem fio as the unprivileged invoking user"
fio --name=maki-xfs-verify --filename="$mountpoint/work/fio.dat" --ioengine=psync \
    --direct=1 --rw=write --bs=4k --size="$FILE_FIO_SIZE" --fsync=32 \
    --verify=crc32c --do_verify=1 --verify_fatal=1 --verify_state_save=0 \
    --output-format=json >"$run_dir/fio-xfs.json"
pass "unprivileged fio verification through XFS"

verify_sqlite_result() {
    local -a rows
    mapfile -t rows < "$1" || return 1
    [[ ${#rows[@]} == 3 && "${rows[0]}" == wal && "${rows[2]}" == ok &&
       "${rows[1]}" =~ ^0\|([0-9]+)\|([0-9]+)$ ]] &&
        [[ "${BASH_REMATCH[1]}" == "${BASH_REMATCH[2]}" ]]
}

log "running a safe SQLite WAL/integrity smoke test"
sqlite3 -batch -bail -noheader -separator '|' "$mountpoint/work/smoke.db" >"$run_dir/sqlite.txt" <<'SQL'
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
verify_sqlite_result "$run_dir/sqlite.txt" || die "SQLite WAL mode, FULL checkpoint or integrity check failed"
sync -f "$mountpoint/work"
pass "SQLite FULL-synchronous WAL checkpoint and integrity_check"

sudo -n env PATH="$PATH" "$attach_bin" verify --volume "$volume_name" \
    --config "$attach_config_path" >"$run_dir/maki-verify-after-workload.txt" 2>&1
pass "workload gate still verifies the live attachment after database I/O"

if [[ "$discard" == true ]]; then
    # R5-010/R5-011: kernel discards are far longer than nbd.maximum_io and
    # used to fail with EINVAL. Free the fio file, trim, checkpoint, and
    # require the backing to release physical blocks.
    discard_max="$(cat "/sys/block/$nbd_target/queue/discard_max_bytes")"
    log "kernel discard_max_bytes for $nbd_target: $discard_max"
    ((discard_max > 0)) || die "kernel NBD device does not accept discards"
    rm -f "$mountpoint/work/fio.dat"
    sync -f "$mountpoint/work"
    "$maki_bin" checkpoint "$config_path" >"$run_dir/checkpoint-before-trim.txt"
    allocated_before="$(du -sB1 "$work_dir/backing/data" | awk '{print $1}')"
    "$maki_bin" status "$config_path" >"$run_dir/status-before-trim.txt"
    sudo -n fstrim -v "$mountpoint" | tee "$run_dir/fstrim.txt"
    # The kernel issues discards without FUA and a checkpoint applies only
    # durable records: fsync the block device, which the kernel turns into a
    # cache flush (an NBD FLUSH). `blockdev --flushbufs` only writes back and
    # drops the page cache and sends no flush.
    sudo -n sync "$device"
    "$maki_bin" status "$config_path" >"$run_dir/status-after-trim.txt"
    "$maki_bin" checkpoint "$config_path" >"$run_dir/checkpoint-after-trim.txt"
    allocated_after="$(du -sB1 "$work_dir/backing/data" | awk '{print $1}')"
    log "backing data allocated: $allocated_before -> $allocated_after bytes"
    ((allocated_before - allocated_after >= 32 << 20)) ||
        die "fstrim released only $((allocated_before - allocated_after)) bytes of the 64 MiB fio file"
    sudo -n env PATH="$PATH" "$attach_bin" verify --volume "$volume_name" \
        --config "$attach_config_path" >"$run_dir/maki-verify-after-trim.txt" 2>&1
    pass "fstrim through XFS, LVM and kernel NBD released backing space"
fi

# The attachment's lifecycle on this kernel. Data is written and fsynced; a
# detach finds the device still held open after its disconnect, which its
# final teardown must wait for (AUD-197); a second attach reads the data
# back. With --kill-daemon, nbdkit is then killed under the mount, cleanup
# must release the attachment without it, and a new nbdkit and a third attach
# read the data back. nbdkit is killed again, the device is disconnected and
# released by hand, cleanup must retire the record by disconnected recovery,
# and a new nbdkit and a fourth attach read the data back before the final
# detach. Each cleanup must take the path for what the device showed, and
# every teardown must leave no mount, holder, connection or attach record.

# Run one maki-attach verb on this run's volume. Its output goes to the log
# and to $run_dir/<evidence>.txt, and its exit status is the function's.
run_helper() {
    local verb="$1" evidence="$2" started status=0
    started="$(date +%s%N)"
    log "running the real maki-attach $verb ($evidence.txt)"
    sudo -n env PATH="$PATH" "$attach_bin" "$verb" --volume "$volume_name" \
        --config "$attach_config_path" 2>&1 | tee "$run_dir/$evidence.txt" || status=$?
    log "maki-attach $verb exited with status $status after $((($(date +%s%N) - started) / 1000000)) ms"
    return "$status"
}

# Look for the helper's attach record as root. record_state is "present" or
# "absent"; a look that fails stops the run, since it shows neither.
attach_record_state() {
    local record="/run/maki-attach/$volume_name.nbd" state
    state="$(sudo -n sh -c 'if [ -e "$1" ] || [ -L "$1" ]; then echo present; else echo absent; fi' \
        sh "$record")" || state=""
    case "$state" in
        present|absent) record_state="$state" ;;
        *) die "could not look for the attach record $record" ;;
    esac
}

# What an attach ($1) must show, which require_released then looks for: the
# mount, the attachment's backend identifier on the device and its record.
require_attached() {
    local backend=""
    findmnt -rn -M "$mountpoint" >/dev/null 2>&1 || die "$1 left $mountpoint unmounted"
    if [[ -r "/sys/block/$nbd_target/backend" ]]; then
        backend="$(<"/sys/block/$nbd_target/backend")"
    fi
    [[ "$backend" == maki-* ]] ||
        die "$1 left $device without the attachment's backend identifier (${backend:-none})"
    attach_record_state
    [[ "$record_state" == present ]] ||
        die "$1 left no attach record at /run/maki-attach/$volume_name.nbd"
    pass "$1 shows the mount, the connection $backend and the attach record"
}

# What a detach or cleanup ($1) must leave: no mount at the mountpoint, no
# holder of the device, no connection, a size of 0 and no attach record.
require_released() {
    local holders backend="" size
    if findmnt -rn -M "$mountpoint" >/dev/null 2>&1; then
        die "$1 left $mountpoint mounted"
    fi
    holders="$(find "/sys/block/$nbd_target/holders" -mindepth 1 -maxdepth 1 -printf '%f ')"
    [[ -z "$holders" ]] || die "$1 left holders of $device: $holders"
    if [[ -r "/sys/block/$nbd_target/backend" ]]; then
        backend="$(<"/sys/block/$nbd_target/backend")"
    fi
    if [[ -n "$backend" ]] || nbd_has_pid; then
        die "$1 left $device connected (backend ${backend:-not shown})"
    fi
    size="$(sudo -n blockdev --getsize64 "$device")"
    [[ "$size" == 0 ]] || die "$1 left $device exposing $size bytes"
    attach_record_state
    [[ "$record_state" == absent ]] ||
        die "$1 left the attach record /run/maki-attach/$volume_name.nbd"
    pass "$1 left no mount, holder, connection or attach record"
}

# Whether process $1 still runs, read from /proc: a zombie the shell has not
# reaped yet has gone. Unlike kill -0 this needs no permission to signal it.
# sudo checks its policy with real, effective and saved uid 0 (sudoers'
# PERM_ROOT), so for that moment the invoking user's kill -0 on its PID fails
# with EPERM although it runs: in the Debian 12 guest the wait for the opener
# stopped so at its first look.
process_running() {
    local stat
    { read -r stat <"/proc/$1/stat"; } 2>/dev/null || return 1
    [[ "${stat##*) }" != Z* ]]
}

# Start an opener of the device (privileged_validation_opener.py) and wait
# until it holds the device.
hold_device_open() {
    rm -f "$run_dir/stop-opener"
    : >"$run_dir/detach-opener.txt"
    # The invoking user deliberately opens the log file.
    # shellcheck disable=SC2024
    sudo -n python3 -B "$REPO_ROOT/scripts/privileged_validation_opener.py" \
        --device "$device" --stop-file "$run_dir/stop-opener" \
        >>"$run_dir/detach-opener.txt" 2>&1 &
    opener_pid=$!
    for _ in $(seq 1 200); do
        grep -q ' holding the device open' "$run_dir/detach-opener.txt" && return 0
        process_running "$opener_pid" || break
        sleep 0.05
    done
    cat "$run_dir/detach-opener.txt" >&2
    die "the opener did not start holding $device"
}

# The opener's verdict: it saw the disconnect while it held the device, and
# the device kept showing the connection until it closed.
finish_opener() {
    local status=0
    wait "$opener_pid" || status=$?
    opener_pid=""
    cat "$run_dir/detach-opener.txt"
    [[ "$status" == 0 ]] ||
        die "the opener of $device exited with status $status; see detach-opener.txt above"
}

# The files written before the first detach must read back unchanged ($1:
# after what).
check_lifecycle_data() {
    (cd "$mountpoint/work" && sha256sum --check --strict "$run_dir/lifecycle.sha256") 2>&1 |
        tee "$run_dir/lifecycle-check-$1.txt" ||
        die "data written before the first detach changed after the $1"
    pass "data written and fsynced before the first detach reads back unchanged after the $1"
}

# The backend identifier the device shows, or nothing.
shown_backend() {
    tr -d '\n' 2>/dev/null <"/sys/block/$nbd_target/backend" || true
}

# The path a cleanup ($1.txt) took must be the one for what the device showed
# before it ($2: the attachment's backend identifier, or empty for none): the
# helper logs the path it takes.
require_cleanup_path() {
    local expected
    if [[ -n "$2" ]]; then
        expected="maki-attach: $device shows the attachment's connection; cleanup follows the detach path"
    else
        expected="maki-attach: $device shows no connection; cleanup follows disconnected recovery"
    fi
    grep -Fq -- "$expected" "$run_dir/$1.txt" ||
        die "cleanup did not say it took the path for a device that showed ${2:-no connection}: $1.txt lacks '$expected'"
    pass "cleanup took the path for a device that showed ${2:-no connection}: ${expected##*; }"
}

# SIGKILL nbdkit under the mounted attachment ($1: when), once what was
# written is synced.
kill_nbdkit() {
    local killed_status=0 shown
    log "killing nbdkit (PID $nbdkit_pid) with SIGKILL under the mounted attachment, $1"
    sync -f "$mountpoint/work"
    kill -KILL "$nbdkit_pid"
    wait "$nbdkit_pid" || killed_status=$?
    nbdkit_pid=""
    [[ "$killed_status" == 137 ]] ||
        die "nbdkit exited with status $killed_status, not 137 (SIGKILL)"
    shown="$(shown_backend)"
    log "with nbdkit dead, $device shows backend ${shown:-none}"
    pass "nbdkit was killed with SIGKILL while XFS was mounted, $1"
}

# Start a new nbdkit on the same backing ($1: after what), which must
# recover the volume and negotiate; nbdinfo's output goes to $run_dir/$2.txt.
start_nbdkit() {
    log "starting a new nbdkit on the same backing, $1"
    remove_stale_test_socket "$socket_path"
    printf '\n--- a new nbdkit %s ---\n' "$1" >>"$run_dir/nbdkit.log"
    "${nbdkit_launcher[@]}" nbdkit --foreground -U "$socket_path" "$plugin_path" \
        config="$config_path" >>"$run_dir/nbdkit.log" 2>&1 &
    nbdkit_pid=$!
    for _ in $(seq 1 200); do
        [[ -S "$socket_path" ]] && break
        kill -0 "$nbdkit_pid" 2>/dev/null || die "the new nbdkit exited before creating its socket"
        sleep 0.05
    done
    [[ -S "$socket_path" ]] || die "the new nbdkit's socket did not become ready"
    nbdinfo "$nbd_uri" >"$run_dir/$2.txt"
    pass "a new nbdkit recovered the volume and negotiates, $1"
}

# Leave the device of a killed nbdkit showing no connection while its attach
# record remains, as an operator could before running cleanup: disconnect it
# over netlink (NBD_CMD_DISCONNECT; the helper's own nbd-disconnect refuses
# an attachment's identifier), then, only while it still shows the
# connection, unmount XFS and remove the LV's mapping by hand. The kernel
# keeps a connection's attributes until the last opener of the device has
# closed it: what the device shows after each step is logged.
release_by_hand() {
    local connection shown holder mapping record recorded looks=0
    connection="$(shown_backend)"
    [[ "$connection" =~ ^maki-[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ ]] ||
        die "$device shows no attachment's connection before the release by hand (${connection:-none})"
    # What the device shows is no proof of whose connection it is: the attach
    # record's must be the one shown, on this device.
    record="/run/maki-attach/$volume_name.nbd"
    recorded="$(sudo -n cat "$record" | python3 -c \
        'import json, sys; record = json.load(sys.stdin); print(record["device"], record["connection_id"])')" ||
        die "could not read the attach record $record"
    [[ "$recorded" == "$device $connection" ]] ||
        die "the attach record $record names the connection ${recorded#* } on ${recorded%% *}, but $device shows $connection"
    # The invoking user deliberately opens the log file.
    # shellcheck disable=SC2024
    if ! sudo -n python3 -B "$REPO_ROOT/scripts/privileged_validation_nbd.py" --device "$device" \
        --identifier "$connection" --helper "$attach_bin" --volume "$volume_name" kernel-disconnect \
        >"$run_dir/kernel-disconnect.txt" 2>&1; then
        cat "$run_dir/kernel-disconnect.txt" >&2
        die "NBD_CMD_DISCONNECT of $device failed; see kernel-disconnect.txt above"
    fi
    cat "$run_dir/kernel-disconnect.txt"
    shown="$(shown_backend)"
    log "after NBD_CMD_DISCONNECT, with XFS mounted, $device shows backend ${shown:-none}"
    if [[ -n "$shown" ]]; then
        sudo -n umount "$mountpoint" || die "could not unmount $mountpoint by hand"
        mount_active=false
        shown="$(shown_backend)"
        log "after the unmount by hand, $device shows backend ${shown:-none}"
    fi
    if [[ -n "$shown" ]]; then
        for holder in "/sys/block/$nbd_target/holders/"*; do
            [[ -e "$holder" ]] || continue
            mapping="$(<"$holder/dm/name")"
            sudo -n dmsetup remove "$mapping" || die "could not remove the mapping $mapping by hand"
            log "removed the mapping $mapping (${holder##*/}) by hand"
        done
    fi
    while [[ -n "$(shown_backend)" ]] || nbd_has_pid; do
        ((++looks < RELEASE_LOOKS)) ||
            die "$device still shows a connection (backend $(shown_backend)) after the release by hand"
        sleep 0.1
    done
    log "$device shows no connection, $looks looks after the release by hand"
    attach_record_state
    [[ "$record_state" == present ]] || die "the attach record went before cleanup ran"
    pass "$device shows no connection while the attach record of its killed nbdkit remains"
}

# What the helper's readers parse, from this attachment, as the helper runs
# its probes: see privileged_validation_capture.py. Nothing in it is a key.
capture_helper_outputs() {
    # The invoking user deliberately opens the output file.
    # shellcheck disable=SC2024
    sudo -n python3 -B "$REPO_ROOT/scripts/privileged_validation_capture.py" --device "$device" \
        --vg "$vg_name" --lv "$lv_name" --mountpoint "$mountpoint" \
        >"$run_dir/helper-outputs.json" || die "could not capture the helper's probe outputs"
    pass "captured the outputs of the helper's probes and the device's block topology (helper-outputs.json)"
}

require_attached "the first attach"
capture_helper_outputs

log "writing and fsyncing 32 MiB beside the SQLite database"
dd if=/dev/urandom of="$mountpoint/work/lifecycle.dat" bs=1M count=32 conv=fsync status=none
sync -f "$mountpoint/work"
(cd "$mountpoint/work" && sha256sum lifecycle.dat smoke.db) >"$run_dir/lifecycle.sha256"
cat "$run_dir/lifecycle.sha256"
pass "lifecycle data written and fsynced"

log "detaching while another process holds $device open"
hold_device_open
run_helper detach maki-detach || die "maki-attach detach failed; see maki-detach.txt above"
mount_active=false
helper_cleanup_needed=false
# The opener writes this line, flushed, just before it closes the device,
# and the device shows the connection until that close: a detach that
# waited for the connection to go cannot have returned before the line.
if ! grep -q ' closing after holding it ' "$run_dir/detach-opener.txt"; then
    cat "$run_dir/detach-opener.txt" >&2
    die "maki-attach detach returned while the opener still held $device: it did not wait for the connection to go"
fi
finish_opener
require_released "detach with an opener of $device"
pass "detach waited for the opener to close $device and completed in one run"

# The sentinel exists now. Later attaches run with init_sentinel off, as the
# first-volume guide has the operator set it after the first attach.
sed 's/^init_sentinel = true$/init_sentinel = false/' "$run_dir/attach.toml" \
    >"$run_dir/attach-reattach.toml"
grep -qx 'init_sentinel = false' "$run_dir/attach-reattach.toml" ||
    die "could not turn init_sentinel off in the attach configuration"
sudo -n install -m 0600 -o root -g root "$run_dir/attach-reattach.toml" "$attach_config_path"

helper_cleanup_needed=true
run_helper attach maki-reattach || die "the second maki-attach attach failed; see maki-reattach.txt above"
mount_active=true
require_attached "the second attach"
run_helper verify maki-verify-reattach || die "maki-attach verify failed after the second attach"
check_lifecycle_data reattach

if [[ "$kill_daemon" == true ]]; then
    kill_nbdkit "after the second attach"
    # Which path cleanup takes depends on what the device shows now.
    shown="$(shown_backend)"
    run_helper cleanup maki-cleanup-dead-daemon ||
        die "maki-attach cleanup failed after nbdkit was killed; see maki-cleanup-dead-daemon.txt above"
    mount_active=false
    helper_cleanup_needed=false
    require_cleanup_path maki-cleanup-dead-daemon "$shown"
    require_released "cleanup after nbdkit was killed"

    start_nbdkit "after the first SIGKILL" nbdinfo-after-kill
    helper_cleanup_needed=true
    run_helper attach maki-attach-after-kill ||
        die "maki-attach attach failed after nbdkit was killed; see maki-attach-after-kill.txt above"
    mount_active=true
    require_attached "the attach after nbdkit was killed"
    run_helper verify maki-verify-after-kill || die "maki-attach verify failed after nbdkit was killed"
    check_lifecycle_data restart

    # Cleanup's path for a device that shows no connection (AUD-203): a
    # killed nbdkit's device keeps showing it, so it is released by hand
    # first, and the record is left for cleanup to retire.
    kill_nbdkit "after the third attach"
    release_by_hand
    run_helper cleanup maki-cleanup-disconnected ||
        die "maki-attach cleanup failed on the disconnected attachment; see maki-cleanup-disconnected.txt above"
    mount_active=false
    helper_cleanup_needed=false
    require_cleanup_path maki-cleanup-disconnected ""
    require_released "cleanup of the disconnected attachment"

    start_nbdkit "after the second SIGKILL" nbdinfo-after-disconnect
    helper_cleanup_needed=true
    run_helper attach maki-attach-after-disconnect ||
        die "maki-attach attach failed after disconnected recovery; see maki-attach-after-disconnect.txt above"
    mount_active=true
    require_attached "the attach after disconnected recovery"
    run_helper verify maki-verify-after-disconnect ||
        die "maki-attach verify failed after disconnected recovery"
    check_lifecycle_data recovery

    run_helper detach maki-detach-final || die "the final maki-attach detach failed; see maki-detach-final.txt above"
    mount_active=false
    helper_cleanup_needed=false
    require_released "the final detach"
else
    log "running the real idempotent maki-attach cleanup helper"
    # The invoking user deliberately opens the log file.
    # shellcheck disable=SC2024
    sudo -n env PATH="$PATH" "$attach_bin" cleanup --volume "$volume_name" \
        --config "$attach_config_path" \
        >"$run_dir/maki-cleanup.txt" 2>&1
    mount_active=false
    helper_cleanup_needed=false
    pass "maki-attach cleanup unmounted XFS, deactivated LVM, and disconnected NBD"
    require_released "cleanup"
fi

# A service stop and its recovery coordinator may both request cleanup. The
# second call must converge as success without a trusted record or live state.
sudo -n env PATH="$PATH" "$attach_bin" cleanup --volume "$volume_name" \
    --config "$attach_config_path" \
    >"$run_dir/maki-cleanup-idempotent.txt" 2>&1
pass "repeated maki-attach cleanup is idempotent"

log "removing the disposable LVM metadata"
connect_test_nbd
test_nbd_action activate-vg --vg "$vg_name"
test_nbd_action remove-lv --vg "$vg_name" --lv "$lv_name"
lv_created=false
test_nbd_action remove-vg --vg "$vg_name"
vg_created=false
test_nbd_action remove-pv
pv_created=false
disconnect_test_nbd
pass "disposable LVM state removed"

stop_process_normally "$nbdkit_pid" "nbdkit" clean || die "nbdkit did not stop cleanly"
nbdkit_pid=""
# The unload hook reports its final drain failure to stderr even on exit 0.
if grep -Fq 'maki-nbdkit: shutdown during unload failed' "$run_dir/nbdkit.log"; then
    die "plugin reported a shutdown failure; see nbdkit.log"
else
    [[ $? == 1 ]] || die "could not inspect the plugin shutdown log"
fi
"$maki_bin" check "$config_path" | tee "$run_dir/maki-check.txt"
pass "clean nbdkit shutdown and offline Maki check"

log "completed all non-crash privileged checks"
