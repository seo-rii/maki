# 운영 준비 검토 및 R3 수정 기록 — 2026-09-08

최초 검토 기준은 `9911cf7`, 최근 로컬 전체 workspace snapshot 검사는 `2a3f023`의 901 passed이며 전체 9 release gates/CI를 함께 완료한 기준선은 `fb3da46`이다(2026-09-12). 2026-09-11에 원격 `732ff74`까지의 10개 변경을 합친 뒤 같은 `main`에서 원격을 반복 확인하며 TDD 수정과 단위별 커밋을 이어갔다. 이후 실제 native 프로세스 충돌, cgroup 장애, Firecracker guest 종료와 전체 GCE 인스턴스 reset 검사를 추가했고, privileged 및 lifecycle crash 검증 기준은 `448c0b2`, remote-provider/SQLite qualification 기준은 `c385c99`이다. 최신 패키지 수정 `3cac300`의 [Linux·Windows CI](https://github.com/seo-rii/maki/actions/runs/35356803628)도 모두 성공했다. 아래에서 수정별 검증 범위와 과거 snapshot을 구분한다.

**운영 승인은 보류한다.** 실제 Maki nbdkit, kernel NBD/LVM/XFS, trusted cleanup/reattach, 설치된 packaged recovery controller와 Docker SQLite 외부 ACK를 한 단일-PV/LV 캠페인에 결합하고 두 번의 자동 crash와 한 번의 cleanup 실패·재시도를 통과했다. 별도의 두 GCE 호스트에서 제한된 fresh-host backing 복원도 통과해 source의 32개 ACK 행을 새 host에서 대조하고, 16개를 추가한 뒤 lifecycle 재시작 후 48개를 다시 대조했다. 두 인증 loopback HTTP provider와 SQLite를 결합한 별도 캠페인도 개별 endpoint failover, 전체 provider 중단의 무-ACK stall과 복구 후 정확한 진행, 32개 행의 restart readback을 통과했다. checksummed PostgreSQL 15도 pgbench 중 postmaster SIGKILL 뒤 WAL 복구와 네 번의 `pg_amcheck`, 48개 ACK 및 Maki lifecycle restart를 통과했다. `733833c`는 recovery payload replay를 1 MiB batch로 제한했다. 후속 [constrained RSS 캠페인](recovery-rss-validation-2026-09-19.md)은 실제 OOM tail 네 개를 48/64 MiB에서 복구했고 관찰한 nbdkit `VmHWM`은 최대 11,415,552 bytes였지만 이는 고정 profile의 측정값이다. 별도 ext4/GCE Persistent Disk 캠페인은 첫 FUA 전에 checkpoint slot과 A/B metadata의 실제 block allocation을 확인하고, 가용 공간 0에서 다음 FUA가 sequence와 journal을 바꾸지 않은 채 ENOSPC로 닫힌 뒤 retry·restart·deep check를 통과했다. [패키지·토폴로지·마이그레이션 캠페인](package-topology-migration-validation-2026-09-19.md)은 generated Debian package clean install/upgrade, 두 동시 volume과 sidecar LV, multi-mapping 및 foreign backend의 fail-closed cleanup, SQLite DB-native와 clean legacy-v1→v2 복원을 통과했다. 그러나 전송 라이브러리의 남은 평문 복사본, 다른 geometry/provider/cache를 포함한 전체 RSS 규격, 더 넓은 storage topology, commercial vendor와 대상 network의 고유 동작, production PostgreSQL과 다른 DB profile 및 migration, 장시간 부하와 물리 전원 손실에는 코드·검증 과제가 있다. `47058d2`의 [cross-host TLS reference-provider 캠페인](cross-host-tls-provider-validation-2026-09-19.md)은 실제 private VPC에서 TLS 1.2/1.3, mTLS·bearer 거절, 두 provider host의 개별·전체 중단과 32 ACK restart readback을 통과했지만 vendor qualification은 아니다. MAKI-020의 필수 proof 정책과 새 포맷은 전체 workspace·릴리스 검사와 Linux/Windows CI를 통과했으며 운영 대상 검증은 남는다. 기존 v1 볼륨은 현재 writable recovery가 거절하므로 교체 전에 [호환성과 데이터 이전 절차](durable-recovery.md)를 읽어야 한다. R3-001–010의 직접 원인은 아래 제품 경로와 집중 검사로 닫았지만, 리뷰 묶음이 함께 추적한 이전 MAKI/FUP 운영 과제는 남아 있으므로 로컬 `maki-review-r3-2026-09-08/` 원본은 보존한다.

`bdb9113` 기준의 후속 [credential rotation·key migration 캠페인](credential-rotation-key-migration-validation-2026-09-19.md)은 중지된 K1 volume의 bearer와 mTLS client identity/CA 교체, old credential 거절, 두 peer 재검증과 superblock/canary hash 불변을 통과했다. 별도 K2 volume으로 SQLite DB-native restore한 24 ACK도 lifecycle restart 뒤 그대로 대조했고 양쪽 volume의 deep check는 invalid slot 0이었다. 이 캠페인은 client credential과 K1→K2 migration 범위였다.

`da89ae3` 기준의 별도 [server CA·endpoint 교체 캠페인](server-ca-endpoint-rotation-validation-2026-09-19.md)은 네 GCE 호스트에서 private CA overlap, 순차 server certificate 교체, old root 제거, 양방향 wrong-trust의 실제 NBD 거절과 같은 key/profile의 A/B→C/B IP 교체를 통과했다. A의 nginx listener를 중지한 상태로 두 peer 재검증과 48 ACK restart readback, 동일 volume UUID와 전환별 superblock/canary hash 불변을 확인했다. B가 계속 남았으므로 C 단독 운용 검증은 아니다. Commercial vendor와 대상 배포 환경 검증은 남아 있어 운영 승인 보류와 R3 원본 보존은 유지한다.

## 실제 cgroup·프로세스 장애 검사 — 2026-09-12

`0509fe3`에 native nbdkit SIGKILL 회귀 6개를 추가했다. FLUSH/FUA 각각
3회 재시작, 미ACK 요청 제외, 확정 저널 삭제·절단의 시작 거절을 검사했다.
외부 oracle의 잘못된 예상값이 Python `-O`에서 통과하는 RED를 확인하고
검사를 명시적 오류 처리로 수정했다. `PYTHONOPTIMIZE=1`에서 6 passed,
strict Clippy·서식 검사도 통과했다. 제품 코드를 변경한 단위는 아니다.
`0509fe3`의 [Linux·Windows CI](https://github.com/seo-rii/maki/actions/runs/34694167299)도 모두 성공했다.

별도로 `e894ae5`의 정상 release/AES-GCM-SIV 경로를 폐기용 Docker에서
실행했다. CPU 0.25개 제한의 실제 throttling, 0.5초 freeze/resume,
SIGKILL 및 32MiB·swap 0의 실제 workload OOM을 확인했다. 세 시나리오의
확정 데이터 136개 블록씩이 재시작 후 일치했고 deep check도 통과했다.
최종 캠페인 PID 1102835, exit 0 로그:
`/home/seorii/logs/maki-r3-cgroup-native-final-evidence-20260912T123818.793378Z.log`.
검사 도구의 실패 ACK·OOM 오판·최적화 우회·정리·진단 회귀도 13 passed다.

**32MiB 재기동 가능성은 보장하지 못했다.** 22MiB의 압박 쓰기를 완료한
두 시험은 같은 32MiB로 복구할 때 30초 안에 READY를 내지 못했다.
21.75MiB를 완료한 마지막 시험은 같은 상한에서 복구했지만 한도에 도달했고,
192MiB 복구는 성공했다. 당시 구현에서 고유 단위 replay와 메모리·시간 예산의
과제가 남아 있다는 실제 증거였다. 특정 최소 RAM이나 정상 운영 용량을 도출한 것은
아니다. 실패와 성공의 원장·종료 상태는 [상세 장애 보고서](cgroup-fault-validation-2026-09-12.md)에 함께 기록했다.

후속 `733833c`는 attach replay를 1 MiB batch로 바꾸었고 2026-09-18
재실행에서 21.5MiB tail을 같은 32MiB cap으로 복구해 ACK 136개를 대조했다.
다만 `memory.peak`가 cap에 정확히 닿았으므로 전체 RSS 여유나 최소 RAM은
여전히 대상 환경별로 검증해야 한다.

현재 호스트는 WSL이 아닌 Debian이므로 `wsl --shutdown`은 실행하지 않았다.
커널과 page cache가 살아 있는 과정의 시험이며 실제 정전·kernel NBD/LVM/XFS·
DB ACK 시험을 대신하지 않는다. MAKI-020의 외부 qualification 및
MAKI-025/028/049/050은 이 결과만으로 닫지 않으며 원본 리뷰를 보존한다.

## Firecracker guest 강제 종료 검사 — 2026-09-12

GCP의 폐기용 N2 인스턴스에서 중첩 KVM으로 Firecracker v1.16.1을 실행했다.
게스트는 공식 Firecracker CI의 Linux 6.18.44 커널, 읽기 전용 rootfs와
`Writeback`/`Sync`로 명시한 별도 data 이미지를 사용했다. release Maki와
실제 AES-GCM-SIV nbdkit plugin이 8개 shard에 16개 4KiB 단위를 기록했다.
L1의 독립 원장은 완전한 guest ACK만 `fsync`한 다음 해당 Firecracker
process group을 `SIGKILL`하고 `-9` 종료를 회수했다.

2회 smoke에 이어 새 data 이미지로 20회를 실행했다. FLUSH 10회와 FUA
10회 모두 ACK 뒤 강제 종료됐고, 같은 UUID의 image를 사용하는 각 다음
부팅에서 최신 16개 단위가 모두 인증된 읽기와 독립 SHA-256 대조를 통과했다.
합계는 ACK 320개와 cold-boot readback 320개다. 마지막 hard cut 뒤 offline
deep check도 durable sequence 320, journal 20 segment/320 record를 확인하고
통과했다. 상세한 해시·실패 시행·재현 범위는
[Firecracker 보고서](firecracker-validation-2026-09-12.md)에 기록한다.

이 검사는 L2 guest RAM과 guest kernel/page cache를 잃는 실제 VM 경계를
추가했다. L1 kernel/page cache와 GCP Persistent Disk는 계속 동작했으므로
물리 정전, storage controller cache 소실, kernel NBD/LVM/XFS 또는 실제 DB
commit 보존을 증명하지 않는다. 따라서 운영 승인 보류와 MAKI-020/049/050의
종료 조건은 유지하며 원본 리뷰도 삭제하지 않는다.

## GCE 전체 인스턴스 강제 reset 검사 — 2026-09-13

Firecracker보다 바깥 경계를 검사하기 위해 폐기용 GCE `n2-standard-4`
인스턴스와 별도 20 GiB balanced Persistent Disk를 만들었다. 외부 호스트의
검증기는 실제 AES-GCM-SIV nbdkit에서 완전한 ACK와 독립 해시 manifest를
받아 자기 원장과 부모 디렉터리를 `fsync`한 직후
`gcloud compute instances reset`만 호출했다. ACK 뒤 guest sync, unmount,
drain, shutdown, reboot 또는 stop은 호출하지 않았다. 매 부팅에서 활성
systemd `ExecStop` witness의 정상
종료 표식이 없는 것도 요구했다.

2회 smoke 뒤 데이터 디스크를 새 ext4/Maki 볼륨으로 다시 만들고 본 검사를
10회 수행했다. FLUSH 5세대와 FUA 5세대, 합계 160개의 ACK된 4 KiB write
version을 각 다음 부팅에서 모두 인증된 읽기와 독립 SHA-256으로 확인했다.
reset 10개는 모두 exit 0, 기존 SSH 10개는 모두 종료됐고, 11개 boot ID는
모두 달랐다. instance ID, data disk ID/attachment, filesystem UUID는 같았다.
모든 READY에서 정상 종료 표식은 없었으며 마지막 deep check는 durable 및
checkpoint sequence 160, invalid slot 0으로 통과했다. Cloud Audit Logs에서도
smoke 2개와 본 검사 10개에 대응하는 완료된 reset operation 12개를 확인했다.
상세 프로토콜과 재현 명령은 [GCE reset 보고서](gce-reset-validation-2026-09-13.md)에
기록한다.

이 결과는 workload VM의 RAM, kernel, page cache를 실제로 잃으므로 앞선
Firecracker의 L1 생존 한계를 줄인다. 그러나 GCP Persistent Disk 서비스와
물리 저장 경로는 계속 동작했다. userspace Unix NBD를 사용했고 kernel
NBD/LVM/XFS, 실제 DB, remote provider, 장시간 부하나 물리 정전은 검사하지
않았다. 따라서 운영 승인과 MAKI-020/049/050은 계속 보류하며 R3 원본도
보존한다.

검사 뒤 인스턴스와 부팅·데이터 디스크를 모두 삭제했다. 이름을 제한한
project 조회에서 인스턴스 0개, 디스크 0개를 확인했고 삭제 전후 JSON과
43개 증거 파일의 검증된 SHA-256 manifest를 로컬 private 로그에 보존했다.

## 현재 privileged·systemd·Docker 수명주기 검사 — 2026-09-13

`5a3bef69aa4980c6783e177c44e6e0b5b7f286f0`을 별도 GCE
`n2-standard-4`, `debian-12-bookworm-v20260908`, Linux
`6.1.0-53-cloud-amd64`에서 검사했다. nbd-client 3.27.1, nbdkit 1.32.5,
LVM 2.03.16, XFS tools 6.1.0, fio 3.33, SQLite 3.40.1을 사용했다. 실제
512 MiB `/dev/nbd15`에서 rootless nbdkit, kernel NBD, raw CRC32C fio,
단일-PV LVM/XFS와 전체 PV/VG/LV UUID pin, 실제 attach/verify/cleanup,
두 번째 멱등 cleanup, XFS fio, SQLite WAL `synchronous=FULL` checkpoint와
`integrity_check=ok`, clean daemon shutdown 및 offline Maki check까지
22개 검사가 exit 0으로 통과했다. 증거는
`/home/seorii/logs/maki-gcp-privileged-20260913-evidence/maki-privileged-success.tgz`에
보존한다.

같은 호스트의 실제 systemd PID 1 transaction은 daemon failure 뒤 fixture
workload `43692`를 멈추고 attach stop과 cleanup을 마친 뒤 새 daemon
`43687→43714`, workload `43692→43719`를 시작했다. cleanup/config 실패에는
workload를 다시 시작하지 않았고, per-start verify 실패에서는 workload
`ExecStart`가 0회였다. `systemd-analyze verify`에도 unit cycle이나 syntax
오류가 없었다. daemon, attach-start, verify와 workload는 fixture였고 실제
`maki-attach cleanup`은 no-record 성공과 invalid-config 실패 경로를 실행했다.

별도 Docker 검사는 `python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea`와
loop-backed XFS를 사용했다. Docker의 기본 `rprivate` bind를 확인했고
container ID가 `bcf202…`에서 `e570ae…`로, 생성 시각과 PID도 바뀌었다.
SQLite 행은 1개에서 2개로 이어졌고 양쪽 container와 host 검사에서
`integrity_check=ok`였다. XFS가 아닌 일반 디렉터리에서는 container
`ExecStart`가 0회였다. `/proc` mount namespace token은 이전 container가
사라진 뒤 두 실행에서 같은 `mnt:[4026532341]` 값으로 재사용됐으므로,
token 차이를 새 container의 합격 조건으로 사용하지 않았다.

Docker 시험은 fixture daemon/attach와 custom `findmnt` UUID gate를 썼으며
real cleanup은 no-record 경로였다. 실제 Maki daemon, kernel NBD/LVM 및
trusted `maki-attach verify`를 같은 crash/restart transaction에 넣지 않았다.
따라서 위 두 수명주기 시험은 current helper의 실제 clean storage smoke를
보완하지만 DB 내구성 또는 전체 storage recovery의 종단간 인증은 아니다.
성공·검증기 실패 시행과 SHA-256은 같은 private evidence directory에 남겼다.

그 뒤 `8bf0e941bd3501b972850240fb1050fbc2a90c0b`의 29개 결합 검사는 실제
Maki nbdkit, kernel NBD, UUID가 고정된 단일-PV LVM/XFS, trusted attach/verify/
cleanup과 Docker SQLite를 한 캠페인에 넣었다. Docker의 첫 `rprivate`
container가 WAL `synchronous=FULL`로 32개 행을 하나씩 commit했고 외부 ACK
원장과 그 디렉터리를 별도 fsync했다. 실제 nbdkit에 `SIGKILL`을 보내 exit
137을 회수한 뒤 kernel NBD 연결은 남았고 identity/topology 전용 `verify`는
0을 반환했다.

일반 `vgchange`가 죽은 server의 PV를 읽지 못해 nonzero로 끝난 뒤,
`8bf0e94`의 cleanup은 complete proof와 현재 name/UUID/major/minor/slave,
open=0 및 backend nonce를 다시 확인해 정확한 단일 mapping에 plain
`dmsetup remove`를 실행했다. NBD disconnect와 nbdkit 재시작/reattach 뒤 새
`rprivate` container가 외부 원장의 32개 행과 byte-for-byte 일치했고
`integrity_check=ok`였다. 최종 cleanup 두 번, LVM metadata 제거, clean daemon
shutdown과 offline check도 통과했다. 이 fallback은 cleanup의 completed
single-target proof 전용이며 multi-LV/internal/open/changed mapping과 timeout은
mutation 없이 닫는다.

이 결합 검사는 설치된 systemd controller, remote provider, whole-VM/물리
전원 손실, 다른 DB, 반복 crash 또는 soak를 포함하지 않았다. 전체 증거와
SHA-256 manifest는
`/home/seorii/logs/maki-gcp-combined-20260913-evidence`에 보존한다.

검사 뒤 기존 privileged host와 새 결합 host의 인스턴스 및 auto-delete
50 GiB balanced boot disk를 각각 삭제했다. 마지막 새 project 조회에서
`maki-*` 인스턴스 0개와 디스크 0개를 확인했고, 결합 host의 정확한 disk
조회도 404였다. 삭제 및 조회 JSON은 각 evidence directory에 보존했다.

## 설치된 systemd 결합 장애 검사 — 2026-09-17

`448c0b2a46bd748eb473e34405175db9b3cfa102`의 release 바이너리, nbdkit
plugin, shipped systemd/sysusers/tmpfiles 파일을 새 Debian 12 GCE
`n2-standard-4`에 설치했다. PID 1이 nbd-client 3.27.1을 해석하는지 먼저
증명하고 `LoadCredential=`의 local AES-GCM-SIV key, `/dev/nbd15`, UUID가
고정된 단일-PV/LV XFS, 실제 `maki` 비특권 daemon과 recovery/attach/workload
graph를 사용했다. Docker image는
`python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea`로
고정했다.

첫 `rprivate` container가 SQLite WAL `synchronous=FULL`로 외부 ACK 16개를
기록한 뒤 실제 daemon main PID를 두 번 연속 `SIGKILL`했다. 각 systemd
recovery transaction은 이전 workload와 attach를 멈추고 cleanup, 새 daemon,
reattach, root verify와 새 container를 순서대로 실행했다. daemon PID,
workload invocation과 container ID가 모두 바뀌었고 외부 ACK 원장은 32개와
48개로 증가했다.

세 번째 crash에서는 root가 정확한 LV descriptor를 열린 채 유지했다.
attach stop과 recovery cleanup은 open count 때문에 모두 실패했고 workload와
기존 container는 사라졌지만 새 container는 시작되지 않았다. 외부 ACK는
48개에서 멈췄고 NBD, mapping, backend identity와 trusted volume record는
보존됐다. descriptor를 닫고 recovery unit을 명시적으로 재시도하자 graph가
복구되어 외부 ACK 64개에 도달했다. 독립적인 일회성 container의 DB 64개
행과 payload hash가 원장과 byte-for-byte 일치했고 `integrity_check=ok`였다.

정상 종료는 DB 연결이 닫힌 뒤 drain을 확인하고 target을 멈춘 다음 workload,
attach와 daemon stop job이 모두 inactive가 될 때까지 기다렸다. journal의
종료 순서는 workload, attach cleanup, daemon이었고 plugin unload drain 오류는
없었다. offline check가 통과했으며 mount, mapping, NBD, holder, volume record와
container가 남지 않았다. 전체 12 check는 exit 0이었다. 증거와 SHA-256
manifest는 `/home/seorii/logs/maki-systemd-combined-20260917`에 보존한다.

정확한 instance와 auto-delete 50 GiB boot disk를 삭제했고 둘의 재조회는
not found였다. 새 project 전체 조회에서도 `maki-*` instance와 disk는 각각
0개였다. 이 결과는 repository artifact를 설치한 짧은 local-provider,
single-PV/LV, SQLite campaign이다. distribution package install/upgrade,
multi-LV/internal mapping, foreign device replacement, remote provider, 다른
DB, fresh-host restore, 이 topology의 whole-VM crash, soak와 물리 전원 손실은
포함하지 않는다.

## 실제 물리 공간 예약 검사 — 2026-09-18

`3cac300`의 release Maki를 새 Debian 12 GCE `e2-standard-2`에서 빌드하고,
별도 10 GiB standard Persistent Disk를 ext4로 포맷했다. 첫 4 KiB FUA가
성공했을 때 4,608-byte slot의 sparse shard file은 이미 8,192 physical
bytes를 소유했고 allocation map A/B도 각각 4,096 bytes를 소유했다.

다른 파일로 ordinary-user 가용 공간 9,910,247,424 bytes를 모두 소진한 뒤
다음 FUA는 `No space left on device`로 실패했다. 실패 전후 appended/durable
sequence는 1, journal length와 SHA-256, slot allocated block 수는 모두
같았다. filler를 지워 같은 write를 다시 실행하자 sequence 2로 성공했고,
nbdkit 재시작 뒤 두 payload hash가 일치했다. deep check는 allocated slot 2,
invalid 0으로 통과했고 unmount 뒤 `e2fsck -fn`도 통과했다. 상세 결과는
[물리 예약 보고서](physical-reservation-validation-2026-09-18.md)에 기록했다.

VM, auto-delete boot disk와 별도 data disk는 모두 삭제했고 정확한 재조회와
`maki-physical-*` 조회에서 남은 리소스가 없었다. 이 결과는 Linux ext4와
해당 GCE storage class의 짧은 두-slot 검사다. untouched slot, DB 임시 공간,
다른 filesystem/COW/quota/thin provisioning과 물리 전원 손실은 포함하지
않는다.

## 검증 기준선

커밋된 파일만 `git archive`로 분리하여 Rust 1.94.0, 저장소 Cargo.lock으로 검사했다. 기존 미추적 실험 파일은 포함하지 않았다.

| 검사 | 결과 | 종료 코드 |
|---|---|---:|
| `cargo fmt --all --check` | 기존 14개 파일 포맷 불일치 | 1 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 통과 | 0 |
| `cargo test --workspace --locked` | 568 passed, 7 ignored | 0 |
| 지정된 release model/crash/endpoint/DB simulation gates | 통과, 실행 결과는 아래 로그 | 0 |

기준선 PID 1875105, 통합 종료 코드 1: `/home/seorii/logs/maki-readiness-baseline-20260908T083949Z.log`.
Release gates PID 1946132, 종료 코드 0: `/home/seorii/logs/maki-readiness-release-gates-20260908T084557Z.log`.
당시 [GitHub CI](https://github.com/seo-rii/maki/actions/runs/34205173224)도 fmt에서 중단됐으며 Clippy/test가 실행되지 않았다. 현재 revision의 결과를 뜻하지 않는다.

## 확인한 결함

- MAKI-009/R3-005: 실제 AES-XTS HTTP 서버 두 개로 전체 daemon→Engine 경로에서 잘못된 평문 성공 반환을 재현했다. 두 서버가 nil UUID 키만 같고 실제 UUID 키가 다르면 초기 검증을 통과한다. FUA 후 첫 서버 장애 시 512바이트 전부 잘못 반환됐고 원래 서버 복귀 후 정상 데이터가 읽혔다. 조건부 P0이다.
- R3-001: negative probe가 요구하는 Integrity 오류를 원격 wire transport가 표현하지 못한다. HTTP 동작 재현과 세 transport의 매핑 확인을 마쳤다. 인증 검증을 끄는 방식으로 해결하지 않는다.
- 최초 sentinel 게시 전 mount 실패: 실제 executor/observer를 사용하는 fixture에서 mount/VG/NBD/record가 남고 attach 및 detach 모두 복구를 거부했다. 장치 변경을 무조건 허용할 문제가 아니라 검증된 복구 상태가 부족한 문제다.

## 수정 진행

| 항목 | 상태 | 완료 증거 |
|---|---|---|
| R3-001 wire Integrity | 수정·검증 완료 | `3703683`; 세 transport의 인증 암호→Engine, 잘못된 키·schema·timeout 구분 |
| R3-002 rollback 소유권 | 수정·검증 완료 | `c834ff5`; foreign/unknown backend에서 모든 teardown 중단 |
| R3-003 논리/암호문/RPC 예산 | 수정·검증 완료 | `4449a74`; 과대 요청 거절, 암호문 overhead 및 최대 예산 경계 |
| R3-004 이종 endpoint 능력 | 수정·검증 완료 | 원격 intersection 보존 + `27dce14`; 25개 관련 회귀 통과 |
| R3-005 실제 UUID 및 canary | 수정·검증 완료 | `8e725fc`; 잠긴 실제 UUID/개별 canary/격리 복귀 검증, 5개 회귀 |
| R3-006 전체 context 검증 | 수정·검증 완료 | 원격 full-context wire 보존 + `dd87466`; 정확한 필드의 명시적 거절만 증거로 인정 |
| R3-007 명시적 복구 수명주기 | 제품 경로·집중 검증 완료, 설치 graph 결합 및 scoped topology qualification 통과 | 기존 intent/recover/verify에 `3fc0404`의 멱등 cleanup selector와 `98a5b0e`/`90843db`의 packaged graph를 추가했다. `448c0b2`에서 설치된 systemd graph가 실제 Maki nbdkit의 두 SIGKILL, kernel NBD/LVM/XFS cleanup/reattach, open-LV 실패 차단과 명시적 재시도, 네 `rprivate` container의 외부 ACK 64개 복구를 수행했다. `3cac300` 패키지 캠페인은 two-LV fallback과 same-NBD foreign backend를 mutation 전에 거절하고 proof/record를 보존했다. nested/internal mapping, partition·holder·udev 경합과 hot replacement는 남음 |
| R3-008 종료 결과/로그 | 지원 foreground 경로 수정·검증 완료 | `dc646ef`; drain 성공/실패 응답, admission 차단·재시도, 실제 rootless nbdkit 오류 로그와 동시 shutdown 회귀. daemonized 로그 경로는 운영 지원 대상으로 승인하지 않음 |
| R3-009 conformance shape | 수정·검증 완료 | `57ca845`; 빈/추가/잘못된 index/길이 응답 8개 RED→GREEN |
| R3-010 capability mode | 수정·검증 완료 | `40502a7`; declared만 지원, remote Verified 선언을 Contractual로 표시 |

추가 수정:

- `cde82b6` (MAKI-004/FUP-004): 특권 명령 120초, probe 15초, stdout/stderr 각 64KiB 상한, 해당 process group 종료·회수 제한. helper 전체 작업 시간이 이 값 하나로 제한된다는 뜻은 아니다.
- `9d7cf24` (MAKI-002/003): `grow --size-bytes` 절대 목표로 재시도하며 각 변경 직전에 소유권 재검증. `--add-bytes`는 명시 거절한다.
- `33185e5` (MAKI-023): checker의 unit ID 열거를 iterator로 변경. 샤드 수에 비례하는 추가 메모리만 사용한다. 기존 bitmap 자체와 recovery payload 메모리는 별도 과제다.
- `b98e8be` (MAKI-027): signed NBD size로 표현할 수 없는 geometry를 생성/디코드에서 거절한다.
- `67e0ea3`, `90c2c24`: 기존 포맷 불일치와 export-size 경계 테스트의 Clippy 표현을 별도 정리했다. 이 사실만으로 최종 전체 CI 통과를 주장하지 않는다.
- `bf63103` (MAKI-012): production template이 integrity/context binding을 요구하도록 변경했다. vendor 계약과 실제 인증 provider 검증이 필요하며 replay 보호까지 제공하는 설정은 아니다.
- `597eb3c` (R3-007, MAKI-007/040 일부): `maki-attach recover`가 backend 부재와 저장된 장치 번호·LVM UUID·slave 관계를 확인하고 mount/VG를 단계적으로 정리한다. 끊긴 파일시스템의 sentinel을 읽지 않는다. proof 없는 활성 mapping은 거절하며, [복구 제한](storage-recovery.md#remaining-recovery-limits)을 그대로 적용한다.
- `b68935d` (R3-007): 검증된 NBD geometry·partition과 LVM metadata를 activation 전에 원자적으로 기록하고, 성공한 activation 뒤 complete mapping proof로 승격한다. 중간 crash의 intent는 mount/unmount/workload 시작 권한을 주지 않으며, backend가 사라진 복구에서 exact UUID/device/topology만 scoped deactivation한다. legacy proof/intent 없는 기록은 계속 fail closed다.
- `91d406f` (R3-007): recorded backend nonce가 계속 연결된 정상 detach도 recovery intent를 사용한다. 검증된 부분 activation subset만 scoped deactivation하며 changed mapper name/UUID/slave/holder/mount와 알 수 없는 internal LVM UUID suffix는 mutation 전에 거절한다.
- `3fc0404` (R3-007): `maki-attach cleanup`이 하나의 lock 아래 no-record 성공, owned connected backend의 detach, absent backend의 recover를 선택한다. foreign/unreadable backend는 mutation 없이 실패하고 record를 보존한다.
- `98a5b0e`, `90843db` (R3-007, MAKI-006/007/040): workload target, recovery coordinator와 workload drop-in을 추가했다. daemon failure가 직접 restart로 attachment를 우회하지 않고 등록 workload·attach·daemon을 멈춘 뒤 cleanup 성공에만 새 target을 시작한다. target stop은 attachment cleanup 뒤 daemon을 멈추며 매 workload start가 root read-only verify를 거친다.
- `1113a26`, `575b2c5`, `d6df001`, `81e7f7f`, `5a3bef6`: nbd-client 3.27.1의 nonzero help banner, real cleanup 두 번, control runtime, netlink의 `nbdN` 이름과 root-owned attach config planning을 회귀로 고정했다. 현재 GCE 22-check privileged 실행과 각 커밋 CI가 통과했다.
- `8bf0e94` (R3-007): 죽은 nbdkit 뒤 kernel NBD 연결이 남고 `vgchange`가 PV를 읽지 못하는 실제 상태를 complete proof 기반 단일-target cleanup으로 복구한다. 일반 명령이 명시적 nonzero로 끝나고 exact topology, open=0, backend nonce가 일치할 때만 plain `dmsetup remove`를 허용한다. focused RED/GREEN, privileged 전체 167개 실행 검사, strict Clippy, GCE 29-check 결합 캠페인과 CI가 통과했다.
- `223db0c` (MAKI-021/041 일부): fresh free-space admission이 emergency reserve뿐 아니라 해당 write의 모든 journal record와 segment-header footprint까지 요구한다. 조회의 `None`/오류와 reserve 덧셈 overflow는 mutation 전에 ENOSPC로 닫는다. 물리 예약과 checkpoint 완주 공간은 남는다.
- `19ece6f` (MAKI-021/041 일부): emergency admission이 켜진 write는 configured checkpoint headroom도 append 뒤 남겨야 한다. 경계 미만, headroom 합산 overflow, emergency=0 opt-out을 RED→GREEN으로 고정했다. RED 3 failed는 `/home/seorii/logs/maki-checkpoint-headroom-red-20260913.log`, 최종 focused 3 passed와 core all-targets 201 passed/6 ignored, strict Clippy는 각각 `/home/seorii/logs/maki-checkpoint-headroom-final-focused-20260913.log`, `/home/seorii/logs/maki-checkpoint-headroom-core-all-final-20260913.log`, `/home/seorii/logs/maki-checkpoint-headroom-clippy-20260913.log`다. 이것은 관측 threshold이며 물리 allocation 선점은 아니다.
- `ced2bda` (MAKI-021/041): Linux write admission이 exact journal range와 해당 checkpoint slot 전체를 `posix_fallocate`로 먼저 확보하고, 새 shard의 allocation map A/B와 catalog를 journal append 전에 생성·동기화한다. slot/journal 예약 ENOSPC는 sequence를 소비하지 않고 재시도 가능하며, 실제 파일 회귀는 첫 ACK 전에 slot의 allocated block과 두 metadata copy를 확인한다. core all-targets 204 passed/6 ignored와 strict Clippy가 통과했다. untouched slot의 full-volume 선점, filesystem/COW overhead와 DB 임시 공간은 포함하지 않는다.
- `733833c` (MAKI-025): 복구가 journal 전체를 검증·수선한 뒤 1 MiB ciphertext batch로 다시 scan하여 checkpoint slot에 반영한다. 4,096 distinct record와 16,384 overwrite의 측정 peak는 약 1.1 MiB였고 replay 중 slot sync crash는 journal을 보존해 재시도됐다. 실제 cgroup은 21.5 MiB pressure tail을 32 MiB에서 복구하고 외부 ACK 136개를 대조했지만 `memory.peak`가 상한에 닿아 전체 RSS 최소 규격은 확정하지 않았다.
- `5803be8` (MAKI-041 일부): geometry가 maximum unit/shard, full-shard slot span, 모든 shard의 allocation map A/B와 catalog A/B 크기를 checked arithmetic으로 계산하고 `maki volume inspect`가 표시한다. 지원 catalog 상한인 2^24 shard를 넘거나 전체 span이 `u64`을 넘는 geometry는 생성·decode 전에 거절한다. 16TiB 표준 예제의 slot span은 18TiB, allocation map A/B는 1,073,758,208 bytes다. format 및 CLI 전체와 strict Clippy가 통과했다. 이 수치는 physical reservation, journal/checkpoint peak, filesystem overhead 또는 DB 임시 공간을 포함하지 않는다.
- `d843540`, `44ba589`, `e1f4143` (MAKI-015 일부): HTTP Base64/Base64URL/hex 응답을 첫 출력 byte 전부터 고정 크기 zeroizing owner에 직접 decode하고, response growth 때 교체되는 allocation을 지운다. JSON object key, pointer overwrite/descent와 잘못된 pointer, 부분 per-item/batch request tree도 RAII로 정리한다. page lock, malformed response parser의 내부 allocation과 외부 library 복사본은 남는다.
- `8419b3d` (MAKI-015 일부): HTTP가 소유한 resolved header/query 값과 결합된 mTLS identity PEM을 정상 drop·구성 오류에서 지운다. key-source credential은 중간 UTF-8 byte vector를 만들지 않고 빌린다. 원본 설정 문자열과 reqwest/hyper/rustls/kernel 복사본은 보장 밖이다.
- `a2cc5bc` (MAKI-005): 선택적인 `[lvm_identity]`가 전체 PV UUID 집합, VG UUID와 설정 대상 LV UUID를 고정한다. attach는 activation 전에 exact match를 요구하고 recovery는 저장된 핀을 재검증한다. grow/detach는 핀이 바뀌거나 빠진 설정을 mutation 전에 거절한다. 생략 호환 모드는 운영 프로필로 승인하지 않는다.
- `fce9066` (MAKI-018): dm-crypt 또는 zram writeback 하부에 NBD가 있거나, cycle·판독 오류·알 수 없는 virtual leaf가 있으면 secure swap으로 인정하지 않는다. device-mapper/MD/partition을 거쳐 실제 장치까지 확인하는 fixture 회귀이며, 실제 swap을 변경한 시험은 아니다.
- `f64f3d8` (MAKI-037): `nbd.threads`를 `1..=256`에서 검증하고 runtime의 숨은 clamp를 제거했다. [설정 계약](configuration.md#nbd-request-limits)은 Tokio worker, native nbdkit callback pool, request admission을 구분한다. 성능 보장은 별도다.
- `df886a3` (FUP-014): Linux backing이 root와 부모 디렉터리 descriptor를 고정하여 open·rename·remove·list·sync·lock을 수행한다. root 교체·symlink 거절·상위 디렉터리 권한 회귀를 추가했다. Linux 밖의 개발용 경로에 같은 보장을 확대해 주장하지 않는다.
- `be3b362` (MAKI-039): status/metrics가 storage lock과 free-space 조회를 기다리지 않는다. [관측 상태와 제한](observability.md)에 cached snapshot의 나이, busy 상태, unavailable cache/space 값과 외부 deadline을 명시했다. runtime 전체 정지나 thread starvation은 해결하지 않았다.
- `f20bb61` (MAKI-019 절차)와 `bdb9113` 기준 qualification: [자격 증명 교체와 키 이전 절차](key-rotation.md)를 추가했고, [세 호스트 실행](credential-rotation-key-migration-validation-2026-09-19.md)이 같은 K1을 유지한 bearer/mTLS client 교체와 별도 K2 volume으로의 SQLite DB-native 복원을 통과했다. [후속 네 호스트 실행](server-ca-endpoint-rotation-validation-2026-09-19.md)이 stopped server certificate/private-CA와 endpoint IP 교체를 추가로 통과했다. Commercial vendor와 대상 배포 환경 검증은 남는다.
- `24d06dd` (MAKI-048 일부): 설정표의 swap 제약과 복구·모니터링 문서 링크, CI 주석의 검사 문서 경로를 정리했다.
- `ad84cc0` (MAKI-047): 활성 `LoadCredential` directive와 맞지 않던 “Uncomment” 주석을 수정했다.
- `7a2bf94` (MAKI-024의 문서 범위): [deep check 설명](operations.md)을 저장 구조·CRC 검사로 한정했다. AEAD, 복구 후 논리 읽기 또는 DB 의미 일관성 검사를 새로 구현한 변경은 아니다.
- `466056d`: Unix 전용 control 생성 경로의 `with_admission`을 `cfg(unix)`로 제한해 Windows strict Clippy의 dead-code 오류를 수정했다. 변경 후 해당 snapshot의 전체 검사와 Linux·Windows CI가 통과했다.
- `133d36d` (MAKI-025 일부): checkpoint에 포함된 journal segment를 streaming으로 검사한다. 해당 fixture의 추가 heap peak는 135,397,624바이트에서 488바이트로 줄었으며 고정 64KiB stack scratch는 별도다. replay payload와 overlay 전체 메모리에는 아직 상한이 없다.
- `f7312c6`, `f643005`, `e14a018` 및 후속 통합 변경 (MAKI-020): 새 볼륨은 superblock envelope v2와 64바이트 `journal/durable-proof.a/b`를 요구한다. journal sync와 양쪽 proof 게시가 성공해야 ACK와 공개 durable sequence가 전진한다. recovery는 복구 메타데이터를 고치기 전에 required horizon의 연속성과 정확한 record end를 검증하며, 받아들인 tail의 양쪽 proof를 게시한 뒤 READY가 된다. [보장 범위와 호환성](durable-recovery.md)에 v1 writable 거절, 읽기 전용 검사 경고, 자동 in-place 이전 부재, 양쪽 유효 rollback에 대한 비보장을 명시했다. 통합 커밋 `1bc0ab5`의 전체 snapshot 검증 결과는 아래에 기록했다.

완료 검증 로그 (각 exit 0):

- context/전송/crypto 6개 crate 전체: `/home/seorii/logs/maki-r3-context-complete-full-20260910T225008.715207Z.log`.
- strict Clippy 6개 crate: `/home/seorii/logs/maki-r3-context-complete-clippy-20260910T225009.087527Z.log`.
- initial mount rollback 전체 privileged: `/home/seorii/logs/maki-r3-sentinel-full-20260910T224531.749402Z.log`.
- absolute grow helper/CLI 전체: `/home/seorii/logs/maki-r3-grow-green-20260910T224834.228839Z.log`.
- checker 수정 후 core 전체 144 passed, 6 ignored: `/home/seorii/logs/maki-r3-checker-memory-core-20260911T071122.102850Z.log`.
- mode·geometry 수정 후 format 전체: `/home/seorii/logs/maki-r3-format-full-green-20260911T071343.398330Z.log`.
- drain 관련 최종 회귀 및 실제 rootless native 시험: `/home/seorii/logs/maki-r3-drain-final-verified-retry-20260911T071546.428649Z.log`.
- production template 회귀: `/home/seorii/logs/maki-r3-auth-sample-green-20260912T025953.381121Z.log`.
- recover helper/CLI 최종 회귀: `/home/seorii/logs/maki-r3-recover-final-tests-20260912T083659.373680Z.log`.
- swap topology 회귀: `/home/seorii/logs/maki-r3-swap-topology-green-20260912T083300.386213Z.log`.
- worker count 관련 회귀: `/home/seorii/logs/maki-r3-nbd-threads-final-20260912T083814.685815Z.log`.
- Linux backing 최종 회귀: `/home/seorii/logs/maki-r3-backing-final-green-20260912T084135.296034Z.log`.
- monitoring 수정 후 core/cache 158 passed, 6 ignored: `/home/seorii/logs/maki-r3-monitoring-core-20260912T084100.107340Z.log`.
- monitoring 및 관련 nbdkit 34 passed: `/home/seorii/logs/maki-r3-monitoring-control-20260912T084100.495636Z.log`.

위 로그는 해당 수정 시점의 증거이며 최종 snapshot 전체 검증과 동일시하지 않는다. 테스트 중 기존 미추적 `review_next_swap.rs`는 현재 API와 맞지 않아 workspace 직접 실행을 막았다. 사용자 실험 파일은 보존하며 최종 검증은 커밋된 파일만 추출한 snapshot에서 수행한다. 공유 디스크가 가득 차 발생한 후속 linker SIGBUS는 코드 테스트 실패와 구분하고, 재생성 가능한 Maki 빌드 캐시 정리 후 다시 검증한다.

## 완료된 이전 snapshot 검증 — `466056d`

첫 검사 대상은 `be3b3626c452340414c7915dc5a0fd0906b4813c`의 커밋된 파일만 추출한 snapshot이었다. 완료된 결과는 fmt 0, strict Clippy 0, workspace tests 101이다. workspace 실행 중 benchmark fixture가 실제 backing 여유 공간 약 1.064GB를 확인해 1GiB emergency reserve 아래에서 ENOSPC를 반환했다. 코드의 내구성 검사가 통과했다는 뜻도, 단순히 무시할 실패라는 뜻도 아니다. 충분한 공간에서 같은 전체 검사를 다시 수행해야 한다.

디스크 압박을 멈추기 위해 당시 release 컴파일은 SIGTERM으로 종료했다(-15). release gate 통과로 계산하지 않는다. 첫 실행 PID 294626, 통합 종료 코드 1, 로그: `/home/seorii/logs/maki-r3-final-snapshot-validation-20260912T084416.089488Z.log`. 해당 revision의 GitHub CI에서 Ubuntu Clippy는 통과했으나 Windows는 `with_admission` dead-code 경고로 실패했고, `466056d`에서 수정했다.

자체 컴파일러 종료 후 Maki의 재생성 가능한 ignored `target/debug`만 정리하여 약 36GB를 확보했다. 다음 전체 검사 대상은 `466056d`이며 `CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_PROFILE_TEST_DEBUG=0`으로 debug 산출물 크기를 줄인다. release profile은 기본값을 유지한다. 이는 운영 성능 결과가 아니며 실행 조건을 구분하기 위해 기록한다.

재검증도 커밋된 파일만 추출하며 원본 트리의 미추적 실험 파일은 포함하지 않는다. 대상 기록은 `.git/r3-final-snapshot.json`, 결과 집계 경로는 `.git/r3-final-validation-results.json`이다.

완료된 단계의 종료 상태와 원격 CI를 아래에 기록한다. 재검증 PID 305605, 통합 종료 코드 0, 659.65초. 로그 `/home/seorii/logs/maki-r3-final-snapshot-retry-20260912T084825.305071Z.log`. 일반 workspace 711 passed, 0 failed, 10 ignored; 지정 release gate는 9 passed, 0 failed, 0 ignored이다. 일반 suite의 ignored 항목을 성공으로 합산하지 않았다.

| 검사 | 현재 문서 상태 | 완료 시 기록할 증거 |
|---|---|---|
| snapshot `cargo fmt --all --check` | 통과, exit 0 | `466056d`, 아래 재검증 로그 |
| snapshot workspace strict Clippy | 통과, exit 0 | `--workspace --all-targets --locked -- -D warnings` |
| snapshot workspace tests | 711 passed, 10 ignored, exit 0 | `--workspace --locked`; rootless nbdkit 실제 종료 오류 회귀 포함 |
| 지정 release gates 및 원격 추가 durability gate | 9 passed, 0 ignored, exit 0 | 기존 phase gate 7개 및 `phase_r3b_durability_gate_full`, `phase_r3b_concurrent_gate_full` |
| 코드 revision의 원격 CI | Linux·Windows 모두 성공 | `466056d`, [CI run](https://github.com/seo-rii/maki/actions/runs/34684217376) |

MAKI-020의 필수 proof 및 MAKI-025의 streaming 수정은 위 `466056d` snapshot에 포함되지 않는다. 처음에는 FUA 2회 성공 뒤 tail payload에 지속 손상을 넣고 mark를 없애거나 유효한 과거 mark로 되돌리면 당시 복구가 성공하는 두 조건을 재현했다(2 failed, exit 101; `/home/seorii/logs/maki-r3-durable-proof-both-red-20260912T085855.114585Z.log`). 정상 정전만으로 COMMIT이 유실됐다는 뜻은 아니다. 추가 Pro 설계 검토는 모델 선택 단계에서 실패하여 결과를 받지 못했다.

## v2 필수 proof 변경 — 1bc0ab5 검증 완료

MAKI-020은 위 RED를 출발점으로, 양쪽 proof의 게시와 보존, 실패 후 verified redirty 재시도, 복합 손상 거절, legacy 호환성, required horizon 검사 이전의 metadata 변경 방지를 구현했다. 집중 회귀 이후 `1bc0ab5`의 커밋된 파일만 추출한 snapshot에서 아래 전체 검증을 완료했다. 후속 변경의 검증은 별도로 기록한다.

| 검사 | 완료 상태와 증거 |
|---|---|
| proof codec/store 및 기존 A/B retry 회귀 | 24 passed, exit 0. `/home/seorii/logs/maki-r3-proof-store-final-20260912T092221.536378Z.log` |
| proof codec/store strict Clippy | exit 0. `/home/seorii/logs/maki-r3-proof-store-clippy-20260912T092221.575479Z.log` |
| 초기 core 통합 집중 회귀 | 9 passed, exit 0. `/home/seorii/logs/maki-r3-proof-integration-green-20260912T092246.536028Z.log` |
| 후속 core/format 전체 | 291 passed, 6 ignored, 0 failed, exit 0. `/home/seorii/logs/maki-r3-proof-verified-core-format-20260912T092844.123321Z.log` |
| 후속 core/format strict Clippy | exit 0. `/home/seorii/logs/maki-r3-proof-verified-clippy-20260912T092844.500283Z.log` |
| 두 번째 proof 게시 실패 회귀 | 2 passed, exit 0. `/home/seorii/logs/maki-r3-proof-second-barriers-final-tests-20260912T093357.710061Z.log` |
| `1bc0ab5` 전체 workspace/fmt/strict Clippy | workspace **768 passed, 0 failed, 10 ignored**, exit 0; fmt와 `--workspace --all-targets -- -D warnings`도 exit 0 |
| `1bc0ab5` 지정 release gate 9개 | **9 passed, 0 failed, 0 ignored**, exit 0. 새 형식으로 기존 7개 및 R3B durability/concurrent gate를 실행 |
| `1bc0ab5` Linux·Windows CI | 모두 성공, [CI run](https://github.com/seo-rii/maki/actions/runs/34686364092) |

전체 검증 PID 411370, 통합 종료 코드 0, 745.41초. 로그
`/home/seorii/logs/maki-r3-proof-snapshot-verified-20260912T093747.794339Z.log`.
workspace는 `cargo test --workspace --locked -j 2`, release는 같은 snapshot에서
`--release -- --ignored`와 위 9개 gate 이름을 지정했다. 일반 suite의 ignored
10개를 성공으로 합산하지 않았다. 이 결과에는 `972399d`의 최신 replay 보유
변경이 포함되지 않는다.

한쪽 proof가 사라지거나 오래되거나 손상되어도 다른 쪽에 현재 proof가 남으면 required horizon은 낮아지지 않는다. 둘 다 없거나 유효하지 않으면 빈 볼륨도 거절한다. CRC 위조나 양쪽 proof와 backing 전체의 유효한 과거 상태로의 동시 rollback은 막지 않으며 A/B 파일은 독립 물리 장애 도메인이 아니다. 추가 metadata/directory sync의 실제 FUA/FLUSH 지연과 지원 손상 모델의 운영 대상 검증이 남는다. 아래 잔여 항목은 로컬 테스트 통과만으로 자동 해결되지 않는다.

실제 Volume 복구의 최신 replay 보유 단위는 별도로 core 174 passed, 0 failed,
6 ignored 및 strict Clippy exit 0을 확인했다. 로그
`/home/seorii/logs/maki-r3-latest-replay-verified-core-20260912T094305.274290Z.log`,
PID 429879. 고정된 네 단위의 1 MiB/64 MiB overwrite 이력을 비교한 heap peak는
두 경우 모두 33,988 bytes였다. 이 후속 수정은 `1bc0ab5` 검증 snapshot에
포함되지 않는다. `972399d`의 커밋된 snapshot에서 관련 core release gate
6개(phase3/4/11/12, R3B durability/concurrent)를 추가 실행해 6 passed,
0 failed, 0 ignored를 확인했다. PID 498676, exit 0, 260.98초; 로그
`/home/seorii/logs/maki-r3-replay-release-verified-20260912T095315.996795Z.log`.
이 커밋의 [Linux·Windows CI](https://github.com/seo-rii/maki/actions/runs/34686934432)도
모두 성공했다. 나머지 3개 release gate의 최근 실행은 `1bc0ab5` 기준이다.

## 전체 workspace 및 release snapshot 검증 — fb3da46

커밋된 소스만 추출한 `fb3da461d5d399b13e87c90fd3b951045b5bb29b`에서
아래 검사를 완료했다. 이전 snapshot의 성공을 재사용한 결과가 아니다.

| 검사 | 완료 결과 |
|---|---|
| 전체 fmt 및 workspace/all-targets strict Clippy | 모두 exit 0 |
| `cargo test --workspace --locked -j 2` | **812 passed, 0 failed, 10 ignored**, exit 0 |
| 지정 release gate 9개 | **9 passed, 0 failed, 0 ignored**, exit 0 |
| Linux·Windows CI | 모두 성공, [CI run](https://github.com/seo-rii/maki/actions/runs/34688000506) |

PID 625199, 통합 exit 0, 645.46초. 로그:
`/home/seorii/logs/maki-r3-transport-final-verified-20260912T101639.234527Z.log`.
release는 같은 snapshot의 workspace에서 `--release --locked -- --ignored`
뒤에 phase0/3/4/11/12, phase5 endpoint/breaker, R3B durability/concurrent의
9개 이름을 지정했다. 일반 suite의 ignored 10개를 성공으로 합산하지 않았다.
후속 카운터 수정은 이 snapshot에 포함되지 않는다.

추가 의존성 검사 `cargo audit --json`도 exit 0으로 끝났으며 알려진 취약점
0건, 경고 0건이었다. RustSec DB revision은
`b50980aad8b8f14f77e25a97b32dd94bf008b0af`(마지막 갱신 2026-09-09),
PID 622494; 로그
`/home/seorii/logs/maki-r3-dependency-audit-20260912T101606.925259Z.log`.
이는 해당 advisory DB와 Cargo.lock 대조 결과이며 알려지지 않은 취약점이나
배포 환경의 안전성을 증명하지 않는다. 원본 R3 리뷰의 SHA256 검사는 통과했고
미해결 항목이 있으므로 원본을 계속 보존한다.

## 카운터 수정 후 전체 snapshot 검증 — 55ef3ec

`f77daae`의 core recovery/writer와 `55ef3ec`의 공개 format scanner 수정을
포함한 커밋 소스 `55ef3ec43214242b3b257b33a083aaf307dcb10f`에서 fmt,
workspace/all-targets strict Clippy, 전체 workspace 검사를 다시 완료했다.
모두 exit 0이며 workspace는 **830 passed, 0 failed, 10 ignored**다.
PID 703634, 통합 exit 0, 162.88초; 로그:
`/home/seorii/logs/maki-r3-counter-final-verified-20260912T103936.029151Z.log`.
[해당 커밋의 Linux·Windows CI](https://github.com/seo-rii/maki/actions/runs/34689007382)도
모두 성공했다. 이 snapshot에서는 전체 release gate 9개를 반복하지 않았다.
변경한 counter 경로의 release 회귀와 format 전체 release 131개는 아래
수정별 기록대로 통과했으며, 전체 release 9개의 최근 결과는 위 `fb3da46`이다.

MAKI-048 문서 대조에서는 현재 reload를 활성 cache의 `max_bytes`로 한정하고,
SPEC production 예시의 인증·context 계약을 packaged 예시와 맞췄다. 자동
simulation CI와 실제 DB/XFS qualification 목표, 등록된 SecretBuffer의 잠금과
별도 transport 할당, oneshot의 과거 성공과 현재 mount 신원도 구분했다.
후속 workload verify 명령과 수신 응답·overlay 변경도 현재 코드와 운영 문서를
최종 대조했다. MAKI-048 문서 일관성 항목은 완료했으며, 다른 코드·운영 검증
항목의 종료나 운영 승인을 뜻하지 않는다.

후속 native 검토에서 operations의 오래된 FUA/블록 크기 설명이 대조에서
누락됐음을 확인했다. `5269b0e`에서 실제 ABI·협상 검사에 맞게 native FUA와
블록 크기 callback 설명을 고쳤다. 이전 문서 대조 결과를 모든 문장의 완전성
보증으로 확대하지 않는다.

## 수신 응답·overlay·workload verify 통합 snapshot — b3c5103

`b3c510333da44b73f8b1819a269bd87779a08613`의 커밋된 소스만 추출해 전체
fmt, workspace/all-targets strict Clippy와 workspace 검사를 완료했다.
모두 exit 0이고 **865 passed, 0 failed, 10 ignored**다. 같은 snapshot에서
`phase11_gate_dbsim_full` release 검사도 **1 passed**, exit 0이다. release는
debug symbols만 비활성화했다. 이 DB 검사는 실제 DB가 아닌 simulation이다.
PID 812671, 통합 exit 0, 237.68초; 로그:
`/home/seorii/logs/maki-r3-workload-final-verified-20260912T110413.350690Z.log`.
[해당 커밋의 Linux·Windows CI](https://github.com/seo-rii/maki/actions/runs/34690037136)도
모두 성공했다. overlay의 나머지 관련 release 5개는 아래 `4a0db11` 수정
기록에서 검증했으며, 전체 release 9개의 최근 실행은 여전히 `fb3da46`이다.

현재 문서 13개의 로컬 파일 링크와 SPEC/packaged production TOML의 의미상
일치를 확인했다. R3 원본 SHA256도 exit 0이며 미해결 원본 항목은 보존한다.

## LVM 사전 검사·native 준비 상태 통합 snapshot — 2a3f023

`2a3f023365e1aef759a2a92ad3d024454c94df2d`의 커밋된 소스만 추출해 fmt,
workspace/all-targets strict Clippy와 workspace 검사를 완료했다.
모두 exit 0이며 **901 passed, 0 failed, 10 ignored**다. PID 915222,
통합 exit 0, 188.09초; 로그:
`/home/seorii/logs/maki-r3-native-ready-final-verified-20260912T115825.561153Z.log`.
별도 집중 검사에서는 설치된 nbdkit 1.32.5로 native startup 9개를 실제 실행했다.
이 lifecycle 변경에서 전체 release 9개나 DB simulation을 반복하지 않았으며,
해당 결과는 위 `fb3da46`/`b3c5103` 기준으로 남긴다.

정상 푸시도 exit 0(PID 938352;
`/home/seorii/logs/maki-r3-native-ready-push-20260912T120211.908393Z.log`)이다.
[해당 커밋의 Linux·Windows CI](https://github.com/seo-rii/maki/actions/runs/34692584706)가
모두 성공했다. Linux는 nbdkit·plugin header·libnbd 도구 설치와 실행 확인을
통과한 뒤 workspace 검사를 실행했다. Windows는 Linux 전용 설치를 건너뛰고
자기 플랫폼의 fmt·strict Clippy·workspace 검사를 통과했다.
CI의 nbdkit 1.36.3/libnbd 1.20.0에서도 native startup **9 passed**를 실행
로그로 확인했다. 완료된 Linux job 로그 수집 PID 978013, exit 0:
`/home/seorii/logs/maki-r3-native-ready-ci-linux-complete-20260912T120853.861042Z.log`.
최종 문서 15개의 로컬 파일 링크 118개는 모두 실제 대상 파일을 가리킨다.
실제 운영 서비스 배포, kernel NBD/LVM/XFS 및 DB 검증은 실행하지 않았다.

## 남은 리뷰 항목과 종료 조건

MAKI-006의 native 초기 준비 상태를 별도로 수정했다. 첫 NBD `open`에
의존하던 adapter 초기화를 nbdkit의 `after_fork`로 옮겨, 복구·설정된 provider
검증·control bind를 끝낸 후에만 같은 프로세스가 `READY=1`을 보낸다.
서비스의 `Type=notify`와 `NotifyAccess=main`은 기존 attach 의존 순서가
이 신호를 기다리게 하며, 시작 대기에는 180초 기본 상한을 둔다. 준비 실패나
지정된 통지 경로의 실패는 시작 실패다. 통지 환경변수가 없는 수동 실행도
첫 client 전에 초기화한다. [초기 준비 상태의 범위](operations.md#data-plane-readiness)는
NBD data plane이며, XFS mount·workload별 storage verify·DB 복구·지속적인
건강 상태를 대신하지 않는다. 실제 서비스 배포와 운영 대상 검증은 남는다.

실제 nbdkit에서 첫 client 없이 READY가 없고 잘못된 설정·복구도 실패 종료하지
않는 RED 3개를 먼저 확인했다(PID 889560, exit 101;
`/home/seorii/logs/maki-r3-native-startup-red-fixed-20260912T114327.477856Z.log`).
abstract 주소 최대 길이 RED 1개(PID 899887, exit 101;
`/home/seorii/logs/maki-r3-native-ready-abstract-red-20260912T115002.305199Z.log`)도
구현 수정 전에 확인했다. 최종 lib·ABI·협상·drain·startup 집중 검사는
**42 passed, 0 failed**, exit 0(PID 905148;
`/home/seorii/logs/maki-r3-native-startup-final-focused-20260912T115140.410937Z.log`)이며,
설치된 nbdkit 1.32.5로 native startup 9개를 실제 실행했다. 같은 명시 타깃의
strict Clippy도 exit 0(PID 905392;
`/home/seorii/logs/maki-r3-native-startup-final-clippy-focused-20260912T115140.767678Z.log`)이다.
경로/abstract 주소, 통지 생략·실패, control bind 실패, 첫 client 후 중복 READY
부재를 검증했다. 패키지 서비스와 Linux CI 도구 설치 계약도 각각 실제 RED 1개
(PID 883207, 904471; exit 101) 후 **4 passed**, exit 0으로 확인했다(PID 908134;
`/home/seorii/logs/maki-r3-native-ready-ci-green-20260912T115323.737822Z.log`).
Linux CI는 native 도구를 설치·확인하고 workspace 검사를 실행한다. 개발 환경의
도구 미설치 skip을 native 실행 성공으로 취급하지 않는다.

`9fd8bfe`는 MAKI-015의 provider-owned 수신 응답을 추가 보호한다. 문자열·부분
JSON·frame 해제 RED 3개(PID 743395, exit 101;
`/home/seorii/logs/maki-r3-ws-response-secrets-red-20260912T104629.715361Z.log`)와
guard 이전 UTF-8 거절 RED 1개(PID 770704, exit 101;
`/home/seorii/logs/maki-r3-ws-response-utf8-red-20260912T105154.621982Z.log`)를
먼저 확인했다. payload를 UTF-8 검사 전에 소유하고 JSON 문자열·키를 생성
시점부터 보호한다. 부분 파싱 실패, 중복 필드 교체, stale/cancelled 응답을
포함하며, 기존 probe 오류의 필드 중복·타입 판정과 wire/API는 유지한다.
전체 WS 49 passed, exit 0(PID 795568;
`/home/seorii/logs/maki-r3-ws-response-secrets-verified-green-20260912T105659.088623Z.log`),
strict Clippy exit 0(PID 798404;
`/home/seorii/logs/maki-r3-ws-response-secrets-verified-clippy-20260912T105742.787597Z.log`)이다.
고유 sliced Bytes의 초기화된 원본 전체 capacity 소거도 확인했다. 선택적
page lock은 노출된 길이를 대상으로 하며 공유 원본, tungstenite 내부 버퍼,
serde escape scratch와 전체 RSS는 남는다. [소유권 범위](transport-memory.md)를
전체 transport 보호 완료로 확대하지 않는다.

R3-007/MAKI-006/040의 workload 시작 전 재검증 경로를 추가했다.
`maki-attach verify`가 없는 CLI RED 1개를 먼저 확인한 뒤 구현했다
(exit 101;
`/home/seorii/logs/maki-r3-workload-verify-cli-red-20260912T104400.824084Z.log`).
기존 root 상태와 잠금을 생성 없이 열고, root 관리 설정의 volume/fs UUID,
connected nonce, 저장된 전체 mapping proof, rw whole-XFS mount와 sentinel을
검사한다. LV fd를 고정한 blkid 및 bounded/no-follow sentinel 읽기 후 신원을
다시 확인한다. identity override와 proof 없는 기록은 거절한다. 파일 생성,
write probe, 복구나 DB 시작은 하지 않으며 `--plan`은 검증 증거가 아니다.
하위 foreign mount가 DB 경로를 가리는 두 RED도 추가로 확인했다(exit 101;
`/home/seorii/logs/maki-r3-workload-submount-red-20260912T110038.894367Z.log`).
verify에서만 경로 구성요소 기준으로 모든 descendant mount를 거절하며,
공백·백슬래시 escape, root 행 전후 순서, `/` 경계와 sibling 제어를 검증했다.
privileged/attach 전체 122 passed, 1 ignored, exit 0(PID 810317;
`/home/seorii/logs/maki-r3-workload-submount-final-all-20260912T110156.606393Z.log`),
두 package all-targets strict Clippy exit 0(PID 810561;
`/home/seorii/logs/maki-r3-workload-submount-final-clippy-20260912T110157.024822Z.log`)을
확인했다. [실행 범위](storage-recovery.md#checking-storage-before-each-workload-start)는
현재 caller namespace의 storage identity다. lock 대기·kernel read의 전체 시간 상한,
명령 종료 이후 가용성, 다른 container namespace 및 DB 복구를 보장하지 않는다.
당시 남았던 활성화 전 LVM 신원과 activation→proof crash 공백은 각각 후속
`1dd4069`와 `b68935d`에서 좁혔다.

MAKI-005의 후속 변경은 NBD 후보의 kernel parent/device/geometry와 독립적인
PV label 목록을 LVM 전체 VG 보고서에 대조한다. VG 이름만 사용하던 활성화는
검증한 device 목록, 발견한 VG UUID와 complete mode를 사용한다. 보고서의
`pv_duplicate=0`만으로 중복 부재를 가정하지 않으며, 별도 후보의 같은 PVID나
보고서에서 누락된 PV를 거절한다. `blkid` exit 2를 빈 장치의 증거로 취급하지
않으므로 빈 여분 파티션과 판독·분류 불가 후보는 이번 지원 범위에서 거절한다.
후속 `a2cc5bc`는 선택적인 `[lvm_identity]`에 전체 PV UUID 집합, VG UUID와
설정 대상 LV UUID를 모두 요구한다. 독립 label/fullreport 결과가 핀과 정확히
일치해야 activation하며, 정렬된 핀을 attachment identity에 저장해 recovery가
다시 검사한다. grow/detach 설정에서 핀이 바뀌거나 빠져도 mutation 전에
거절한다. 기존 unpinned 설정/기록은 호환을 위해 읽지만 독립 관리 신원 인증이
아니므로 운영 프로필로 승인하지 않는다. host udev 자동 활성화와 다른 root
작업의 원자성은 남는다.
[LVM 사전 검사 제한](storage-recovery.md#checking-lvm-before-activation)을
실제 운영 토폴로지와 함께 검증해야 하며 이 항목 전체를 완료로 처리하지 않는다.

실제 RED는 외부 PV와 연결 없는 활성화 계획 2개(PID 832344, exit 101;
`/home/seorii/logs/maki-r3-lvm-preflight-red-20260912T111740.606060Z.log`),
PV 중첩·device alias·다른 LV UUID·잘못된 UUID 롤백·계획 표시 5개
(PID 846082, exit 101;
`/home/seorii/logs/maki-r3-lvm-preflight-boundaries-red-fixed-20260912T112718.080288Z.log`),
사전 검사 실패 중 나타난 외부 mapping의 롤백 1개(PID 854312, exit 101;
`/home/seorii/logs/maki-r3-lvm-preflight-early-rollback-red-20260912T112926.771361Z.log`),
cachevol 사전 거절 2개(PID 856473, exit 101;
`/home/seorii/logs/maki-r3-lvm-preflight-cachevol-red-20260912T113023.154099Z.log`)다.
수정 후 helper/CLI 전체 **142 passed, 0 failed, 1 ignored**, exit 0
(PID 866086;
`/home/seorii/logs/maki-r3-lvm-preflight-final-packages-20260912T113539.686746Z.log`)과
두 package all-targets strict Clippy exit 0(PID 866330;
`/home/seorii/logs/maki-r3-lvm-preflight-final-clippy-20260912T113540.043074Z.log`)을
확인했다. fmt와 독립 재검토도 통과했다. 정상 내부 UUID suffix, 부분 활성화
롤백과 kernel parent/range/device/holder 제어를 포함한다. 실제 장치의 LVM
report/activation이나 DB 검증은 실행하지 않았다.

이 단위는 `1dd4069d3407f8f7b78dd5f26fe0b380b2b20fb3`로 정상 푸시했다
(PID 872497, exit 0;
`/home/seorii/logs/maki-r3-lvm-preflight-push-20260912T113801.079900Z.log`).
UUID 핀 TDD의 RED는
`/home/seorii/logs/maki-r3-lvm-identity-pins-red-20260912T161500Z.log`,
GREEN은
`/home/seorii/logs/maki-r3-lvm-identity-pins-focused-green-20260912T161900Z.log`다.
최종 privileged lib 114 passed/1 ignored, 통합 34 passed와 attach 10 passed,
strict Clippy·fmt가 통과했다
(`/home/seorii/logs/maki-r3-lvm-identity-pins-full-20260912T162000Z.log`,
`/home/seorii/logs/maki-r3-lvm-identity-pins-clippy-20260912T162100Z.log`,
`/home/seorii/logs/maki-r3-lvm-identity-pins-fmt-20260912T162200Z.log`).
[해당 커밋의 Linux·Windows CI](https://github.com/seo-rii/maki/actions/runs/34691556494)는
fmt, strict Clippy, workspace 검사를 모두 통과했다. 이 helper 단위 때문에
이전 9개 release simulation gate를 반복하지는 않았다.

후속 `b68935d`는 LVM activation 직전에 위 preflight 결과를 recovery intent로
원자 게시하고, complete mapping proof 게시와 같은 record 갱신에서 intent를
제거한다. activation 직후 helper가 죽는 RED와 손상된 persisted intent RED를
각각 `/home/seorii/logs/maki-r3-007-recovery-intent-red-20260913.log`,
`/home/seorii/logs/maki-r3-007-intent-validation-red-20260913.log`에서 확인했다.
foreign VG/dm UUID, NBD device number, slave, 추가 holder와 mounted upper layer는
mutation 0회로 거절한다. focused 15 passed, privileged 전체 137 passed/1 ignored,
strict Clippy와 fmt/diff 검사가 통과했다. backend가 사라진 경우에만 recover를
사용하고, intent는 scoped deactivation 외의 upper-layer 작업을 허용하지 않는다.
실제 NBD/LVM/XFS와 container/workload 재시작 qualification은 남는다.

후속 `91d406f`는 같은 intent를 recorded backend nonce가 계속 연결된 정상
detach에도 적용했다. 변경된 dm UUID·name·slave·holder·mount를 mutation 전에
거절하고, partial activation에서는 검증된 LV/internal mapping subset만
device-list와 VG UUID로 제한해 비활성화한다. 임의의 internal UUID suffix를
허용하던 RED도 별도로 닫았다. RED 로그는
`/home/seorii/logs/maki-r3-connected-intent-red-20260912T155628.859248Z.log`,
`/home/seorii/logs/maki-r3-lvm-internal-suffix-red-20260912T160352.052470Z.log`다.
최종 privileged unit·integration은 142 passed/1 ignored
(`/home/seorii/logs/maki-r3-connected-intent-final-full-20260912T160422.999048Z.log`),
strict Clippy도 exit 0
(`/home/seorii/logs/maki-r3-connected-intent-final-clippy-20260912T160433.231699Z.log`)이었다.

MAKI-028의 동일 ciphertext 중복 보유를 별도 수정했다. 64×64KiB의 promotion과
실제 FileBacking checkpoint에서 전체 ciphertext가 재복사되는 RED 2개와
기존 버전/API 제어 2개의 통과를 먼저 확인했다(PID 758308, exit 101;
`/home/seorii/logs/maki-r3-overlay-sharing-red2-20260912T105007.223459Z.log`).
private Arc로 동일 latest/durable와 내부 checkpoint snapshot만 공유하며
공개 owned-copy API와 두 버전을 합산하는 논리적 `bytes()`는 유지한다.
추가 heap peak는 promotion 4,192,480→0 bytes, checkpoint
4,262,528→66,688 bytes였다. 기존 네 단위 1/64MiB 복구 fixture도 재측정해
둘 다 21,280 bytes를 확인했다(PID 783468, exit 0;
`/home/seorii/logs/maki-r3-overlay-sharing-recovery-measure-20260912T105408.761843Z.log`).
이전 33,988 bytes는 overlay 공유 전 결과다. core 전체 197 passed,
6 ignored, exit 0(PID 771865;
`/home/seorii/logs/maki-r3-overlay-sharing-core-20260912T105212.001171Z.log`),
all-targets strict Clippy exit 0(PID 772112;
`/home/seorii/logs/maki-r3-overlay-sharing-clippy-20260912T105212.382385Z.log`),
관련 phase3/4/12 및 R3B durability/concurrent release gate 5개도 모두 통과했다
(PID 775728, exit 0, debug symbols만 비활성화;
`/home/seorii/logs/maki-r3-overlay-sharing-release-gates-20260912T105247.376322Z.log`).
이 후속 변경은 `55ef3ec` snapshot 검증에 포함되지 않는다.

후속 복구 카운터 검사는 CRC가 유효한 극단값에서 panic/wrap하거나 metadata
재기록 이후 중단하는 경로를 수정했다. scan/deep_check/Volume::recover의
RED 6 failed(PID 655635, exit 101;
`/home/seorii/logs/maki-r3-recovery-counter-red-20260912T102352.443277Z.log`)와
append/roll의 변이 이후 panic RED 2 failed(PID 660690, exit 101;
`/home/seorii/logs/maki-r3-recovery-counter-writer-red-20260912T102522.575120Z.log`)를
먼저 확인했다. checked successor로 변이 전에 거절하며 MAX-1의 정상 읽기와
마지막 유효 기록을 유지한다. core 회귀는 debug/release 각각 10 passed,
exit 0: PID 668705, `/home/seorii/logs/maki-r3-recovery-counter-final-debug-20260912T102742.505784Z.log`;
PID 668966, `/home/seorii/logs/maki-r3-recovery-counter-release-20260912T102742.886460Z.log`.
이 집중 release 회귀는 debug symbol만 껐다. core all-targets strict Clippy는
exit 0(PID 669275;
`/home/seorii/logs/maki-r3-recovery-counter-clippy-20260912T102743.272721Z.log`)이다.
이 후속 변경은 위 `fb3da46` 전체 snapshot 검증에 포함되지 않는다.

공개 slice journal scanner도 별도 수정했다. 완료된 MAX sequence record와
손상 payload 뒤 successor 탐색이 overflow하는 RED 3개를 먼저 확인했다
(PID 680904, exit 101;
`/home/seorii/logs/maki-r3-format-counter-red-20260912T103111.557613Z.log`).
표현할 수 없는 다음 sequence는 payload를 결과에 복사하기 전에 거절하며
MAX-1 prefix와 기존 torn-tail/durable-prefix 판정은 유지한다. format 전체
debug/release는 각각 131 passed, exit 0(PID 684346/684804;
`/home/seorii/logs/maki-r3-format-counter-all-debug-20260912T103239.273267Z.log`,
`/home/seorii/logs/maki-r3-format-counter-all-release-20260912T103239.708019Z.log`)이다.
집중 release 검사에서는 debug symbols만 끈다(`CARGO_PROFILE_RELEASE_DEBUG=0`).
format strict Clippy는 exit 0(PID 685140;
`/home/seorii/logs/maki-r3-format-counter-clippy-20260912T103240.170979Z.log`),
core counter와 scanner differential/memory 회귀는 21 passed, exit 0
(PID 688804;
`/home/seorii/logs/maki-r3-counter-final-combined-debug-20260912T103348.758180Z.log`)이다.
이 변경도 `fb3da46`의 이전 전체 snapshot 결과와 구분한다.

MAKI-015의 WS 요청도 중간 JSON tree/base64 String을 없애고 고정
`SecretBuffer`에 직접 직렬화했다. 실제 요청의 연결 전 취소·과대 frame RED
2개(PID 577718, exit 101;
`/home/seorii/logs/maki-r3-ws-request-secrets-red-20260912T100655.147157Z.log`)와
주소 가능 capacity 초과 RED(PID 602314, exit 101;
`/home/seorii/logs/maki-r3-ws-request-capacity-red-20260912T101104.921254Z.log`)를
확인했다. 마지막 Bytes/Message 소유자까지 보호하며 전체 WS 35 passed,
exit 0(PID 608315;
`/home/seorii/logs/maki-r3-ws-request-secrets-verified-green-20260912T101156.856770Z.log`),
strict Clippy exit 0(PID 613372;
`/home/seorii/logs/maki-r3-ws-request-secrets-verified-clippy-20260912T101249.221580Z.log`)이다.
그 후 `9fd8bfe`에서 소유한 응답 tree/frame을 보호했다. library-private
scratch/frame copies와 전체 resident budget은 남는다.

MAKI-021의 stale free-space admission을 먼저 수정했다. 시계를 전진하지
않고 여유 공간을 high→low, low→high, unknown→known-low로 바꾸는 RED 3개가
실패했다(PID 583843, exit 101;
`/home/seorii/logs/maki-r3-fresh-space-red-20260912T100807.570132Z.log`). 쓰기
판단에만 새 조회를 강제했고 관련 6개 및 core 전체 182 passed, 6 ignored,
exit 0(PID 593921;
`/home/seorii/logs/maki-r3-fresh-space-all-core-20260912T100939.097861Z.log`),
strict Clippy exit 0(PID 593322;
`/home/seorii/logs/maki-r3-fresh-space-clippy-20260912T100931.425712Z.log`)이었다.

후속 `223db0c`는 reserve만 비교하던 판단에 정확한 다음 journal append
footprint를 더하고 `None`/EIO와 산술 overflow를 ENOSPC로 닫았다. 경계·오류
RED는 각각 `/home/seorii/logs/maki-r3-space-admission-red-20260912T153302.313039Z.log`,
`/home/seorii/logs/maki-r3-space-admission-overflow-red-20260912T153900.976531Z.log`다.
수정 후 core 199 passed, 6 ignored와 strict Clippy가 통과했다. 정책과 무관한
in-memory transport/nbdkit fixture는 `223db0c`에서 reserve 0을 명시했다.
FileBacking을 쓰는 benchmark config는 `ba22e6c`, config-driven NBD fixture는
`aab7a16`, 나머지 cross-platform NBD integration config는 `ef5e8a7`에서
같은 시험 전용 값을 명시했다. 운영 기본값은 바꾸지 않았다. 영향받은 HTTP·
gRPC·WebSocket·NBD 통합 24개는 로컬에서 통과했으며 최종 Windows CI 결과는
아래 현재 revision 검증과 구분한다. 조회 이후 외부 공간 소비, 새 checkpoint
slot과 bitmap/metadata, checkpoint 완주 공간의 실물 예약은 여전히 보장되지
않는다.

최종 코드 revision `ef5e8a7`의 [Linux·Windows CI](https://github.com/seo-rii/maki/actions/runs/34704665399)는
fmt, workspace all-targets strict Clippy와 전체 workspace tests를 모두 통과했다.
Linux job은 native NBD 도구를 설치하고 fault-campaign oracle도 실행했다. nightly
release gates는 이 push-triggered run의 실행 대상이 아니며, 앞서 기록한
`fb3da46`의 9개 release gate와 이후 범위별 검사를 현재 코드 전체의 새 release
snapshot으로 확대하지 않는다.

후속 HTTP credential 수명 변경 `8419b3d`의
[Linux·Windows CI](https://github.com/seo-rii/maki/actions/runs/34705597735)와,
그 변경을 포함한 LVM UUID 핀 revision `a2cc5bc`의
[Linux·Windows CI](https://github.com/seo-rii/maki/actions/runs/34705758371)도 fmt,
workspace all-targets strict Clippy와 전체 workspace tests를 통과했다. 두 Linux
job은 native NBD 도구와 fault-campaign oracle도 실행했다. nightly release gates는
push run에서 생략되므로 앞서 기록한 release snapshot 범위를 바꾸지 않는다.

MAKI-005의 파일시스템 검사 순서는 별도로 수정했다. 잘못된 UUID 또는
비-XFS를 mount·sentinel 쓰기 후에야 거절하는 RED 2개를 먼저 확인했다
(PID 565315, exit 101;
`/home/seorii/logs/maki-r3-premount-filesystem-red-20260912T100414.261832Z.log`).
bounded `blkid --probe`로 TYPE과 설정된 UUID를 mount 전에 검사하고 probe
전후 backend/mapping을 다시 검증한다. 집중 회귀 7개와 privileged/attach
전체 106 passed, 1 ignored, exit 0(PID 584793;
`/home/seorii/logs/maki-r3-premount-filesystem-full-20260912T100820.432850Z.log`),
strict Clippy exit 0(PID 585042;
`/home/seorii/logs/maki-r3-premount-filesystem-clippy-20260912T100820.806650Z.log`)을
확인했다. 이 변경 당시에는 실제 kernel/DB 시험, 활성화 전 LVM 신원 검증과
activation→proof crash 공백이 남았고, 뒤의 `1dd4069`/`b68935d`가 두 코드
공백을 각각 좁혔다. `fs_uuid` 생략은 기존대로 허용하며 TYPE만 검사한다.

MAKI-025의 deep checker도 전체 replay payload 보유를 제거했다. 1 MiB/64 MiB
저널에서 추가 heap peak가 각각 1,060,242/67,765,650 bytes로 늘어나는 RED를
확인했다(PID 567161, exit 101;
`/home/seorii/logs/maki-r3-deep-scan-memory-red-20260912T100444.042988Z.log`).
검증한 payload를 즉시 버리고 기존 기록 수·required proof·손상·torn-tail
판정을 공유한 뒤 두 경우 모두 9,176 bytes로 줄었다. checker/recovery/proof
회귀 27 passed, exit 0(PID 580442;
`/home/seorii/logs/maki-r3-deep-scan-memory-final-20260912T100741.192029Z.log`),
관련 strict Clippy exit 0(PID 580858;
`/home/seorii/logs/maki-r3-deep-scan-memory-clippy-20260912T100741.568824Z.log`).
이 시점에는 공개 all-record API와 실제 attach의 고유 단위·overlay/metadata
메모리가 남았다. 후속 `733833c`가 attach payload를 1 MiB batch로 바꿨고,
공개 API와 metadata/runtime/provider/cache 비용은 계속 별도다.

MAKI-015의 WebSocket decoded-output 단위는 별도로 완료했다. 부분 base64
디코딩 오류와 뒤 항목 거절에서 해제 직전 평문 잔존을 확인한 RED 2개를
먼저 실행했다(PID 505010, exit 101;
`/home/seorii/logs/maki-r3-ws-decoded-secrets-red-20260912T095528.092317Z.log`).
출력 처음부터 `SecretBuffer`로 소유한 뒤 전체 WebSocket 28 passed, exit 0
(PID 514438; `/home/seorii/logs/maki-r3-ws-decoded-secrets-green-20260912T095638.444940Z.log`),
strict Clippy exit 0(PID 517699;
`/home/seorii/logs/maki-r3-ws-decoded-secrets-clippy-20260912T095733.902307Z.log`)을
확인했다. JSON/base64 문자열과 transport 내부 복사본은 이 수정의 범위가
아니다. [소유권과 남은 범위](transport-memory.md)를 별도로 명시한다.

`d843540`은 같은 원칙을 HTTP Base64/Base64URL/hex decoder의 오류 경로에
적용했다. malformed 입력이 257-byte 부분 평문을 지우지 않고 해제하는 RED
2개(`/home/seorii/logs/maki-r3-http-decode-red-confirmed-20260912T153530.020456Z.log`)
뒤, 첫 출력 byte 전에 정확한 크기의 zeroizing owner를 설치했다. HTTP 전체는
35 passed/3 ignored, exit 0
(`/home/seorii/logs/maki-r3-http-decode-all-green-20260912T154703.185710Z.log`)이고
scoped all-targets strict Clippy도 통과했다. 이 시점에는 response accumulator의
이전 allocation과 JSON key/request 오류 경로가 아직 남아 있었다.

후속 `44ba589`는 response buffer가 성장할 때 새 zeroizing allocation에 복사한
뒤 이전 owner를 지우고 교체한다. RED·focused GREEN·전체 HTTP·strict Clippy
로그는 각각
`/home/seorii/logs/maki-r3-http-response-growth-red-20260912T160123.496084Z.log`,
`/home/seorii/logs/maki-r3-http-response-growth-green-20260912T160157.015567Z.log`,
`/home/seorii/logs/maki-r3-http-response-growth-all-20260912T160213.938345Z.log`,
`/home/seorii/logs/maki-r3-http-response-growth-clippy-20260912T160231.852860Z.log`다.

`e1f4143`은 object key, 잘못된 pointer의 incoming value, overwrite와 intermediate
replacement, 부분 per-item/batch request tree를 조기 반환에서도 지우는 RAII를
추가했다. 여섯 RED가 모두 평문 allocation 해제를 관찰했고
(`/home/seorii/logs/maki-r3-http-json-red-confirmed-20260912T160646.273386Z.log`),
focused 9 passed, 전체 HTTP 42 passed/3 ignored, strict Clippy가 통과했다
(`/home/seorii/logs/maki-r3-http-json-green-confirmed-20260912T160813.313621Z.log`,
`/home/seorii/logs/maki-r3-http-json-all-20260912T160822.872270Z.log`,
`/home/seorii/logs/maki-r3-http-json-clippy-20260912T160844.302415Z.log`).
후속 `8419b3d`는 provider/spec가 소유한 resolved header/query 값과 결합된
mTLS identity PEM을 정상 drop과 provider/config 구성 오류에서 지운다. key-source
credential을 UTF-8로 확인할 때 중간 byte vector도 만들지 않는다. 세 RED와 focused
GREEN, 전체 HTTP **46 passed/3 ignored**, strict Clippy가 통과했다
(`/home/seorii/logs/maki-r3-http-credential-provider-drop-red-20260912.log`,
`/home/seorii/logs/maki-r3-http-credential-construction-red-20260912.log`,
`/home/seorii/logs/maki-r3-http-credential-config-red-20260912.log`,
`/home/seorii/logs/maki-r3-http-credential-focused-green-20260912.log`,
`/home/seorii/logs/maki-r3-http-credential-all-green-20260912.log`,
`/home/seorii/logs/maki-r3-http-credential-clippy-green-20260912.log`).
원본 설정 문자열, malformed response를 Value로 반환하기 전 serde_json 내부
allocation, page lock과 reqwest/hyper/rustls/kernel 복사본은 보장 밖이다.

gRPC provider가 소유하는 protobuf item도 별도 수정했다. 전체 capacity의
Drop/clear/중복 필드 교체, parent에 추가되기 전 부분 decode 실패, 실제
tonic 인코딩과 취소를 검사했다. 최초 RED 8 failed(PID 496466, exit 101;
`/home/seorii/logs/maki-r3-grpc-owned-red-20260912T095252.107877Z.log`)와
추가 tonic RED 3 failed(PID 502329, exit 101;
`/home/seorii/logs/maki-r3-grpc-owned-tonic-red-20260912T095441.855915Z.log`)를
확인한 뒤 구현했다. 전체 gRPC는 31 passed, exit 0(PID 525372;
`/home/seorii/logs/maki-r3-grpc-owned-all-tests-20260912T095838.241230Z.log`),
strict Clippy도 exit 0(PID 533205;
`/home/seorii/logs/maki-r3-grpc-owned-clippy-20260912T095936.047726Z.log`)이다.
공개 protobuf API와 wire는 유지한다. item의 zeroization을 tonic 내부
buffer 소거나 성공 전 page lock까지 확대해 주장하지 않는다.

로컬 리뷰의 `01-prior-50-status.md`(MAKI-001–050)와 `02-followup-15-status.md`(FUP-001–015)의 번호를 유지한다. R3-001–006/009/010의 수정은 MAKI-001/009/010/011과 FUP-001/007/009/010/011/013의 해당 원인을 포함한다. grow는 MAKI-002/003과 FUP-003, 지원 foreground drain은 MAKI-008과 FUP-005의 해당 원인을 포함한다. MAKI-016/017/026 및 FUP-002/006/008/012/015의 이전 수정은 유지하며, 최종 snapshot 실행 여부는 위 절에서 별도로 기록한다.

| 남은 ID | 성격과 현재 제한 | 종료 조건 |
|---|---|---|
| MAKI-005 | 코드 지원 완료, 좁은 실제 topology 검증 완료: mount 전 TYPE/configured FS UUID와 `[lvm_identity]`의 전체 PV/VG/대상-LV UUID exact match를 제공하고, 한 개의 pinned single-PV GCE topology에서 attach/verify/cleanup을 통과했다. unpinned 호환 모드, host udev 및 외부 root 조정은 운영 보장 밖 | 운영 구성에 핀을 필수화하고 지원 토폴로지에서 foreign/unknown 대상 변경 0회, 실패·재시도, udev/root 경합을 포함한 실제 대상 검증 |
| R3-007, MAKI-006/007/040, FUP-004의 복구 범위 | 제품 경로와 실제 installed-graph 결합 검증 완료: `448c0b2`에서 두 자동 SIGKILL cleanup/reattach, open-LV 실패 차단과 Docker ACK 64개 복구를 수행했다. `3cac300` 패키지 캠페인은 two-LV fallback과 same-NBD foreign backend를 mutation 전에 거절하고 proof/record를 보존했다 | nested/internal mapping, partition·holder·udev 경합, hot replacement, 실패 단계별 실제 장치 재시도와 운영 topology를 더 검증 |
| MAKI-015/032 | 부분 수정: 기존 WS 요청·decoded output·수신 frame/JSON 보호에 더해 `52640cc`는 HTTP 소유 요청·응답·decode를 SecretBuffer로 유지하고 전체 할당 용량을 잠근다. gRPC private protobuf item도 decode·오류·취소부터 결과 전달까지 SecretBuffer를 유지한다. 원본 설정 문자열, parser/library-private 복사본 및 전체 resident 비용은 별도 | 소유 버퍼의 집중 수명 회귀는 통과. 라이브러리 복사본까지 완전 소거·잠금이나 보편 RSS 상한으로 확대하지 않으며, 목표 구성의 실제 peak RSS를 검증. [전송 보호 범위](transport-memory.md) 참고 |
| MAKI-020 | v2 코드·집중 회귀·전체 workspace/9 release gates/CI 완료. Firecracker guest hard cut 20회와 전체 GCE instance reset 10회에서 필수 proof와 ACK readback은 보존됨. GCE reset은 workload VM memory/kernel cache를 잃었지만 Persistent Disk 서비스와 물리 저장 경로는 살아 있었음. v1의 이미 모호한 이력은 복원해 증명할 수 없음 | 지원 복합 fault의 운영 대상 qualification, 물리 전원 차단, proof sync 비용 측정, [legacy 데이터 이전](durable-recovery.md) 검증. CRC/동시 유효 rollback 비보장과 일반 정전 COMMIT 유실을 재현한 것이 아니라는 범위를 유지 |
| MAKI-021/041 | `ced2bda`에서 accepted Linux write의 exact journal range와 전체 checkpoint slot을 `posix_fallocate`하고 새 shard allocation/catalog A/B를 append 전에 동기화한다. ENOSPC는 sequence를 소비하지 않고 재시도된다. `5803be8`은 최대 layout을 검사·표시한다. untouched slot의 전체-volume 선점과 filesystem/COW/DB 공간은 별도다 | 실제 fill ratio·filesystem overhead·quota·DB 임시 공간별 배포 용량을 검증하고, 지원 filesystem에서 reservation 의미를 qualification |
| MAKI-025 | `733833c`에서 attach recovery payload를 1 MiB batch로 replay하고 checkpoint 뒤 journal을 회수한다. 4,096 distinct/16,384 overwrite 회귀가 약 1.1 MiB measured peak를 유지했다. [실제 cgroup/RSS 캠페인](recovery-rss-validation-2026-09-19.md)은 OOM tail 네 개를 48/64 MiB에서 복구해 ACK 136개와 zero-invalid deep check를 반복했고 nbdkit `VmHWM`은 최대 11,415,552 bytes였다. 64 MiB 두 번은 max event 없이 cap 아래였고 48 MiB는 cap에 닿았다 | 최대 catalog/fill ratio와 remote provider/cache/multi-volume profile에서 전체 working set의 RSS 여유와 복구 시간을 검증. 관찰한 profile `VmHWM`을 코드상 보편 상한으로 해석하지 않음 |
| MAKI-028 | 부분 수정: 동일한 latest/durable 버전과 내부 checkpoint snapshot은 immutable ciphertext를 공유. 서로 다른 버전·공개 owned snapshot·slot codec·metadata 비용은 남음 | 실제 최대 overlay에서 peak RSS 한도 검증; 두 버전을 합산하는 보수적 논리 budget을 유지하며 전체 메모리 증거로 사용하지 않음 |
| MAKI-029/030 | 코드 개선 완료: `4a3a29a`는 runtime 데이터 경로·복구·checkpoint의 동기 backing I/O를 blocking pool로 옮기고 취소 중 guard 및 shutdown worker 수명을 보존한다. `0e29a24`는 고정 horizon의 slot 쓰기·sync 동안 volume lock을 해제한다 | 지연·취소·동시 신규 shard·실패 재시도 회귀 통과. metadata publication과 v3 punch는 계속 lock을 보유하고 일부 attach canary I/O도 동기 경로다. 목표 부하의 최악 지연과 전체 runtime 여유를 별도 측정 |
| MAKI-013 | 기본 v2/v3의 제한 유지. 새 Linux 볼륨에서 선택하는 [독립 로컬 witness·COW backing](rollback-protection.md)을 구현했다. 현재 witness에 대한 과거 backing 거절, page 인증, cache/overlay freshness, FUA·discard·동시 checkpoint와 용량 소진 후 복구를 로컬 테스트했다 | 새 형식의 독립 persistent-disk 정전·RSS·지연 qualification 및 witness 운영 절차가 남는다. 전체 호스트/witness 동시 rollback, 원격 witness와 분산 fencing, 같은 identity의 restore epoch는 지원하지 않음 |
| MAKI-014 | 구현·로컬 통합 검증 완료: HTTP 외에 WSS/gRPC TLS 및 mTLS, CA/hostname 검증, credential 기반 client key, 실제 daemon attach·쓰기/읽기·종료를 지원. TLS 설정과 평문 URL 조합을 거절 | 로컬 provider 및 daemon 인증서 회귀 통과. 실제 vendor·대상 network·장시간 DB profile의 WSS/gRPC qualification은 별도이며 과거 HTTP VPC 캠페인을 전용하지 않음 |
| MAKI-019 | 범위 한정 통과: `f20bb61` 절차에 이어 `bdb9113`의 [세 호스트 캠페인](credential-rotation-key-migration-validation-2026-09-19.md)이 stopped bearer/mTLS-client 교체, old credential 거절, superblock/canary hash 불변, 두 peer 재검증, 서로 다른 provider key fingerprint와 volume UUID, wrong-key canary 거절, K1→K2 SQLite DB-native restore와 24 ACK restart readback을 통과했다. `da89ae3`의 [네 호스트 캠페인](server-ca-endpoint-rotation-validation-2026-09-19.md)은 stopped server-CA overlap/removal, 두 wrong-trust 거절, 동일 key/profile의 distinct-IP 교체와 48 ACK restart readback도 통과했다 | Commercial vendor와 대상 network에서 client/server credential·CA·endpoint 교체를 반복하고, 공유 client 영향과 cross-sign/revocation 정책, key retirement, 새 volume write 이후 rollback과 production DB cutover를 검증 |
| MAKI-022 | 구현·로컬 검증 완료: `8f7606f`의 `--discard` 새 v3 볼륨만 durable TRIM을 제공. 기본 v2 의미 유지. ext4 실제 blocks 감소, 이웃·재쓰기, A/B sync 실패·restart·fallback, 실제 nbdkit/libnbd 및 전체 workspace 통과. 후속 구현은 replay 종료 뒤 빠진 물리 회수를 최대 4,096개 슬롯 위치씩 checkpoint/worker에서 재시도. `fe259e3`의 별도 v3 GCE 캠페인은 native NBD에서 10회 whole-instance reset, 11개 boot, ACK unit 160개 대조와 final deep check의 invalid slot 0을 통과했고 리소스를 삭제했다 | [공간 회수 제한](space-reclamation.md) 유지: 부분 crypto unit 미회수, 지원 filesystem 필요, punch batch 중 volume lock 유지. 이 GCE 실행은 local provider의 128 MiB 볼륨이며 production DB, 물리 Persistent Disk 전원 차단, 대상 fill-ratio qualification은 별도 |
| MAKI-024 | 검증 범위: 문서 과장은 수정했으나 deep check는 AEAD/논리 읽기/DB 검사가 아님 | 각 검사 범위를 분리하고 암호 검증·복구 후 데이터·DB 의미 검증의 필요한 도구와 실행 증거 확보 |
| MAKI-031/033/034/035 | 성능·확장: 순차 batch, 작은 syscall, 신규 할당 bitmap 전체 쓰기, 상주 bitmap/fallback scan | 고정 용량·fill ratio에서 tail latency·RSS·복구 시간·쓰기 증폭 기준을 충족하거나 해당 병목 수정 |
| MAKI-036 | 선택적 성능 개선: FUA group commit 미구현 자체는 데이터 무결성 결함이 아님 | FUA 의미를 유지한 목표 성능 충족 여부로 구현 필요성을 결정; 미구현을 근거 없이 P0로 올리지 않음 |
| MAKI-038 | 부분 검증: `c385c99`의 loopback 캠페인에 이어 `47058d2`의 [세 호스트 TLS 캠페인](cross-host-tls-provider-validation-2026-09-19.md)이 private VPC에서 TLS 1.2/1.3, mTLS와 bearer, wrong-CA/no-client/wrong-bearer 거절, A/B provider VM 개별 중단과 양쪽 중단의 24→25 stall/resume, 최종 32 ACK 및 restart readback을 통과했다. 후속 client credential 교체와 [server-CA·endpoint IP 교체](server-ca-endpoint-rotation-validation-2026-09-19.md)도 고정 reference-provider profile에서 통과했다 | commercial vendor endpoint와 대상 network의 DNS/proxy/packet-loss/rate-limit 동작, 대상 환경의 credential/certificate rotation 재검증, bounded-error 정책의 DB 오류, 지연 목표, daemon/VM 동시 장애, 장시간 부하를 검증 |
| MAKI-042/043/044 | 배포·장애 도메인: WAL/temp/log/backup 보호 범위, key/provider/Docker 부팅 순환, 공유 장치·provider 장애가 미확정 | 정확한 배포 경로·의존성·물리 topology를 고정하고 독립 장애와 공유 장애를 구분한 시험 |
| MAKI-045/046 | 운영·패키징: `ece7e39`의 fresh-host unchanged-v2 복원에 더해 `3cac300` 캠페인이 한 Debian 12 VM에서 generated package clean install/upgrade와 두 볼륨 재attach를 통과했다. stopped-source SQLite native restore는 corrupt copy를 거절한 뒤 exact retry했고, old-reader legacy-v1 backup은 unchanged v1 metadata의 current-writer 거절 뒤 fresh v2에 exact restore됐다 | signed repository와 downgrade/maintainer rollback, 별도 secret-backup system, live/crash-time capture, 다른 DB와 실제 cutover를 대상 환경에서 검증 |
| MAKI-049/050 | 외부 qualification·지원 범위: 고정 버전·digest의 Firecracker guest hard cut 20회와 전체 GCE instance reset 10회가 외부 ACK/hash 대조를 통과. installed-systemd SQLite crash, fresh-host restore, loopback 및 [cross-host TLS reference provider](cross-host-tls-provider-validation-2026-09-19.md), PostgreSQL 15 process crash, physical reservation, 그리고 [package/topology/migration 캠페인](package-topology-migration-validation-2026-09-19.md)이 각 scoped profile을 통과했다. physical power, production DB profile과 다른 engine, commercial vendor와 대상 network 고유 동작, 더 넓은 migration과 장시간 결과는 미확정 | 버전·digest·내구성 설정·provider·용량·실패 시나리오를 고정한 장시간 실제 DB ACK/hash 대조와 성능·복원 승인 |

MAKI-004의 명령 제한, MAKI-012/018/023/027/037/047, FUP-014의 Linux 경로 원인은 위 수정 기록으로 추적한다. MAKI-039의 storage 대기 제거와 후속 blocking-pool I/O 분리는 검증했지만 별도 프로세스 heartbeat를 구현한 것은 아니다. 지원 기능과 선택적 성능 개선의 보류는 명시적인 지원 범위 결정으로 관리할 수 있으나, 이 문서에서 그 결정을 이미 승인된 것으로 간주하지 않는다.

## 운영 승인 조건

먼저 위 코드·복구 과제를 수정하거나 검증 가능한 지원 범위로 결정해야 한다. 현재 revision은 설치된 controller, actual Maki nbdkit, single-PV/LV kernel NBD/LVM/XFS와 SQLite 외부 ACK를 한 캠페인에 결합해 두 번의 자동 SIGKILL 및 open-LV 실패·재시도를 통과했고, [별도 fresh-host backing restore](fresh-host-restore-validation-2026-09-17.md)는 source VM 삭제 후 새 VM에서 32개 ACK를 복원하고 48개까지 진행한 뒤 restart readback을 통과했다. [별도 remote HTTP provider DB 캠페인](remote-provider-db-validation-2026-09-18.md)은 두 loopback provider의 개별 failover와 양쪽 중단 중 무-ACK stall, 복구 후 정확한 진행 및 restart readback을 통과했다. [별도 cross-host TLS 캠페인](cross-host-tls-provider-validation-2026-09-19.md)은 private VPC에서 TLS 1.2/1.3, mTLS·bearer 거절, 두 provider VM의 개별·전체 중단과 32 ACK restart readback을 통과했다. [별도 PostgreSQL 캠페인](postgresql-crash-validation-2026-09-18.md)은 checksummed cluster의 postmaster SIGKILL/WAL 복구, `pg_amcheck`와 48 ACK를 통과했다. [패키지·토폴로지·마이그레이션 캠페인](package-topology-migration-validation-2026-09-19.md)은 generated package upgrade, two-LV와 foreign-backend fail-closed 경계, stopped-source SQLite native 및 clean legacy-v1→v2 restore를 통과했다. 다음 단계는 nested/internal/partition/holder topology, commercial vendor와 대상 network 고유 장애, signed package repository와 rollback, live·production DB migration, production PostgreSQL과 다른 engine, physical power와 장시간 부하를 검증하는 것이다. Firecracker와 전체 GCE reset 시험은 guest crash 및 workload VM reset 경로의 증거지만 kernel NBD/LVM/XFS/DB 물리 정전 시험의 대체가 아니다. 대상 VM/DB 이미지/용량과 지연·복구 목표는 아직 확정되지 않았다.

초기 검증 프로파일은 고정 Linux 도구 버전, 단일 인증 provider, 단일 disposable volume/DB부터 시작할 수 있다. 한 VM의 두 loopback provider를 통한 실제 볼륨별 실패 전환과 total-outage stall/resume 통과는 목표 운영 topology 승인을 뜻하지 않는다. [검사와 qualification 절차](testing.md), [저장소 복구 제한](storage-recovery.md), 로컬 리뷰의 `05-release-plan.md` 승인 계획을 함께 적용한다. 외부에서 복원할 수 없는 유일한 원본 저장소로의 운영은 승인하지 않는다.

### 2026-09-20 구현 후 운영 판단

코드 차원의 다음 작업은 반영했다: checkpoint의 긴 data-I/O 구간 잠금 축소,
blocking I/O와 worker 종료 수명 분리, opt-in v3 durable discard/물리 회수,
HTTP/gRPC 소유 평문 buffer 보호 확대, WSS/gRPC TLS와 설정·daemon 연결.
롤백 방지는 독립 witness와 인증된 세대의 설계를 제안했으며 아직 구현하지 않았다.

최종 고정 source snapshot과 전용 Cargo target에서 workspace 1,051개 통과,
실패 0개, ignored 10개를 확인했다. `cargo fmt --all --check`와 workspace
all-targets strict Clippy도 통과했다. 근거는
`~/logs/maki-tls-final-20260920T090302Z/test.log` 및 `exit.status` 0이다.
앞선 공유 target 실행은 다른 source snapshot의 artifact가 섞여 실패했으므로
통과 증거로 사용하지 않는다. Windows 경로 fixture 수정 `d050610`의
[Linux·Windows CI](https://github.com/seo-rii/maki/actions/runs/35500946666)는
성공했으며, 이 CI는 후속 TLS 구현 이전 revision에 대한 결과다.

현재 근거는 격리된 시험 환경이나 제한된 pilot을 준비하는 데 사용할 수 있지만,
모든 운영 profile의 승인을 뜻하지 않는다. Commercial provider·실제 network,
production DB의 용량/지연 목표, library-private 메모리 복사본, 넓은 장치 topology,
물리 전원 장애와 장시간 workload는 위 표의 남은 경계로 유지한다. 새 v3 discard와
WSS/gRPC를 기존 v2/HTTP 외부 캠페인이 이미 검증했다고 해석하지 않는다.
모든 리뷰 항목이 종료되지 않았으므로 원본 R3 리뷰 폴더도 보존한다.

### 2026-09-20 후속 재시도 및 의존성 검증

`267cb3e`는 전체 replay가 끝난 뒤 남은 v3 discard 공간을 checkpoint당 최대
4,096개 슬롯 위치씩 재시도한다. 새 journal 기록이 없어도 background worker가
진행하며, 새 overlay 예약은 건너뛰고 실패한 punch/sync는 같은 위치에서 재시도한다.
실제 파일의 재시작 후 회수 회귀와 기존 회수 회귀가 모두 통과했다.

TLS 커밋 뒤 CI `35501638723`은 유지보수가 중단된 `rustls-pemfile`에 대한
RUSTSEC-2025-0134 경고로 실패했다. `6c5f2dc`는 tonic 0.13과
`rustls::pki_types::PemObject`로 이 의존성을 제거했고, 경고 제외 없이 엄격한
감사를 통과했다. `9631acc`는 백그라운드 반복 시험에 v3 discard의 crash/model/
reclaim 회귀를 추가하고 각 실행의 Cargo target을 분리했다.

통합 고정 snapshot은 workspace 1,057 passed / 0 failed / 10 ignored,
Python 장애 검증 61 passed, Debian 패키징 3 passed를 기록했다.
`cargo audit --deny warnings`, fmt, workspace all-target strict Clippy도 통과했다.
로그는 `~/logs/maki-followup-final-20260920T094155Z/test.log`, 종료 코드는 0이다.
이 통합 snapshot 실행은 별도 GCP v3 결과를 포함하지 않는다. 이후 `f5bde3e`
고정 source의 extended background storage 실행은 100/100 rounds, 8개 suite의
800회 실행과 4,800 passed, supervisor exit 0으로 2026-09-20 17:04:40 UTC에
끝났다. 별도 `fe259e3` GCE v3 native-NBD 캠페인은 10회 instance reset과 11개
boot에서 ACK unit 160개를 대조하고 proof/checkpoint sequence 190, 8 shards,
15 allocated / 0 invalid slots의 offline deep check를 통과했다. instance/disk
정리 배열과 이후 exact-name 재조회도 비어 있었다. 두 실행은 production 승인,
real DB 검증 또는 물리 Persistent Disk 전원 손실 증거가 아니다.

후속 CI `f71ce01`의 Windows 실패는 non-Unix에서 page lock 성공을 전제한
gRPC 보호 회귀의 platform 기대값 문제로 확인했으며, 이 문서 시점에는 수정 CI
재실행이 완료되지 않았다. 따라서 위 campaign 결과를 최신 Linux·Windows CI
성공 주장으로 확대하지 않는다.
`6b86bef`는 성공한 잠금 또는 실패 횟수 증가를 검사하도록 테스트를 수정했다.
잠금 한도 0으로 기존 실패를 재현한 뒤 전체 gRPC 37개와 같은 제한의 재검사
1개, strict Clippy 및 fmt를 통과했다. 근거는
`~/logs/maki-grpc-lock-green-20260920T215727Z/` (`exit.status` 0)이다.
