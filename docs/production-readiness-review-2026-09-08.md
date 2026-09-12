# 운영 준비 검토 및 R3 수정 기록 — 2026-09-08

최초 검토 기준은 `9911cf7`, 가장 최근에 완료한 전체 workspace/9 release gates/CI 기준선은 `fb3da46`이다(2026-09-12). 2026-09-11에 원격 `732ff74`까지의 10개 변경을 합친 뒤 같은 `main`에서 TDD 수정과 단위별 커밋을 이어갔다. 이 기준선은 v2 proof, 복구/검사 메모리, 전송 소유 버퍼, mount 전 검사와 fresh-space admission 변경을 포함한다. 후속 카운터 경계 수정의 검증은 별도로 기록한다. 아래에서 수정별 검증 범위와 과거 snapshot을 구분한다.

**운영 승인은 보류한다.** 외부 시험 대상만 부족한 상태가 아니다. 자동 복구의 중간 상태, 전송 라이브러리의 평문 복사본, 물리 공간 admission과 고유 단위·metadata의 전체 메모리에 코드 과제가 남아 있다. MAKI-020의 필수 proof 정책과 새 포맷은 전체 workspace·릴리스 검사와 Linux/Windows CI를 통과했으며 운영 대상 검증은 남는다. 기존 v1 볼륨은 현재 writable recovery가 거절하므로 교체 전에 [호환성과 데이터 이전 절차](durable-recovery.md)를 읽어야 한다. 로컬에 제공된 `maki-review-r3-2026-09-08/` 원본은 모든 항목의 해결과 검증이 끝날 때까지 보존한다.

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
| R3-007 명시적 복구 수명주기 | 부분 수정·상위 과제 미완료 | `b06d0f9` 최초 sentinel 이전 실패 정리, `597eb3c` 기록된 kernel identity로 recover, `b3c5103` 매 workload 시작 전 read-only verify. VG 활성화와 proof 게시 사이 crash 및 workload 재바인딩 통합은 남음 |
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
- `fce9066` (MAKI-018): dm-crypt 또는 zram writeback 하부에 NBD가 있거나, cycle·판독 오류·알 수 없는 virtual leaf가 있으면 secure swap으로 인정하지 않는다. device-mapper/MD/partition을 거쳐 실제 장치까지 확인하는 fixture 회귀이며, 실제 swap을 변경한 시험은 아니다.
- `f64f3d8` (MAKI-037): `nbd.threads`를 `1..=256`에서 검증하고 runtime의 숨은 clamp를 제거했다. [설정 계약](configuration.md#nbd-request-limits)은 Tokio worker, native nbdkit callback pool, request admission을 구분한다. 성능 보장은 별도다.
- `df886a3` (FUP-014): Linux backing이 root와 부모 디렉터리 descriptor를 고정하여 open·rename·remove·list·sync·lock을 수행한다. root 교체·symlink 거절·상위 디렉터리 권한 회귀를 추가했다. Linux 밖의 개발용 경로에 같은 보장을 확대해 주장하지 않는다.
- `be3b362` (MAKI-039): status/metrics가 storage lock과 free-space 조회를 기다리지 않는다. [관측 상태와 제한](observability.md)에 cached snapshot의 나이, busy 상태, unavailable cache/space 값과 외부 deadline을 명시했다. runtime 전체 정지나 thread starvation은 해결하지 않았다.
- `f20bb61` (MAKI-019 일부): [자격 증명 교체와 키 이전 절차](key-rotation.md)를 추가했다. 같은 키를 유지하는 credential 교체와 새 볼륨으로의 DB-native 복원을 구분하며, 실제 운영 전환 검증은 남는다.
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

## 남은 리뷰 항목과 종료 조건

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
활성화 전 LVM 신원 및 activation→proof crash 공백은 남는다.

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

MAKI-021의 stale free-space admission을 별도로 수정했다. 시계를 전진하지
않고 여유 공간을 high→low, low→high, unknown→known-low로 바꾸는 RED 3개가
실패했다(PID 583843, exit 101;
`/home/seorii/logs/maki-r3-fresh-space-red-20260912T100807.570132Z.log`). 쓰기
판단에만 새 조회를 강제하며 통계 cache와 unknown/EIO의 기존 계약은 유지한다.
관련 6개 및 core 전체 182 passed, 6 ignored, exit 0(PID 593921;
`/home/seorii/logs/maki-r3-fresh-space-all-core-20260912T100939.097861Z.log`),
strict Clippy exit 0(PID 593322;
`/home/seorii/logs/maki-r3-fresh-space-clippy-20260912T100931.425712Z.log`)이다.
조회 이후 외부 공간 소비와 journal/slot/metadata/checkpoint 완주 공간의
실물 예약은 이 수정으로 보장되지 않는다.

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
확인했다. 실제 kernel/DB 시험, 활성화 전 LVM 신원 검증과 activation→proof
crash 공백은 해결하지 않았다. `fs_uuid` 생략은 기존대로 허용하며 TYPE만 검사한다.

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
공개 all-record API와 실제 attach의 고유 단위·overlay/metadata 메모리는 남는다.

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
| MAKI-005 | 부분 수정: mount 전 TYPE/configured UUID 및 probe 전후 mapping/backend 검증 완료. PV/VG/LV의 독립 신원 검증은 VG 활성화 전에 끝나지 않음 | 활성화 전 신원 검증과 foreign/unknown 대상 변경 0회를 보여 주는 실패·재시도 회귀 |
| R3-007, MAKI-006/007/040, FUP-004의 복구 범위 | 부분 수정: 명령 deadline, 기록 기반 recover 및 workload 시작 전 반복 가능한 read-only verify 제공. activation→proof 게시 crash 공백, 실제 workload READY와 다른 namespace·재시작 경로의 통합은 남음 | 모든 attach/cleanup 중간 상태의 안전한 재시도, 올바른 mount에서만 DB 시작, container 재생성/재바인딩을 포함한 실제 대상 시험 |
| MAKI-015/032 | 부분 수정: WS 요청·decoded output·소유 수신 frame/JSON 문자열·키와 gRPC private item 보호 완료. 공유 원본·serde scratch·tungstenite/tonic 등 별도 할당의 수명·잠금과 전체 resident 비용은 남음 | 남은 소유/라이브러리 버퍼의 성공·오류·취소 수명과 실제 peak resident 상한을 검증. [전송 보호 범위](transport-memory.md)를 전체 메모리 소거·잠금으로 확대하지 않음 |
| MAKI-020 | v2 코드·집중 회귀·전체 workspace/9 release gates/CI 완료, 운영 검증 대기: 필수 mirrored proof가 확정 이력의 경계를 요구하며 증거 부족 시 거절. v1의 이미 모호한 이력은 복원해 증명할 수 없음 | 지원 복합 fault의 운영 대상 qualification, proof sync 비용 측정, [legacy 데이터 이전](durable-recovery.md) 검증. CRC/동시 유효 rollback 비보장과 일반 정전 COMMIT 유실을 재현한 것이 아니라는 범위를 유지 |
| MAKI-021/041 | 부분 수정: 매 쓰기의 fresh free-space threshold 검증 완료. 진행 중 journal·새 slot·checkpoint 완주 공간의 실물 예약은 아님 | 동시 요청까지 포함한 공간 admission/예약과 경계 ENOSPC 회귀, geometry·fill ratio·DB 임시 공간별 물리 용량 계산 |
| MAKI-025 | 부분 수정: segment streaming, Volume attach의 단위별 최신 replay 보유, deep checker의 검증 후 payload 폐기로 반복 이력에 따른 payload/pending 증가를 제거. 고유 단위, 서로 다른 latest/durable 버전, segment/bitmap metadata 및 공개 전체 기록 API의 메모리는 남음 | 전체 working set의 메모리 상한을 검증하고 고유 단위가 많은 journal도 안전하게 복구. [측정 범위](durable-recovery.md#cost-and-verification-limits)의 heap 결과를 전체 RSS 상한으로 해석하지 않음 |
| MAKI-028 | 부분 수정: 동일한 latest/durable 버전과 내부 checkpoint snapshot은 immutable ciphertext를 공유. 서로 다른 버전·공개 owned snapshot·slot codec·metadata 비용은 남음 | 실제 최대 overlay에서 peak RSS 한도 검증; 두 버전을 합산하는 보수적 논리 budget을 유지하며 전체 메모리 증거로 사용하지 않음 |
| MAKI-029/030 | 구조·성능: checkpoint의 exclusive lock과 async worker 위 동기 backing I/O가 남음 | 목표 부하의 최악 I/O 정지·runtime 여유를 검증하고 기준 미달 시 작업 격리/잠금 범위 수정. MAKI-039의 snapshot이 이를 해결한 것은 아님 |
| MAKI-013 | 위협 모델: AEAD는 같은 unit의 과거 유효 ciphertext나 전체 snapshot rollback을 막지 않음 | replay를 지원 위협 모델에서 제외하는 결정과 제한을 명시하거나 세대 인증·독립 anchor를 구현하고 공격 회귀 실행 |
| MAKI-014 | 지원 기능: WSS/gRPC TLS를 명시 거절하며 HTTP TLS를 지원 | TLS가 필요한 지원 프로파일을 HTTP로 제한하거나 해당 transport TLS와 인증서 실패 회귀를 구현. 평문으로 조용히 연결하는 결함으로 표현하지 않음 |
| MAKI-019 | 운영 경로: credential/endpoint 교체와 새 볼륨 key migration 절차는 `f20bb61`에 문서화했으나 실제 전환 검증 미완료 | 교체 전후 실제 volume UUID/key 검증, 실패 시 재시도·되돌리기, 새 volume으로 key migration하는 실행 절차 |
| MAKI-022 | 지원 기능·용량: TRIM/deallocation 미구현으로 삭제가 backing 회수를 보장하지 않음 | 회수 없는 용량 모델을 명시한 제한 프로파일 승인 또는 durable deallocation과 crash 회귀 구현 |
| MAKI-024 | 검증 범위: 문서 과장은 수정했으나 deep check는 AEAD/논리 읽기/DB 검사가 아님 | 각 검사 범위를 분리하고 암호 검증·복구 후 데이터·DB 의미 검증의 필요한 도구와 실행 증거 확보 |
| MAKI-031/033/034/035 | 성능·확장: 순차 batch, 작은 syscall, 신규 할당 bitmap 전체 쓰기, 상주 bitmap/fallback scan | 고정 용량·fill ratio에서 tail latency·RSS·복구 시간·쓰기 증폭 기준을 충족하거나 해당 병목 수정 |
| MAKI-036 | 선택적 성능 개선: FUA group commit 미구현 자체는 데이터 무결성 결함이 아님 | FUA 의미를 유지한 목표 성능 충족 여부로 구현 필요성을 결정; 미구현을 근거 없이 P0로 올리지 않음 |
| MAKI-038 | 전체 I/O 계약: provider stall/error가 NBD/XFS/DB에 미치는 지연·오류·복구 미검증 | 지원 timeout/error 설정에서 외부 DB ACK와 복구 데이터를 대조하고 최악 지연 목표 확인 |
| MAKI-042/043/044 | 배포·장애 도메인: WAL/temp/log/backup 보호 범위, key/provider/Docker 부팅 순환, 공유 장치·provider 장애가 미확정 | 정확한 배포 경로·의존성·물리 topology를 고정하고 독립 장애와 공유 장애를 구분한 시험 |
| MAKI-045/046 | 운영·패키징: 현재 버전의 새 호스트 설치/업그레이드 및 key/format을 포함한 전체 복원 증거 부족 | clean-host 권한·도구 버전 확인, DB-native backup과 별도 key/설정에서 복원 후 외부 데이터 대조 |
| MAKI-049/050 | 외부 qualification·지원 범위: 현재 revision의 실제 DB·정전·장시간 결과와 DB별 ACK/이미지/topology가 미확정 | 버전·digest·내구성 설정·provider·용량·실패 시나리오를 고정한 외부 ACK/hash 대조와 성능·복원 승인 |

MAKI-004의 명령 제한, MAKI-012/018/023/027/037/047, FUP-014의 Linux 경로 원인은 위 수정 기록으로 추적한다. MAKI-039의 storage 대기 제거는 검증했지만 별도 프로세스 heartbeat나 runtime 격리를 구현한 것은 아니다. 지원 기능과 선택적 성능 개선의 보류는 명시적인 지원 범위 결정으로 관리할 수 있으나, 이 문서에서 그 결정을 이미 승인된 것으로 간주하지 않는다.

## 운영 승인 조건

먼저 위 코드·복구 과제를 수정하거나 검증 가능한 지원 범위로 결정해야 한다. 그다음 현재 revision의 실제 kernel NBD/LVM/XFS 및 서비스 재시작 검증, DB 외부 ACK 대조, 새 호스트 백업 복원, 정전과 장시간 부하 시험이 필요하다. rootless nbdkit 시험은 실제 native plugin 경로의 증거지만 kernel NBD/LVM/XFS/DB 정전 시험의 대체가 아니다. 과거 Debian smoke 역시 현재 helper 변경을 인증하지 않는다. 대상 VM/DB 이미지/용량과 지연·복구 목표는 아직 확정되지 않았다.

초기 검증 프로파일은 고정 Linux 도구 버전, 단일 인증 provider, 단일 disposable volume/DB부터 시작할 수 있다. 다중 원격 서버의 실제 볼륨별 검증과 실패 전환 회귀는 수정했지만 목표 운영 topology 승인을 뜻하지 않는다. [검사와 qualification 절차](testing.md), [저장소 복구 제한](storage-recovery.md), 로컬 리뷰의 `05-release-plan.md` 승인 계획을 함께 적용한다. 외부에서 복원할 수 없는 유일한 원본 저장소로의 운영은 승인하지 않는다.
