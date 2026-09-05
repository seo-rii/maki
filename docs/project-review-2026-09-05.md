# Maki 프로젝트 평가 — 2026-09-05

이 문서는 수정 전 `8b06c53`에 대한 평가 기록이다. 이후 BUG-001부터
BUG-009까지와 TEST-001을 TDD로 수정했다. 변경 내용, 검증 결과와 운영 경로
전환 절차는 [수정 기록](review-remediation.md#follow-up-review-2026-09-05)과
[업그레이드 절차](operations.md#upgrading-the-runtime-layout)에 있다.

검토 대상은 `main`의 `8b06c53`이다. 시작 시 작업 트리는 깨끗했다. 구현과 기존 수정 기록을 대조하고 Linux에서 기본 검사와 별도 재현을 실행했다. 운영 코드, 기존 테스트, 서비스, 장치, 인프라는 변경하지 않았다.

Maki는 불변식, crate 경계, 장애 시뮬레이션과 회귀 테스트가 잘 갖춰진 개발 단계의 저장소다. 그러나 이번에 확인한 메타데이터 재시도, 장애 복구, 배포 경계의 문제를 고려하면 중요한 실제 데이터를 맡길 단계로 평가하기는 어렵다. 아래에는 기존 보고서의 해결된 항목을 반복하지 않고, 현재 코드에 남아 있는 별도 실패 경로를 기록했다.

| 평가 영역 | 판단 |
|---|---|
| 구조 | format, backing, crypto, engine, privileged helper의 책임 분리가 명확하다. |
| 검증 기반 | CrashableBacking, ManualClock, failpoint, 모델 기반 검사와 회귀 테스트가 강점이다. |
| 저장 정확성 | 정상 경로뿐 아니라 실패한 동기화 이후의 재시도까지 검증해야 한다. BUG-001에서 A/B 사본 두 개의 무효화를 재현했다. |
| 장애 복구·자원 제한 | 요청 자체의 timeout과 그 요청이 사용한 자원의 종료가 분리되어 있다. BUG-004/005는 장기 장애에서 가용성을 해친다. |
| 운영·권한 분리 | Rust 내부의 검증을 서비스 시작 조건, 디렉터리 소유권, 그룹 접근권한까지 연결해야 한다. |
| 출시 준비 | 현재 문서처럼 production-qualified로 표시하지 않는 것이 적절하다. 하드웨어 전원 차단, 실제 DB 장애 캠페인, 장기 부하 검증도 남아 있다. |

P1은 실제 데이터 또는 제한적 운영에 앞서 수정할 문제, P2는 후속 수정이 필요한 문제로 사용했다. 재현 프로그램의 exit 0은 **결함이 존재한다는 assertion이 통과했다**는 뜻이다.

## 새로 확인한 이슈

### BUG-001 — P1: 실패한 A/B 동기화 뒤 재시도가 마지막 durable 사본을 덮어쓴다

- 근거: `crates/maki-format/src/ab.rs:149–159`, `crates/maki-core/src/store.rs:390–395`.
- A/B의 다음 기록 대상을 디스크에서 읽히는 generation으로 선택한다. 그러나 `sync_data`가 실패해도 새 사본은 페이지 캐시에서 CRC와 decode를 통과할 수 있다.
- A=1, B=2가 durable인 상태에서 A=3의 동기화가 실패하면, 재시도는 B를 stale로 판단해 B=4로 덮어쓴다. 두 번째 기록도 아직 durable하지 않은 시점에 crash가 발생하면 두 사본 모두 torn write의 대상이 된다.
- 기존 `CrashableBacking::with_tearing(512)`와 16,384-unit `AllocationMap`으로 재현했다. 두 차례 sync 실패 후 seed 540에서 `AbStore::load::<AllocationMap>() == None`이다. 같은 현상은 superblock 타입으로도 재현된다. 정상 체크포인트 경로에서도 allocation store를 재시도하므로 일반적인 메타데이터 갱신에 적용된다.
- 영향: allocation A/B가 모두 무효인 cataloged shard는 다음 attach에서 거부된다. 이 재현은 메타데이터 보호 사본의 소실을 입증하며, 실제 디스크의 사용자 데이터 소실을 입증한 것은 아니다.
- 수정 방향: 마지막으로 durable하다고 확인된 사본을 보존하는 실패·재시도 규칙을 정의해야 한다. 상대 사본을 교체하기 전에 선택한 기준 사본의 내구성을 확립하거나, 실패한 대상에 재시도를 고정하는 방법을 검토한다. A/B를 사용하는 모든 메타데이터와 프로세스 재시작까지 함께 검증해야 한다.
- 필요한 회귀 검사: allocation 저장 sync 실패 → 재시도 중 crash → 최소 한 사본 유지 및 볼륨 재복구.

### BUG-002 — P1: attach 설정이 없을 때 암호화 마운트 없이 종속 서비스가 시작될 수 있다

- 근거: `packaging/systemd/maki-attach@.service:16`, `docs/operations.md:197–201`.
- attach unit은 설정이 없으면 `ConditionPathExists`로 건너뛴다. 문서가 제시하는 workload의 `Requires=`와 `After=` 조합은 이 condition 실패를 시작 실패로 전파하지 않는다. [systemd 공식 문서](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.unit.xml)의 `Requires=` 및 assertion 설명으로 확인했다.
- 영향: 설정이 없거나 잘못 배치되었고 마운트 지점의 일반 디렉터리가 쓰기 가능하면, DB 등이 암호화 마운트의 identity 검사를 거치지 않고 평문 파일을 쓸 수 있다.
- 수정 방향: 필수 설정의 부재가 시작 작업 실패가 되도록 `AssertPathExists` 또는 실패하는 사전 검사를 사용한다. workload와 실제 mount의 생명주기 의존성도 검토한다.
- 필요한 회귀 검사: 격리된 systemd 환경에서 설정 누락 시 workload의 `ExecStart`가 실행되지 않음을 검사한다. 이번 검토에서는 실제 서비스를 시작하거나 변경하지 않았다.

### BUG-003 — P1: root helper 상태의 상위 디렉터리를 비특권 계정이 소유한다

- 근거: `packaging/tmpfiles.d/maki.conf:2`, `crates/maki-privileged/src/exec.rs:68–77,371–376`, `crates/maki-privileged/src/plan.rs:280–287`.
- `/run/maki`는 `maki:maki`, 0750이다. root helper의 attach lock과 device record가 그 아래에 있고, 경로 기반 파일 열기·쓰기와 문자열 읽기를 사용한다. device record는 형식만 검사하고 소유권이나 대상 볼륨의 실체를 확인하지 않는다.
- 영향: 상위 디렉터리를 변경할 수 있는 `maki` 프로세스가 있으면 privileged 상태 경로와 disconnect 대상의 무결성을 보장할 수 없다. 잘못된 경로에 root가 기록하거나 다른 NBD 장치를 대상으로 삼을 위험이 있다.
- 전제: 해당 프로세스가 패키지의 `ProtectSystem=strict` namespace 밖에 있거나, sandbox 없이 직접 실행되는 환경이다. 패키지 daemon의 읽기 전용 namespace가 그대로 유지되는 경우의 직접 변경까지 재현한 것은 아니다.
- 수정 방향: helper 전용 상태를 모든 상위 경로까지 root가 통제하는 디렉터리로 분리한다. 열기 시 경로·소유권을 검증하고 device record를 실제 연결 identity와 대조한다. daemon/control socket의 접근권한과 함께 설계하되 운영 중 장치에는 적용하지 않았다.

### BUG-004 — P1: HalfOpen probe의 timeout·요청 오류가 회로 차단기를 영구 정지시킨다

- 근거: `crates/maki-crypto/src/endpoint.rs:474,517–547`.
- `breaker.allow()`가 HalfOpen probe 슬롯을 소비한 뒤 operation deadline 또는 `NonRetryableRequest`로 종료하면 성공·실패 완료 처리가 없어 슬롯이 돌아오지 않는다. 전송 inflight guard가 반환하는 슬롯과는 별개다.
- `half_open_max_requests=1`에서 장애 → HalfOpen probe의 deadline 또는 요청 오류 → 정상 요청을 재현했다. ManualClock을 하루 진행해도 `HalfOpen`, `inflight=0`, `provider_calls=2`에 머물며 정상 요청은 `attempts exhausted`로 실패한다. 슬롯이 여러 개면 같은 종료가 슬롯 수만큼 발생할 때 소진된다.
- 영향: 서버가 복구되어도 단일 endpoint 볼륨이 I/O를 재개하지 못한다. 기본 stall 정책에서는 계속 대기할 수 있다.
- 수정 방향: probe 수명에 대한 guard로 정상 종료, 오류, deadline, future 취소, 예산 부족 경로에서 슬롯 반환을 보장한다. 반환과 endpoint 실패 집계는 별도로 처리해야 한다.

### BUG-005 — P1: WebSocket timeout 뒤 이전 연결과 reader task가 남는다

- 근거: `crates/maki-crypto-websocket/src/lib.rs:154–171,289–293`.
- `retire()`는 sender만 제거한다. `tokio::spawn`으로 분리된 reader는 split socket을 계속 소유하고, 서버가 응답도 종료도 하지 않으면 `source.next()`에서 남아 있다. task를 종료할 handle이 connection에 없다.
- loopback 서버와 네 번 timeout을 재현했다. 서버 관측값은 `accepted=4, closed=0`이었고 provider를 drop한 뒤에도 `closed=0`이었다.
- 영향: 재연결할 때마다 socket과 task가 누적되어 장기 장애에서 자원 제한을 깨뜨린다.
- 수정 방향: connection generation이 reader/writer task와 socket 종료를 함께 소유해야 한다. timeout, 교체, provider drop 이후 이전 세대의 task와 파일 디스크립터가 남지 않는 검사가 필요하다.

### BUG-006 — P2: SecretBuffer 하나를 해제하면 살아 있는 다른 buffer의 잠금도 풀린다

- 근거: `crates/maki-crypto/src/secret.rs:36–50,73–83,138–148`.
- 일반 `Vec` 두 개는 같은 메모리 페이지를 공유할 수 있다. `mlock`/`munlock`은 페이지 단위이며 중복 잠금 횟수가 누적되지 않는다. [Linux mlock 공식 매뉴얼](https://man7.org/linux/man-pages/man2/mlock.2.html).
- 같은 페이지에 위치한 64-byte SecretBuffer 두 개 중 하나를 drop하자, 살아 있는 buffer의 `is_page_locked()`는 true인데 `VmLck`는 12 KiB에서 8 KiB로 줄었다.
- 영향: `secure-buffers`가 주장하는 buffer 수명 동안의 메모리 잠금이 유지되지 않는다. 실제 swap 기록은 검사하지 않았으며 비밀의 swap 노출 가능성은 호스트 swap 정책에 달려 있다.
- 수정 방향: 전용 페이지 할당 또는 페이지별 잠금 참조 관리가 필요하다. 할당, duplicate, into_vec, drop과 zeroization 순서를 함께 검증한다.

### BUG-007 — P2: 같은 이름의 credential이 서로 다른 source를 덮어쓴다

- 근거: `crates/maki-nbdkit/src/daemon.rs:137–145,149–159`, `crates/maki-format/src/config.rs:697–708`.
- `RoutedKeySource`가 `(source, name)` 대신 name만 키로 저장한다. encrypt header가 `{source="credential", name="dup"}`, decrypt header가 `{source="env", name="dup"}`이면 뒤에 수집한 env가 두 항목 모두에 적용된다.
- `CREDENTIALS_DIRECTORY`를 제거하고 합성 env 값만 둔 별도 프로세스에서 설정 검증과 provider 생성이 성공했다. 두 항목을 모두 credential source로 바꾼 대조군은 provider 생성을 거부했다. 외부 endpoint 접속 없이 재현했다.
- 영향: 선언한 credential source를 엄격하게 따른다는 O-06의 보장이 source 충돌에서 깨진다. 의도와 다른 자격 증명을 전송하거나, 필수 systemd credential 없이 provider를 구성할 수 있다.
- 수정 방향: 각 CredentialRef의 source를 직접 전달해 해석하거나 source+name으로 구분한다. name-only API를 유지하면 충돌을 검증 단계에서 거부해야 한다.

### BUG-008 — P2: HTTP 전송 오류 문자열에 query 인증정보가 포함된다

- 근거: `crates/maki-crypto-http/src/lib.rs:247–261`, `crates/maki-crypto/src/endpoint.rs:364`, `crates/maki-nbdkit/src/daemon.rs:446`.
- reqwest 전송 오류를 그대로 문자열로 옮기면서 query가 포함된 URL도 CryptoError에 들어간다. 이 오류는 quarantine 등의 warning 경로에서 출력된다. C-11의 spec Debug redaction은 이 경로에 적용되지 않는다.
- 합성 query token과 loopback connection-refused로 오류에 token이 포함되는 것을 확인했다. 실제 credential은 사용하지 않았다.
- 영향: query에 인증정보를 사용하는 설정에서는 전송 장애가 로그의 비밀 노출로 이어진다.
- 수정 방향: 오류를 문자열로 변환하기 전에 URL을 제거하거나 정제한다. 요청 URL과 credential을 포함하지 않는 오류·로그 assertion이 필요하다.

### BUG-009 — P2: maki-admin 사용자에게 control socket까지의 디렉터리 탐색 권한이 없다

- 근거: `packaging/tmpfiles.d/maki.conf:2`, `packaging/systemd/maki@.service:13–14,42–43`, `crates/maki-control/src/uds.rs:103`.
- socket을 maki-admin 그룹의 0660으로 설정해도 `/run/maki`와 volume runtime directory는 maki:maki의 0750이다.
- 영향: maki-admin에만 속하고 별도 ACL이 없는 관리자는 상위 디렉터리를 탐색하지 못해 status/checkpoint/reload에 EACCES를 받는다. 구성과 POSIX 접근 규칙을 대조한 결과이며 실제 사용자·그룹을 만들지는 않았다.
- 수정 방향: control 경로의 디렉터리 탐색 권한을 제공한다. 이를 위해 NBD socket까지 불필요하게 개방하지 않도록 control 경로를 별도로 구성하는 방법을 검토한다.

## 수정 전 검사 결과

| 검사 | 결과 | exit |
|---|---|---:|
| `cargo fmt --all --check` | 실패: `crates/maki-nbdkit/tests/review_control.rs:80`의 format! 서식 | 1 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 통과 | 0 |
| `cargo test --workspace --locked` | 399 passed, 0 failed, 7 ignored | 0 |

서식 실패는 **TEST-001 / P2**로 기록한다. 현재 환경의 Cargo는 1.94.0이다. 평가 요청이므로 서식을 자동 수정하지 않았다.

기본 검사 프로세스 PID는 773689였고 최종 aggregate exit는 1이다. 로그는 `/home/seorii/logs/maki-review-checks-20260905T094606.927674Z.log`, 개별 검사 종료 상태는 같은 stem의 `.exit.json`에 있다. 로그 디렉터리와 로그는 각각 0700, 0600으로 생성했으며 프로세스 종료 후 제한된 출력만 확인했다.

별도 재현은 모두 현재 workspace의 compiled library를 사용했고, 아래 최종 실행은 모두 exit 0이다. 소스는 `/tmp`의 임시 검증 자료이므로 시스템 청소 시 사라질 수 있다.

| 이슈 | 재현 소스 | 최종 결과 기록 |
|---|---|---|
| BUG-001 | `/tmp/maki-review-storage-vu75ekaw/allocation_probe.rs` | `/home/seorii/logs/maki-review-allocation-20260905T100219.740673Z.log` |
| BUG-004 | `/tmp/maki-crypto-audit-p0tbiuny/breaker_probe.rs` | 같은 디렉터리의 `breaker_probe.out`, `probe-status.json` |
| BUG-005 | `/tmp/maki-crypto-audit-p0tbiuny/ws_probe.rs` | 같은 디렉터리의 `ws_probe.out`, `probe-status.json` |
| BUG-006 | `/tmp/maki-crypto-audit-p0tbiuny/secret_page_probe.rs` | 같은 디렉터리의 `secret_page_probe.out`, `probe-status.json` |
| BUG-007 | `/tmp/maki-review-config-6upzcsza/main.rs` | `/home/seorii/logs/maki-review-config-20260905T095149.682075Z.log` |
| BUG-008 | `/tmp/maki-crypto-audit-p0tbiuny/http_error_probe.rs` | 같은 디렉터리의 `http_error_probe.out`, `probe-status.json` |

## 이미 알려진 제한 및 이번 검토의 범위

아래는 새로 발견한 이슈 수에 포함하지 않았다.

- `nbd.maximum_io`를 실제 plugin에서 광고·강제하지 않는 O-03. 현재 `docs/review-remediation.md:189–198`에 미해결로 기록되어 있다. journal headroom을 실제 NBD 요청 크기와 맞춰야 한다.
- scheduler의 deadline이 queue 진입 시점부터 계산되지 않는 제한과 마지막 engine handle 해제 후 checkpoint worker가 일시적으로 lock을 유지하는 K-10.
- 실제 plugin의 FUA가 native가 아닌 emulation 값인 점은 기존 Linux 검증 문서에 기록되어 있다.
- WebSocket/gRPC TLS 미지원, 실제 DB 강제 종료·하드웨어 전원 차단·72시간 부하 검증 미완료.

이번에는 ignored release gate, 실제 kernel NBD 연결, systemd 설치, DB 및 하드웨어 전원 차단 캠페인을 실행하지 않았다. 기본 테스트 통과가 이 검증들을 대신하지 않는다. 부분 쓰기 후 짧은 journal record 재시도와 RMW 메모리 예산 계산은 검토 후보였지만, 이번 보고서에서는 재현과 범위 확정이 끝난 이슈만 확정 목록에 포함했다.

검토 당시 권장 작업 순서는 BUG-001/002/003의 내구성과 운영 경계, BUG-004/005의 장애 복구, 나머지 P2 및 기존 O-03, 이후 실제 운영 검증이었다. 이 문서의 신규 이슈는 각각 실패하는 회귀 검사로 시작해 수정했으며, 기존 제한과 외부 운영 검증은 별도 범위로 남는다.
