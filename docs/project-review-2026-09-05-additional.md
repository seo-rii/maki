# Maki 추가 코드 검토 — 2026-09-05

검토 기준은 `1411ed540fd323a38acb41aefebe9f844b493e6c`이다. 이전 수정과
중복되지 않는 결함 **8개**를 확인했다. 재현 검사에서 기대한 안전 동작이
실패한 사례는 **13개**, 정상 대조군은 **2개**다. 아래 항목은 모두 미수정이다.

이번 산출물은 검토 기록과 재현 테스트다. 제품 구현 변경, 커밋, 푸시는
수행하지 않았다. 실제 장치나 서비스를 조작하지 않고 메모리 저장소,
임시 파일, 모의 mountinfo/sysfs, loopback 서버를 사용했다.

## 우선순위

| 우선순위 | 이슈 | 확인한 영향 |
|---|---|---|
| P1 | BUG-022 | checkpoint 상태 sync 실패 후 재시작·journal 회수·새 FUA·정전이 이어지면 복구 거부 |
| P1 | BUG-019 | attach가 다른 디스크의 XFS를 Maki 파일시스템으로 초기화하고 승인할 수 있음 |
| P1 | BUG-018 | grow가 신뢰 기록과 대상 확인 없이 LVM/XFS 변경 명령 실행 |
| P1 | BUG-017 | gRPC 본문/트레일러 정지 시 RPC timeout과 해당 요청의 failover가 진행되지 않음 |
| P2 | BUG-016 | 이름에 `zram`이 들어간 일반 디스크 swapfile이 보안 검사를 통과 |
| P2 | BUG-023 | backing 내부 symlink를 따라 다른 볼륨을 모사한 외부 파일에 기록 |
| P2 | BUG-015 | shutdown 성공 뒤 기존 제어 연결과 볼륨 잠금이 남음 |
| P2 | BUG-024 | 유효한 HTTP JSON pointer escape가 잘못된 요청 필드로 전송됨 |

## BUG-022 — checkpoint 상태의 내구성보다 journal 회수가 앞섬

근거: [recovery.rs:127](../crates/maki-core/src/recovery.rs#L127),
[volume.rs:247](../crates/maki-core/src/volume.rs#L247).

checkpoint 1 성공 → checkpoint 2의 상태 파일 sync 실패 → 프로세스 재시작
→ idle checkpoint 성공으로 journal 회수 → FUA 3 성공 → 전원 손실 순서에서
복구가 `base sequence 3 does not bridge from checkpoint 1`로 거부됐다.
재시작은 실패한 상태 기록을 page cache에서 읽을 수 있지만, recovery는
선택한 상태의 내구성을 확정하지 않고 journal 삭제의 근거로 사용한다.

기존 BUG-001은 A/B 갱신 재시도, BUG-021은 journal image의 writeback을
다뤘다. 이번 실패는 checkpoint 상태를 소비하는 복구·회수 경계다.
수정 시 journal을 회수하기 전에 선택한 checkpoint 상태의 내구성을
확정하고, 재시작 후 다시 발생하는 전원 손실까지 검사해야 한다.

재현: [core/review_next_storage.rs](../crates/maki-core/tests/review_next_storage.rs).

## BUG-019 — attach가 마운트된 LV와 NBD의 연결 관계를 확인하지 않음

근거: [exec.rs:241](../crates/maki-privileged/src/exec.rs#L241),
[plan.rs:279](../crates/maki-privileged/src/plan.rs#L279).

설정된 VG/LV가 NBD가 아닌 다른 디스크의 XFS로 연결된 상태에서,
`fs_uuid=None`과 `init_sentinel=true`를 사용하면 그 파일시스템에 sentinel을
쓰고 attach가 성공했다. verifier는 XFS·sentinel·NBD 연결 여부를 각각
확인하지만, 해당 마운트가 기록된 NBD를 사용하는지는 확인하지 않는다.
이 상태를 허용하면 의존 애플리케이션이 Maki의 암호화 경로 밖에서 동작할
수 있다. 실제 애플리케이션 데이터 유출을 실행한 것은 아니다.

같은 sysfs fixture는 기존 detach topology 검사에서 거부됐다. 따라서
BUG-003/010의 검증을 attach에도 적용하고, 최초 sentinel 작성 전부터
마운트 대상과 NBD 의존성을 확인해야 한다.

재현: [exec_tests.rs](../crates/maki-privileged/src/exec_tests.rs),
`review_next_attach_rejects_a_logical_volume_backed_by_an_unrelated_disk`.
장치 명령은 모의 실행하며 실제 sentinel I/O·parser·verifier를 사용한다.

## BUG-018 — grow가 attachment 검증과 동시 실행 잠금을 건너뜀

근거: [exec.rs:445](../crates/maki-privileged/src/exec.rs#L445),
[exec.rs:479](../crates/maki-privileged/src/exec.rs#L479),
[plan.rs:333](../crates/maki-privileged/src/plan.rs#L333).

grow plan은 `attachment=None`이며, executor는 NBD connect/disconnect가
있는 plan에만 잠금과 신뢰 기록 검사를 적용한다. 기록이 전혀 없는 경우와
기록의 backend·VG/LV·mountpoint가 모두 다른 경우에 `lvextend`,
`xfs_growfs`가 실행되고 성공으로 반환됐다. 실제 명령은 fixture다.

현재 attachment와 다른 LVM/XFS를 영구적으로 확장할 수 있으며 detach와도
직렬화되지 않는다. grow 역시 같은 신뢰 기록·대상 관찰·잠금을 사용하고
명령 전에 불일치를 거부해야 한다.

재현: [exec_tests.rs](../crates/maki-privileged/src/exec_tests.rs)의
`review_next_grow_requires_trusted_attachment_before_commands`,
`review_next_grow_rejects_reused_backend_and_changed_targets`.

## BUG-017 — gRPC timeout이 전체 응답 완료를 제한하지 않음

근거: [grpc/lib.rs:125](../crates/maki-crypto-grpc/src/lib.rs#L125),
[grpc/lib.rs:190](../crates/maki-crypto-grpc/src/lib.rs#L190).

transport timeout은 Channel에 설정되지만 전체 `unary` 완료에는 별도
제한이 없다. 실제 loopback 서버가 헤더 뒤 메시지를 멈추거나 메시지 뒤
트레일러를 멈추면, 250ms 설정에도 2초 동안 요청이 pending이었다.
완전한 응답을 보내는 대조군은 통과했다.

`stall` 정책은 외부 작업 deadline이 없으므로 이 RPC가 해당 슬롯을
차지하며 그 요청의 재시도·failover를 막는다. BUG-013의 `bounded-error`
외부 deadline은 별도로 유효하다. 수정은 transport의 전체 응답 수신과
준비 대기를 한 RPC 제한 시간 안에 포함해야 한다.

재현: [grpc/review_next_transport.rs](../crates/maki-crypto-grpc/tests/review_next_transport.rs).

## BUG-016 — swap 보안 판단이 장치 대신 이름을 신뢰함

근거: [security.rs:72](../crates/maki-nbdkit/src/security.rs#L72).

`/var/swap/zram-backup.swap`이라는 일반 디스크 swapfile을 포함한
`/proc/swaps` fixture에서, 암호화 확인 함수가 false를 반환해도 위험
목록이 비어 있었다. `name.contains("zram")`이면 검사를 건너뛰기 때문이다.
`require_secure_swap_policy=true`가 해당 swap을 거부하지 못한다.
실제 swap을 켜거나 평문을 디스크에 유출시키지는 않았다.

커널의 zram은 `/dev/zram<id>` 형태의 장치이며 sysfs 정보를 제공한다.
이름의 부분 문자열로 일반 파일까지 분류해서는 안 된다.
[커널 zram 문서](https://docs.kernel.org/admin-guide/blockdev/zram.html).
추가 코드 관찰로 [security.rs:161](../crates/maki-nbdkit/src/security.rs#L161)은
`/proc/swaps` 읽기 실패도 빈 목록으로 바꾼다. 이 I/O 실패 경로는 별도
프로세스 오류 주입으로 검증하지 않았다. 수정 시 관찰 실패도 안전한
상태로 간주하지 않아야 한다.

재현: [review_next_swap.rs](../crates/maki-nbdkit/tests/review_next_swap.rs).

## BUG-023 — backing 경로의 symlink가 볼륨 외부 쓰기로 연결됨

근거: [file.rs:24](../crates/maki-backing/src/file.rs#L24),
[file.rs:125](../crates/maki-backing/src/file.rs#L125).

경로 검사는 `../`와 절대 경로 같은 문자열만 거부한다. shard 파일 또는
상위 `data` 디렉터리가 symlink일 때 `open`이 이를 따라가며, write/sync로
다른 볼륨을 모사한 외부 임시 파일을 실제 변경했다. 필요한 조건은 backing
내부 symlink와 대상 파일에 대한 프로세스의 쓰기 권한이다. 권한 상승이
입증된 것은 아니며, 문서화된 backing root 격리를 위반하는 문제다.

최종 파일뿐 아니라 각 부모 구성요소까지 descriptor 기준으로 검증해야
한다. 기존 경로 escape 테스트는 문자열 경로만 다뤘다.

재현: [backing/review_next_storage.rs](../crates/maki-backing/tests/review_next_storage.rs).

## BUG-015 — shutdown 후에도 제어 세션이 Engine을 보유함

근거: [adapter.rs:267](../crates/maki-nbdkit/src/adapter.rs#L267),
[uds.rs:161](../crates/maki-control/src/uds.rs#L161).

제어 연결에서 status 응답을 받은 뒤 `shutdown()`을 호출했다. 성공으로
반환됐지만 같은 연결의 다음 status도 `ready`로 응답했고, 볼륨 잠금은
`VOLUME_ALREADY_ATTACHED`로 유지됐다. listener task를 중단해도 별도로
spawn한 세션은 중단되지 않으며 backend의 Engine 참조가 남는다.

프로세스 또는 runtime 자체를 끝내면 자원이 회수되지만, 성공한 shutdown이
즉시 잠금을 해제한다는 adapter 계약과는 다르다. 모든 세션의 종료를 추적하고
기다린 뒤 Engine의 마지막 참조를 해제해야 한다.

재현: [review_next_control.rs](../crates/maki-nbdkit/tests/review_next_control.rs).

## BUG-024 — HTTP 요청 JSON pointer escape 누락

근거: [http/lib.rs:236](../crates/maki-crypto-http/src/lib.rs#L236),
[http/lib.rs:240](../crates/maki-crypto-http/src/lib.rs#L240).

`/key~1slot` 매핑이 `key/slot` 대신 `key~1slot`이라는 필드로 실제 서버에
전송됐다. `~0`와 batch의 `items_path`·`item_fields`도 같은 문제다.
일반 중첩 포인터 `/key/slot`은 정상 동작했다. slash/tilde를 포함하는
벤더 필드 이름을 설정하면 요청이 벤더 계약과 달라진다.

응답은 `Value::pointer`를 사용하므로 요청과 응답 규칙도 일치하지 않는다.
토큰마다 `~1`, `~0` 순서로 escape를 해제하는 JSON Pointer 규칙을 적용하고
`~01` 같은 조합도 검증해야 한다.
[RFC 6901 §4](https://www.rfc-editor.org/rfc/rfc6901.html#section-4).

재현: [http/review_next_transport.rs](../crates/maki-crypto-http/tests/review_next_transport.rs).

## 재현 실행과 로그

아래 명령은 repository root에서 실행한다. 결함이 남아 있는 현재 상태의
기대 결과는 모두 **exit 101**이다. 정상 대조군 두 개는 같은 실행에서 통과한다.
로그 경로는 `/home/seorii/logs/` 기준이며 아래 표에 PID를 기록했다. 최종
결과와 원래 실행 명령은 각 `.exit.json`에 보존했다. 로그 권한은 0600이다.

| 이슈 | 명령 | PID | 로그 |
|---|---|---:|---|
| BUG-022 | `cargo test -p maki-core --locked --test review_next_storage -- --ignored` | 3024422 | `maki-fix-audit-next-storage-checkpoint-ignored-red-20260905T132743.826382Z.log` |
| BUG-018/019 | `cargo test -p maki-privileged --locked --lib review_next_ -- --ignored --nocapture` | 3023425 | `maki-fix-audit-next-ops-confirmed-20260905T132739.777121Z.log` |
| BUG-017 | `cargo test -p maki-crypto-grpc --locked --test review_next_transport -- --ignored` | 3022604 | `maki-fix-audit-next-crypto-red-20260905T132734.946001Z.log` |
| BUG-016 | `cargo test -p maki-nbdkit --locked --test review_next_swap -- --ignored` | 3031721 | `maki-fix-audit-next-swap-red-20260905T132834.694085Z.log` |
| BUG-023 | `cargo test -p maki-backing --locked --test review_next_storage -- --ignored` | 3038727 | `maki-fix-audit-next-storage-symlink-red-20260905T132948.064034Z.log` |
| BUG-015 | `cargo test -p maki-nbdkit --locked --test review_next_control -- --ignored` | 3012421 | `maki-fix-audit-next-control-swap-red-20260905T132549.112050Z.log` |
| BUG-024 | `cargo test -p maki-crypto-http --locked --test review_next_transport -- --ignored` | 3034639 | `maki-fix-audit-next-http-pointer-red-20260905T132918.181444Z.log` |

표의 명령은 이슈별 최소 재현 명령이다. BUG-015/017의 원래 기록 명령은
다음 test target도 지정했지만 첫 실패에서 종료했으므로, 다음 target은
별도 로그로 실행했다. 정확한 원래 argv는 `.exit.json`에 있다.

새 테스트 15개는 모두 `#[ignore]`로 명시 실행하게 했다. 일반 기본 테스트에
의도한 실패를 추가하지 않으며, 수정 작업에서는 각 실패를 먼저 확인하고
구현 후 통과로 바꿀 수 있다. 전체 `-- --ignored` 실행에는 이 감사 재현도
포함되므로, 현재 checkout에서 기존 release gate와 구분해야 한다.

## 감사 산출물 검증

- 재현 실행: 실패 13개, 정상 대조군 통과 2개. 위 실행들은 의도한 assertion
  실패로 exit 101이다. 컴파일 실패를 결함 재현으로 세지 않았다.
- 새 테스트의 기본 실행: 전부 ignored 처리되어 exit 0이다. 변경한
  `maki-privileged` 기본 unit test도 50개 통과, 새 재현 3개 ignored였다.
- `cargo fmt --all --check`, `git diff --check`: exit 0.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: PID
  `3135638`, exit 0. 로그:
  `/home/seorii/logs/maki-fix-audit-next-clippy-final-20260905T142359.842212Z.log`.
  첫 Clippy 실행에서 발견한 테스트용 UUID 숫자 표기 경고는 값 변경 없이
  정리했다.

제품 구현을 수정하지 않은 감사이므로 전체 기존 release gate를 다시
실행하지 않았다. 현재 HEAD는 `1411ed5`이고 재현 및 보고서는 미커밋 상태다.
