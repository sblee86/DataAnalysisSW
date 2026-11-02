# IDLStudio CSV adapter · provisional v1

실제 IDLStudio CSV 예시는 추후 제공 예정입니다. 아래는 현재 검증 가능한 임시 입력 규격입니다. 실제 출력 헤더/비트 배치 규칙을 확인한 뒤 어댑터를 맞춥니다. IDLStudio와의 형식 호환성이 확인된 상태는 아닙니다.

**모든 통신 데이터는 빅엔디언입니다. 1바이트 값은 순서를 바꾸지 않습니다.** `endian`을 생략하면 `be`, `le`를 명시하면 오류입니다. 바이트 순서와 비트 번호 방향은 별개입니다.

## CSV 열

| 열 | 필수 | 의미 / 기본값 |
|---|---|---|
| `message` | 아니오 | 메시지 이름, 생략 시 `Default` |
| `name` | 예 | 메시지 안에서 유일한 필드명 |
| `byte_offset` | 예 | UDP/TCP 헤더를 제외한 payload 시작에서 0 기준 바이트 위치 |
| `bit_offset` | 아니오 | 첫 바이트 안의 0~7 위치, 기본 0 |
| `bit_length` | 예 | 필드 비트 길이. 정수/bitfield는 1~64 |
| `type` | 예 | `uint`, `int`, `bitfield`(uint와 동일), `bool`, `float32`, `float64`, `bytes` |
| `endian` | 아니오 | `be`만 지원. `big`, `bigendian`, `network`도 같은 의미 |
| `bit_order` | 아니오 | `msb0`(기본) 또는 `lsb0`. bit_offset의 번호 방향 |
| `scale` | 아니오 | 배율, 기본 1 |
| `bias` | 아니오 | 보정값, 기본 0. 해석값 = raw × scale + bias |
| `unit` | 아니오 | 단위 문자열 |
| `description` | 아니오 | 설명. 따옴표 안의 쉼표·개행·이스케이프 따옴표 지원 |

한국어 `필드명`, `바이트오프셋`, `비트수`, `자료형` 등과 `FieldName`, `ByteOffset`, `BitLength`, `DataType` 등의 명시적 별칭을 지원합니다. 알 수 없는 열은 미사용 열로 알립니다. 단위 추정/헤더 모호한 자동 추정은 하지 않습니다. type/오프셋을 누락하거나 지원하지 않는 타입은 오류로 표시합니다.

UTF-8(BOM 선택), BOM이 있는 UTF-16 LE/BE, CP949 입력을 지원합니다. 기본 구분자는 쉼표이며 세미콜론/탭도 헤더에서 감지합니다. 최대 파일 16 MB, 10,000 필드, 256 메시지, payload 범위 65,535 bytes입니다.

## 비트 필드 의미

- `msb0`: 한 바이트에서 0번은 최상위 비트(0x80), 7번은 최하위 비트(0x01).
- `lsb0`: 0번은 최하위 비트(0x01), 7번은 최상위 비트(0x80).
- `bit_offset`부터 번호가 증가하는 방향으로 해당 바이트의 슬라이스를 선택합니다. 다음 바이트로 넘어가면 그 바이트의 번호 0부터 선택합니다. 각 바이트에서 선택한 슬라이스의 수치 자체는 반전하지 않습니다. 먼저 읽은 슬라이스를 상위 쪽에 배치해 빅엔디언으로 연결합니다.
- 따라서 `AB CD`, byte_offset=0, bit_offset=4, bit_length=8이면 `msb0`은 `BC`(188), `lsb0`은 `AD`(173)입니다. 이 교차 바이트 규칙은 실제 IDLStudio 출력과 대조해야 합니다.
- 같은 메시지의 물리적 비트가 겹치면 오류입니다. 다른 메시지는 같은 payload 위치를 독립적으로 정의할 수 있습니다. Union/중첩 별칭 필드는 아직 지원하지 않습니다.
- signed 정수는 지정한 비트 길이의 2의 보수로 부호 확장합니다. uint64의 raw 값은 문자열로 표시해 정밀도를 보존합니다.
- bool은 1 bit, float32/64는 바이트 정렬된 IEEE754 32/64 bits여야 합니다. bytes는 바이트 정렬·8배수 길이이며 원본 순서를 그대로 HEX 표시합니다. bool/bytes의 scale=1, bias=0만 허용합니다.

## 확인 예시

`samples/Telemetry.csv`와 payload `00 01 B2 FF 9C 41 48 00 00`:

| 필드 | 해석 |
|---|---|
| sequence | 1 |
| mode | 5 (상위 3 bits) |
| enabled | true |
| status | 2 (하위 4 bits) |
| temperature | raw -100 → -10.0 degC |
| voltage | 12.5 V |

`samples/ControlCommand.csv`는 9 bit 교차 바이트 필드를, `samples/StatusReport.csv`는 lsb0 번호와 bytes 필드를 보여줍니다. 모두 임의 샘플이며 IDLStudio 실제 출력 파일이 아닙니다.

## 적용 범위

프로파일에서 CSV 필드 표와 **Payload HEX 해석 미리보기**를 제공합니다. 메시지를 선택해 payload만 붙여 넣으세요. 길이 부족/NaN/범위 초과는 필드별 오류로 표시하며 0으로 숨기지 않습니다. 현재 PCAP 기록은 선택 NIC 전체 프레임이며, 송수신 IP는 분류 통계와 CSV 변환 대상 선택에 사용합니다. 완전한 UDP 데이터그램의 PCAP→CSV 변환을 제공하지만 실시간 메시지 자동 식별/포트 매칭/TCP 재조립/CDR 정렬 해석은 하지 않습니다. CSV의 오프셋은 실제 wire payload 위치를 나타내야 하며 IDL 타입의 CDR 배치를 자동 추정하지 않습니다.

v0.2에서 저장한 IDL 원본은 설정에 그대로 보존합니다. admin으로 해당 프로파일을 선택하고 CSV를 다시 가져와 저장하면 기존 프로파일 ID와 NIC 매칭을 유지합니다. CSV를 적용하지 않은 기존 IDL 프로파일도 전체 PCAP 기록은 가능하며 CSV 값 변환에는 정상 CSV 정의가 필요합니다.
