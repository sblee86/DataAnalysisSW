# LANscope · v0.3

Windows WPF LAN 기록 작업 공간. 로그인 → ICD/IP 프로파일 → NIC 매칭 → 시험별 PCAP 기록 흐름을 제공합니다.

- [웹 UI 미리보기](https://sblee86.github.io/DataAnalysisSW/)
- [전체 소스 + 오프라인 NuGet 패키지 ZIP](https://github.com/sblee86/DataAnalysisSW/archive/refs/heads/main.zip)
- [Windows x64 실행 파일 ZIP](https://github.com/sblee86/DataAnalysisSW/raw/refs/heads/main/downloads/LANscope-win-x64.zip)
- [Pages 설정](https://github.com/sblee86/DataAnalysisSW/settings/pages): Deploy from a branch → `main` → `/docs` → Save. 실제 공개 사이트의 활성화는 클라우드에서 확인하지 못했습니다.

## Windows 실행 및 역할

실행 ZIP을 해제하고 `LanScope.exe` 실행. 단일 EXE에 .NET, 계정 바이너리, 샘플 CSV ICD를 포함합니다. 별도 .NET 설치 없이 실행할 수 있습니다. 실제 NIC 검색/수집에는 **Npcap**이 필요합니다. Npcap 설치 옵션에 따라 관리자 권한으로 실행해야 할 수 있습니다. Npcap 설치 프로그램은 포함하지 않습니다.

임시 계정은 `admin`과 `guest`이며 초기 암호는 전달 메시지에서 제공합니다.

| 기능 | admin | guest |
|---|---|---|
| NIC → 프로파일 현황/통계 | 가능 | 가능 |
| 시험 기록 시작·중지 | 가능 | 가능 |
| ICD/IP 프로파일 생성·편집·삭제 | 가능 | 불가 |
| NIC 재검색·매칭 변경 | 가능 | 불가 |
| 기록 폴더 변경 | 가능 | 불가 |

기록 중에는 설정을 변경할 수 없습니다. 로그아웃/종료 시 진행 중인 기록 중지 여부를 확인합니다. 잘못된 로그인은 오류를 표시하고, 5회 실패 시 해당 프로세스에서 30초 대기합니다. 웹 시안은 브라우저 메모리에서 동작하며 실제 인증 서버나 NIC 수집 기능을 제공하지 않습니다.

## 첫 기록

1. admin으로 로그인합니다. 최초 설정에는 샘플 프로파일 3개가 준비됩니다. NIC 매칭은 자동으로 만들지 않습니다.
2. **기록 프로파일**에서 이름, ICD 파일, 송신 IP와 수신 IP를 입력합니다. IP는 쉼표/공백/줄바꿈으로 여러 개 지정할 수 있습니다. IPv4/IPv6 개별 주소를 지원하며 CIDR·호스트명은 지원하지 않습니다.
3. **역방향 응답도 기록**을 선택하면 송신→수신과 수신→송신을 모두 기록합니다. 해제하면 송신→수신만 기록합니다.
4. **기록 설정**에서 검색된 NIC을 선택하고 프로파일을 최소 1개 선택한 뒤 **선택 NIC 매칭 저장**을 누릅니다. 한 NIC에 여러 프로파일을 매칭할 수 있습니다. OS NIC 전체와 추가 Npcap 장치를 표시하며 캡처 불가/연결 해제 NIC은 구분합니다. 현재 캡처할 수 없는 장치가 저장된 매칭에 있으면 기록을 시작하지 않습니다.
5. 기록 폴더를 직접 입력하거나 찾아보기로 선택하고 **경로 저장**합니다.
6. **기록 대시보드**에서 시험 이름을 입력하고 **기록 시작**합니다. guest도 저장된 설정으로 시작·중지할 수 있습니다.
7. 중지하면 파일을 닫고 Npcap 통계를 표시합니다. 시작 실패·디스크 오류·장치 중지 등은 오류로 표시합니다. 일부 장치 시작에 실패하면 이미 열린 장치도 중지합니다. 실패한 시험 폴더는 진단/부분 데이터 보존을 위해 유지합니다.

시험마다 `<기록폴더>/<시각>_<시험이름>_<고유ID>/` 아래에 다음을 생성합니다.

- `nic01_<profileId>.pcap` 등: NIC→프로파일 조합당 한 파일. NIC 링크 타입과 패킷 타임스탬프를 보존합니다. 캡처 snaplen은 65,535 bytes입니다. 파일은 매초 flush하고 중지 시 닫습니다. 비정상 전원 종료 시 완전한 마지막 프레임까지 보장하지는 않습니다.
- `session.bin`: 시험 이름, 계정 ID, 시작 UTC, NIC/프로파일/IP/ICD 원본을 담은 버전 표시 바이너리 메타데이터. 암호나 계정 해시는 포함하지 않습니다.

통계는 각 매칭별 패킷 수, 바이트 합계, 최소/최대/평균 프레임 크기와 최근 수신 시각을 표시합니다. PCAP 파일 헤더 크기는 바이트 합계에 포함하지 않습니다. 같은 패킷이 여러 프로파일에 매칭되면 각 파일/통계에 중복 기록됩니다. ARP 등 IP 주소가 없는 프레임은 IP 프로파일에 매칭하지 않습니다. 고속 트래픽의 손실 없는 기록은 보장하지 않으며 Npcap 드롭 통계와 실제 부하 테스트로 확인해야 합니다. 표의 크기는 현재 버퍼의 프레임 바이트 수입니다.

## CSV ICD / 비트 필드

ICD 입력은 **IDLStudio에서 출력한 CSV 기반**으로 전환합니다. 통신 데이터는 **빅엔디언 고정**이며 1바이트는 변환하지 않습니다. 실제 CSV 예시가 아직 없어 현재 열 규격은 임시 어댑터입니다. 실제 IDLStudio 호환성은 예시를 받은 뒤 확인합니다.

`samples/Telemetry.csv`, `ControlCommand.csv`, `StatusReport.csv`로 구조/비트 필드/교차 바이트/부호/실수/배율을 확인할 수 있습니다. 프로파일 화면에 CSV 필드 표와 메시지별 **Payload HEX 해석**을 제공합니다. raw payload 기준 0 시작 byte offset, 비트 길이 1~64, msb0/lsb0 번호 지정과 signed 부호 확장을 지원합니다. uint64 raw 값도 정밀도를 보존합니다.

[CSV 열·비트 위치 규격과 예시](docs/CSV-ICD.md)를 확인하세요. 기존 IDL 설정은 삭제하지 않지만 CSV로 다시 선택해 저장해야 기록을 시작할 수 있습니다. 기존 프로파일 ID/NIC 매칭은 유지됩니다. 기존 `.idl` 샘플은 구버전 참고용이며 신규 입력은 `.csv`만 받습니다.

현재 실시간 수집 매칭은 여전히 송수신 IP 기준입니다. CSV 파싱과 수동 HEX 해석은 지원하지만 **실시간 메시지 자동 판별/IDLStudio wire 형식/CDR/TCP 재조립은 지원하지 않습니다.**

## 설정과 계정 보관

- 계정: `Resources/accounts.bin`을 .NET 내장 리소스로 포함해 단일 EXE에 묶습니다. 각 암호는 임의 salt와 PBKDF2-HMAC-SHA256 600,000회 해시로 저장하며 평문 암호는 리소스에 없습니다.
- 계정 변경: `python scripts/set-accounts.py`에서 암호를 숨김 입력하고 WPF를 다시 빌드합니다. 계정 생성 UI는 없습니다. 웹 미리보기 로그인은 검토용 임시 계정을 별도로 유지합니다.
- 변경 가능한 설정: `%LOCALAPPDATA%\LANscope\workspace.bin`. Windows DPAPI(CurrentUser)로 암호화한 바이너리에 Hidden 속성을 설정합니다. NIC/프로파일/ICD 원본/기록 폴더를 함께 저장합니다. 임시 파일을 통한 원자적 교체를 사용합니다. 손상/다른 Windows 사용자로 인한 복호화 실패 시 로그인 화면에 오류를 표시하고 원본을 자동 덮어쓰지 않습니다.
- 변경 가능한 설정을 EXE 내부에 다시 쓰지는 않습니다. 동일한 Windows 사용자에서 실행한 admin/guest 앱 계정이 설정을 공유합니다. 다른 Windows 사용자/다른 PC로 설정을 복사하면 DPAPI 복호화가 되지 않을 수 있습니다.
- 숨김 속성·내장 리소스는 역공학 방지나 강한 보안 경계가 아닙니다. PC 소유자에게서 앱을 보호하는 방식이나 원격 인증을 대신하지 않습니다. 임시 계정은 실사용 전 변경하세요.

## 오프라인 직접 빌드

전체 저장소 ZIP에는 `nuget-offline/`의 원본 .nupkg와 SHA-256 manifest, 잠금 파일이 포함됩니다. `NuGet.Config`는 로컬 피드만 사용합니다. `downloads/LANscope-source.zip`은 GitHub 단일 파일 크기 제한 때문에 패키지를 제외한 코드 전용 ZIP입니다. 오프라인 빌드는 반드시 **전체 저장소 ZIP**을 받으세요.

1. Windows x64 **.NET SDK 10.0.403**을 설치합니다. SDK 자체와 Npcap은 별도 설치 대상입니다.
2. PowerShell로 저장소 루트에서 실행합니다.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-offline.ps1
```

결과는 `artifacts\windows-x64\LanScope.exe`. 실행 정책 설정은 해당 명령 호출에만 적용됩니다. 다른 SDK 패치는 다른 런타임 팩을 요구할 수 있으므로 고정 SDK를 사용하세요.

Linux에서는 Windows 타깃으로 cross-build가 가능하지만 WPF/DPAPI/Npcap의 Windows 동작을 실행 검증할 수는 없습니다.

```sh
dotnet restore src/LanScope/LanScope.csproj -r win-x64 --locked-mode
dotnet publish src/LanScope/LanScope.csproj -c Release -r win-x64 --self-contained true --no-restore -o artifacts/windows-x64
```

## 검증과 알려진 한계

Linux에서 암호 해시 인증, admin/guest 권한, IPv4/IPv6 양방향 매칭, 필수 NIC 매칭 검증, 크기 통계, 운영 코드가 작성한 PCAP을 libpcap으로 재읽기 등을 확인합니다. CSV 파싱과 빅엔디언·비트 필드·64 bit 정밀도·인코딩·오류 처리 검사도 포함합니다. `tests/LanScope.Checks`는 테스트 암호를 `LANSCOPE_TEST_ADMIN` / `LANSCOPE_TEST_GUEST` 환경 변수로 받아 출력하지 않습니다. Windows에서 실행하면 추가로 DPAPI round-trip/Hidden 속성/암호화/설정 재저장을 확인합니다. Linux에서는 이 네 검사를 명시적으로 건너뜁니다.

브라우저 시안에서는 로그인 오류와 역할별 메뉴, 프로파일·ICD 선택, NIC 복수 매칭, guest 시작·중지, 통계 시뮬레이션을 검증합니다. 사이트는 `design/ui-preview.html`과 동일한 `docs/index.html`을 사용합니다.

Windows에서 반드시 확인할 항목: 로그인과 DPI별 WPF 렌더링, Npcap 설치 옵션 및 권한, 실제 NIC 검색/연결 해제, 송수신 PCAP 정확성, 복수 NIC 수집, 고속 트래픽 드롭, 디스크 오류, 강제 종료 후 파일 복구. 코드에 구현된 기능과 Windows 실기 검증 완료는 구분해야 합니다.
