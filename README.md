# DRAS (Data Recording & analysis software)

Windows WPF / C# 12 / **.NET 9**, SDK **9.0.200** 기반 LAN 패킷 기록·ICD 분석 프로그램입니다.

- [Windows 실행 ZIP](https://github.com/sblee86/DataAnalysisSW/raw/refs/heads/main/downloads/DRAS-win-x64.zip)
- [전체 저장소 ZIP — 오프라인 NuGet 및 런타임 설치 파일 포함](https://github.com/sblee86/DataAnalysisSW/archive/refs/heads/main.zip)
- [웹 UI 미리보기](https://sblee86.github.io/DataAnalysisSW/) — **admin / admin**
- [Windows Desktop Runtime 9.0.2 x64 설치 파일](https://github.com/sblee86/DataAnalysisSW/raw/refs/heads/main/installers/dotnet/windowsdesktop-runtime-9.0.2-win-x64.exe)

## 실행과 직접 빌드

**SDK 9.0.200을 이미 설치했다면 SDK를 추가 설치하지 않아도 됩니다.** `global.json`이 해당 버전을 선택합니다. Visual Studio 2022 **17.12 이상**과 .NET 데스크톱 개발 워크로드를 사용하고 `DRAS.sln`을 여세요. `dotnet --version` 결과는 저장소 폴더에서 9.0.200이어야 합니다.

```powershell
dotnet --version
dotnet build DRAS.sln
powershell -ExecutionPolicy Bypass -File scripts/build-offline.ps1
```

빌드 스크립트는 포함된 NuGet 7개의 SHA-256을 확인하고 로컬 피드로 복원한 뒤 `artifacts/windows-x64-net9`에 게시합니다. SDK는 NuGet 패키지가 아니며 설치 파일을 중복해서 넣지 않았습니다. 프로젝트/검증은 `net9.0-windows` / `net9.0`, C# 12입니다. SDK 9.0.200과 함께 나온 런타임 버전은 **9.0.2**입니다.

배포는 **런타임 별도형**으로 가볍게 변경했습니다. 실행 ZIP을 풀고 **모든 파일을 같은 폴더에 유지**한 상태로 `DRAS.exe`를 실행하세요. EXE만 따로 복사하지 마세요. PC에 Windows Desktop Runtime 9.0.2 이상 9.x가 없으면 포함된 설치 EXE를 먼저 실행합니다. SDK가 있어도 Desktop Runtime 설치 여부는 별도로 확인할 수 있습니다.

```powershell
dotnet --list-runtimes
# Microsoft.WindowsDesktop.App 9.0.2 또는 더 높은 9.0.x가 있어야 합니다.
```

전체 저장소의 `installers/dotnet`에는 공식 Microsoft **Desktop Runtime 9.0.2 x64** 설치 EXE 하나만 있습니다. 공개 릴리스 메타데이터의 SHA-512와 대조했으며 URL·해시는 `origin.json`, `SHA512SUMS.txt`에 있습니다. 이전 .NET 8 설치 파일, 불필요한 런타임 내장 NuGet 팩과 큰 런타임 포함 배포본은 제거했습니다. **Npcap**은 실제 NIC 캡처를 위해 PC에 별도 설치해야 합니다. SDK/런타임/Npcap은 서로 다릅니다.

## 기록 대시보드

- admin/guest 모두 **IP → 공통헤더 ID → Length → 정확한 ICD 크기** 검사를 통과한 인터페이스 패킷만 PCAP에 저장합니다. 비IP/미매칭/오류/모호한 패킷은 제외합니다.
- 시험마다 새 폴더, NIC→인터페이스별 PCAP을 만듭니다. 헤더 규칙이 없으면 시작하지 않으며 전체 저장으로 복귀하지 않습니다.
- **기록 폴더 변경**은 대시보드에서 바로 폴더를 선택해 저장합니다. 관리자만 변경하며 기록 중에는 막습니다. 다음 시험부터 적용하고 기존 PCAP을 이동하지 않습니다.
- 기록명은 넓고 높은 독립 입력란입니다. 오른쪽 아래 손잡이를 끌어 너비·높이를 조절하거나 설정에서 지정할 수 있습니다. 기록 중 이름 변경은 막습니다.

## 설정 — 글자 크기 / 배치·입력란 / 계정·보안

우측 상단 **설정**은 별도 탭으로 나뉩니다. 본문·메뉴·표 내용·표 제목·화면 제목과 **시험 기록명 글자 크기**를 독립 조절합니다. 목록 폭, NIC 비율, 기록명 입력란 너비/높이도 저장합니다. WPF 설정 창은 크기 조절이 가능하고 웹도 같은 탭 구성을 제공합니다. 버튼에 마우스를 올리면 작업 목적·권한·영향을 설명하는 도움말을 표시합니다.

화면 환경은 `%LOCALAPPDATA%\DRAS\ui-preferences.bin` 숨김 바이너리에 따로 저장하며 기존 글자 설정도 읽습니다. guest도 자기 화면을 조절할 수 있습니다.

**관리자 비밀번호 변경**은 admin 로그인 후 계정·보안 탭에서 현재 비밀번호, 새 비밀번호(8~128자), 확인을 입력합니다. 기존 ICD·서명 키를 교체하지 않고 새 비밀번호로 기존 키를 여는 암호화 봉투를 저장하므로 이전 암호화 ICD를 계속 읽을 수 있습니다. 새 로그인부터 이전 비밀번호는 거절합니다. 변경 실패 시 기존 로그인을 보존하고, 인증 파일 누락/변조 시 이전 내장 비밀번호로 자동 복귀하지 않습니다.

인증 봉투 `admin-login.bin` 및 변경 중 `.pending` 파일과 `workspace.bin`은 같은 Windows 사용자 데이터 폴더에 있습니다. 백업·복원 시 **폴더 전체를 함께 보존**하세요. 비밀번호 원문이나 평문 키는 저장하지 않습니다. 이는 앱의 로그인 변경이며 이미 유출된 키의 회수나 같은 Windows 사용자에게 OS 파일 접근 제한을 제공하는 기능은 아닙니다.

웹 비밀번호 변경은 공개 데모의 현재 페이지에서만 적용되며 새로고침하면 **admin/admin**으로 돌아옵니다. Windows 계정/키와 별개입니다.

## 인터페이스 관리

첫 화면은 **현재 ICD** 탭입니다. 저장 프로파일을 선택하면 현재 필드·활성 상태·IP·guest 변환 권한을 보여줍니다.

- **현재 ICD**: 필드 구조, 활성 상태, 송수신 IP와 권한을 검토·저장합니다.
- **가져오기**: 파일 선택 카드와 해석 옵션 카드로 나눴습니다. CSV를 고르고 필요한 `.h/.hpp`를 함께 선택한 뒤 Big/Little/CSV 필드별 순서·pack·비트 순서를 지정합니다. 예제 적용은 별도 영역입니다.
- **내보내기**: CSV / 일반 C++ struct / ZIP을 선택하고 버튼 하나로 내보냅니다.
- **HEX 시험**: 필드별 해석·비트 값 쓰기를 시험합니다. 네트워크로 송신하거나 PCAP을 덮어쓰지 않습니다.

탭을 바꿔도 편집 내용이 유지됩니다. admin만 ICD/헤더/IP/NIC/기록 폴더를 편집·삭제할 수 있습니다. 프로파일 우클릭/Delete, NIC·대시보드 매칭 해제는 설정만 변경하며 PCAP은 삭제하지 않습니다. 비활성 ICD는 기록·CSV 변환에서 제외합니다.

## CSV·C/C++와 내보내기

[입력·내보내기 규칙](docs/CSV-ICD.md)을 확인하세요. 실제 IDLStudio CSV 샘플이 아직 없어 열 규격은 명시적 임시 어댑터입니다. CSV와 함께 제한된 C/C++ 고정 struct·중첩 struct·배열·정수 비트 필드를 읽고, pack1/2/4/8 및 storage lsb0/msb0를 선택합니다. includes/전처리/컴파일러를 실행하거나 ABI를 자동 추정하지 않습니다.

- CSV는 UTF-8 BOM으로 내보냅니다. Excel에서 수정해 CSV UTF-8로 저장하고 **CSV 필드별 설정**으로 다시 가져옵니다. 전개 CSV의 `storage_bits`, `storage_bit_offset`, `message_size`가 비트 저장 단위와 꼬리 패딩을 보존하므로 외부 헤더가 필요하지 않습니다.
- C++는 `struct Telemetry { uint16_t sequence; uint8_t mode : 3; float voltage; };` 형태의 **일반 필드 선언**을 `icd-struct.hpp`로 저장합니다. 배열도 지원하며 원래 이름·offset/endian/scale/bias는 주석에 남깁니다. 네이티브 C++ 메모리 배치가 통신 endian을 자동 직렬화하지는 않습니다. 정확한 물리 위치·배율 보존은 CSV를 사용하세요.
- ZIP은 전개 CSV, 원본 CSV·헤더, 일반 구조체, 가져오기 옵션과 기존 wire 연동용 헤더를 포함합니다. 원본 헤더를 수정한 뒤 원본 CSV와 함께 같은 옵션으로 다시 가져올 수 있습니다.

admin이 명시적으로 내보낸 파일은 평문입니다. 내부 저장은 `%LOCALAPPDATA%\LANscope\workspace.bin`의 Hidden + DPAPI CurrentUser + 관리자 서명이며, CSV/헤더 원본·이름은 관리자 키로 AES-GCM 암호화합니다. 새 비밀번호 기능에서도 기존 키와 바이너리 리소스는 유지합니다. 실제 ICD와 키를 공개 저장소/웹에 넣지 마세요.

## PCAP → CSV 권한

양 계정은 동일한 헤더 검증을 통과한 패킷만 기록합니다. **guest는 명시적으로 허용된 ICD의 값만 CSV로 변환**하며 ICD 정의/헤더를 내보낼 수 없습니다. 같은 IP라도 헤더 ID로 구분할 수 있습니다. IP·ID·길이 규칙까지 겹치면 설정과 저장을 거절하고, CSV에서도 모호한 프레임은 제외합니다. 표준 PCAP은 외부 분석 도구에서도 읽을 수 있습니다.

변환은 완전한 UDP 데이터그램을 스트리밍 처리합니다. TCP 재조립/자동 메시지 구별/CDR 추정은 지원하지 않습니다. 제외/필드 오류를 보고하고 실패·취소 시 부분 CSV를 지우며 PCAP 원본을 덮어쓰지 않습니다.

## 검증과 클라우드 빌드

현재 **SDK 9.0.200**에서 핵심 검증 **198개**, 웹 파서/내보내기 **44개**를 통과했습니다. Chromium에서 탭, 이름 크기/글자, 폴더 변경, 내보내기·재가져오기, 비밀번호 변경/재로그인과 guest 권한을 검증합니다. 일반 C++ 헤더는 컴파일 후 멤버 읽기/쓰기를 확인했습니다.

Windows WPF 실제 실행·DPAPI·Npcap 라이브 NIC 및 설치 EXE 실행은 Linux에서 수행하지 않습니다. 해당 검증은 로컬 Windows에서 필요합니다. 핵심 검증은 `LANSCOPE_TEST_ADMIN/GUEST` 바인딩으로 암호를 받으며 출력하지 않습니다.

```bash
# 기존 checkout 사용, SDK9 활성화 후
export DOTNET_ROOT=/workspace/.dotnet
export PATH="$DOTNET_ROOT:$PATH"
export DOTNET_CLI_HOME=/workspace/.setup/dotnet-home
export NUGET_PACKAGES=/workspace/.setup/offline-dras-net9
dotnet restore DRAS.sln --locked-mode -m:1 -nodeReuse:false
dotnet build DRAS.sln --no-restore -m:1 -nodeReuse:false
bash scripts/package.sh /workspace/artifacts
node tests/check-csv-web.cjs
```

`downloads/DRAS-source.zip`은 코드 전용이며 NuGet/설치 파일은 제외합니다. 직접 오프라인 빌드하려면 위의 **전체 저장소 ZIP**을 받으세요. `docs/`는 GitHub Pages용 공개 UI 데모이고 실제 NIC 수집·ICD 보안은 WPF에서 수행합니다.

### WPF 시작 시 DecodeGrid null 수정

탭 콘텐츠를 만드는 동안 기본 SelectedIndex가 SelectionChanged를 발생시켜 뒤쪽 HEX 탭의 DecodeGrid가 생성되기 전에 미리보기를 갱신하던 문제를 수정했습니다. 선택 이벤트 7개를 XAML에서 제거하고 InitializeComponent가 끝난 뒤 한 번씩 연결합니다.

`python tests/check-wpf-event-wiring.py`는 초기화 전 이벤트 연결의 재도입을 검사합니다. Windows에서는 다음 시작 검사로 실제 WPF 창 생성과 ICD 옵션 전환을 확인할 수 있습니다. 로그인·Npcap 캡처 없이 실행합니다.

```powershell
dotnet run --project tests/LanScope.StartupChecks
```

시작 검사는 Linux에서 빌드만 가능하며 실행 검증은 Windows에서 합니다.


## 기록 전에 공통헤더 지정

현재 ICD 위의 **공통헤더 ID · Length / 메시지 매핑 설정**에서 현재 ICD 또는 별도 헤더를 고르고 ID/Length 필드를 직접 선택하세요. 헤더 포함 여부, 길이 기준과 메시지별 기대 ID를 지정하고 **검증 후 적용 → 프로파일 저장**합니다. 별도 헤더는 대상 ICD와 필드 배치·크기를 대조해 오류를 보고합니다. 체크섬은 없음 모드이며 현재 UDP 데이터그램만 처리합니다. [자세한 설정·제외 기준](docs/RECORDING-MATCHING.md)을 확인하세요.

이전 전체 NIC 저장 요구는 최신 요구로 변경됐습니다. 잘못된 헤더의 패킷은 저장하지 않으며 CSV 변환에서도 같은 검사를 합니다. 기존 설정도 공통헤더 규칙을 지정해야 새 기록을 시작할 수 있습니다.
