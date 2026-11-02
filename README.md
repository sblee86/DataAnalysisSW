# DRAS (Data Recording & analysis software)

Windows WPF LAN 패킷 수집/PCAP 기록 및 CSV 값 변환 작업 공간.

- [웹 UI 미리보기](https://sblee86.github.io/DataAnalysisSW/) — **웹 관리자 로그인: admin / admin** (공개 UI 데모 전용)
- [전체 소스 + 오프라인 NuGet ZIP](https://github.com/sblee86/DataAnalysisSW/archive/refs/heads/main.zip)
- [Windows x64 실행 ZIP](https://github.com/sblee86/DataAnalysisSW/raw/refs/heads/main/downloads/DRAS-win-x64.zip)
- [GitHub Pages 설정](https://github.com/sblee86/DataAnalysisSW/settings/pages): Deploy from a branch → `main` → `/docs` → Save

웹 로그인 변경은 Windows 계정/ICD 키를 바꾸지 않습니다. Windows 임시 계정 암호는 이전 전달 메시지와 동일합니다. 웹은 공개 샘플과 통계 시뮬레이션만 사용하며 PCAP 변환 화면의 다운로드도 데모 결과입니다. 실제 PCAP 분석은 WPF에서 수행합니다.

## 실행용 .NET 설치 파일 포함

- [Windows .NET 8 Desktop Runtime x64 설치 파일](https://github.com/sblee86/DataAnalysisSW/raw/refs/heads/main/installers/dotnet/windowsdesktop-runtime-8.0.33-win-x64.exe)을 `installers/dotnet/`에 포함했습니다. 공식 Microsoft 배포본이며 공개 SHA-512와 대조했습니다. 원본 URL/해시는 해당 폴더의 `origin.json`, `SHA512SUMS.txt`에 있습니다.
- 배포된 `DRAS.exe`는 런타임 포함형이므로 보통 별도 설치 없이 실행됩니다. 설치 파일은 요청하신 환경용으로 함께 제공합니다. Linux에서 설치 EXE 자체를 실행 검증한 것은 아닙니다.
- **Desktop Runtime 설치와 SDK 설치는 다릅니다.** VS2022에서 소스를 빌드하려면 아래 안내의 .NET SDK 8.0.427이 필요합니다. Npcap도 별도 설치 대상입니다.

## CSV + C/C++ 헤더 가져오기 / 활성 ICD 목록

관리자 → 인터페이스 관리에서 CSV와 필요한 `.h/.hpp`를 함께 선택하고 바이트 순서·pack·비트 순서를 지정한 뒤 저장하세요. CSV의 `type=struct`와 `struct_name` 또는 `type=struct:Envelope`가 헤더 구조체를 참조합니다. [입력 규칙과 제한](docs/CSV-ICD.md)을 확인하세요. 공개 샘플 `samples/StructTelemetry.csv` + `samples/PacketLayout.h`는 pack=1, lsb0 예제입니다.

CSV 원본·이름·헤더 원본·헤더 이름은 함께 AES-GCM 암호화해 기존 Windows 사용자별 숨김 폴더의 `workspace.bin`에 저장합니다. 선택한 외부 원본 파일을 삭제하거나 변경하지 않습니다. 이전 CSV-only 암호문과 계정/키를 유지합니다. guest 허용 ICD만 변환 시 내부 복호화하며, 이때도 원본 편집 UI는 제공하지 않습니다.

저장된 목록에는 별칭·활성/비활성·바이트 순서를 표시하고, 선택하면 저장한 헤더와 옵션을 다시 불러옵니다. **저장 ICD 다시 읽기**는 디스크의 암호화 저장소를 다시 읽습니다. **활성 ICD**를 해제하면 해당 ICD 분류와 CSV 변환을 중지하지만, NIC 전체 표준 PCAP 기록은 admin/guest 모두 계속 가능합니다. 웹은 공개 샘플을 메모리에 유지하는 검토용 시안이며 새로고침 시 가져온 ICD는 사라집니다.

## 화면 설정 / 우클릭 메뉴

- 프로그램 표시 이름은 **DRAS (Data Recording & analysis software)**이며 실행 파일은 `DRAS.exe`입니다.
- 우측 상단 **화면 설정**에서 본문(12~20), 메뉴(12~20), 표 내용(10~20), 표 제목(11~22), 화면 제목(20~36px)을 각각 조절합니다. 기본값은 13/13/12/12/28입니다. 로그인 화면과 모든 계정에서 사용할 수 있고, 표 행 높이도 맞춰집니다. WPF 설정 창은 크기를 조절할 수 있으며 웹 설정 패널도 모서리를 끌어 조절합니다. ICD 목록 너비와 NIC 목록 비율은 설정 또는 구분선 드래그로 조절합니다.
- WPF 글자 크기는 `%LOCALAPPDATA%\DRAS\ui-preferences.bin` 숨김 바이너리, 웹은 브라우저 로컬 저장소에 유지합니다. 화면 설정은 인터페이스 수정 권한과 별개입니다.
- admin이 프로파일 목록을 우클릭하면 **프로파일 삭제**, Delete 키로도 삭제할 수 있습니다. NIC 목록은 **선택 NIC 매칭 해제**, 대시보드 표는 **이 프로파일 매칭 해제**를 제공합니다. 확인 후 설정만 변경하며 PCAP 파일은 삭제하지 않습니다.
- guest 및 기록 중에는 설정 삭제/매칭 해제를 막습니다. CSV 변환의 PCAP 경로 우클릭 **선택 해제**는 모든 계정이 사용할 수 있으며 원본을 지우지 않습니다.
- 기존 계정/암호화 키와 `%LOCALAPPDATA%\LANscope\workspace.bin` 경로는 유지해 이전 데이터 호환성을 보존합니다. 공개 저장소 이름 `DataAnalysisSW`는 그대로입니다.

## 권한 — PCAP 기록과 CSV 해석을 분리

| 기능 | admin | guest |
|---|---|---|
| 선택 NIC 전체 패킷 PCAP 저장/시작/중지 | 동일하게 가능 | 동일하게 가능 |
| 모든 인터페이스의 수집 현황 확인 | 가능 | 가능 |
| 인터페이스/ICD/IP 추가·수정·삭제 | 가능 | 불가 |
| NIC 매칭/저장 경로 변경 | 가능 | 불가 |
| 저장된 PCAP → CSV 값 변환 | 전체 ICD | 관리자가 허용한 ICD만 |
| 원본 CSV ICD/필드 편집 | 가능 | 불가 |

**guest의 ICD 권한은 CSV 변환에만 적용하며 PCAP 기록에는 적용하지 않습니다.** CSV 변환 권한이 전혀 없어도 기록할 NIC가 설정되어 있으면 guest도 수집할 수 있습니다. 동일 IP의 ICD가 혼재해도 PCAP 저장은 허용합니다.

## Windows 실행 및 첫 설정

실행 ZIP을 해제해 `DRAS.exe`를 실행합니다. .NET과 암호화된 샘플 ICD가 단일 EXE에 포함되어 별도 .NET 런타임 설치는 필요하지 않습니다. 실제 NIC 캡처에는 **Npcap**을 별도로 설치해야 하며, 설치 옵션에 따라 Windows 관리자 권한이 필요할 수 있습니다.

1. admin으로 로그인해 **인터페이스 관리**에서 CSV ICD와 송수신 IP를 설정합니다. 공개 CSV 샘플 3개가 초기 프로파일로 준비됩니다.
2. **이 ICD의 PCAP → CSV 값 변환을 guest에게 허용**을 선택하면 해당 ICD의 값 변환을 허용합니다. 기본은 변환 비허용입니다. 같은 CSV 내용을 쓰는 프로파일들은 하나의 ICD 권한을 공유합니다.
3. **기록 설정**에서 NIC별 프로파일을 1개 이상 매칭하고 기록 폴더를 저장합니다. NIC 매칭이 기록 장치 선택 역할을 합니다. 수정은 admin만 가능합니다.
4. admin 또는 guest로 **기록 대시보드**에서 시험 이름을 입력하고 시작합니다.
5. 선택 NIC에서 Npcap이 전달한 모든 프레임을 기록합니다. ICD/IP 매칭되지 않은 패킷과 ARP도 기록되며, ICD 필터/BPF로 원본을 제외하지 않습니다.
6. 기록 중 설정·변환을 제한하며 로그아웃/종료 시 중지 여부를 확인합니다.

기록 파일은 `<기록폴더>/<시각>_<시험이름>_<고유값>/` 아래 생성됩니다.

- `nic01.pcap`, `nic02.pcap` …: **NIC당 한 표준 PCAP**, 링크 타입·타임스탬프·수집 원본을 보존합니다. snaplen=65,535 bytes. 파일을 매초 flush하고 정상 중지 시 닫습니다.
- `session.bin` v3: 시험/계정/시간/NIC/인터페이스 별칭/ID/ICD 지문/PCAP 참조만 담습니다. 원본 CSV·ICD 파일명·필드 구조·암호화 키는 넣지 않습니다.

상단 전체 패킷/용량은 NIC PCAP 전체 기준입니다. 아래 NIC→인터페이스 표는 송수신 IP에 매칭된 패킷의 분류 통계이며 저장 필터가 아닙니다. 하나의 프레임이 여러 인터페이스 통계에 잡힐 수 있지만 PCAP에는 해당 NIC에서 받은 프레임을 한 번만 기록합니다. 통계 바이트에는 PCAP 헤더가 포함되지 않습니다.

드라이버/네트워크에서 이미 누락된 패킷이나 snaplen 밖의 원본 길이까지 보장하지 않습니다. 고속 기록 드롭과 비정상 종료 후 마지막 프레임은 Windows 부하/복구 시험으로 확인해야 합니다.

## PCAP → CSV 값 변환

1. 기록을 중지한 후 **PCAP → CSV 변환** 메뉴를 엽니다.
2. PCAP 파일, 해석 인터페이스, 메시지를 선택합니다.
3. guest는 허용된 ICD만 선택 후 변환할 수 있습니다. 제한된 ICD 선택 시 메시지/변환 기능을 차단합니다. admin은 모든 ICD를 사용할 수 있습니다.
4. CSV 출력 경로를 선택합니다. 원본 PCAP은 변경하지 않습니다. 취소/실패 시 미완료 임시 CSV는 제거하며, PCAP과 동일한 경로를 출력으로 선택할 수 없습니다.

현재는 **완전한 UDP 데이터그램** 중 선택 인터페이스의 송수신 IP에 매칭되는 패킷을 해석합니다. ARP/다른 IP/TCP/IPv4 조각/불완전 UDP는 제외 건수로 알립니다. TCP 스트림 재조립과 자동 메시지 식별은 미구현입니다. CSV 정의는 UDP payload 시작을 기준으로 지정해야 합니다. payload가 짧거나 값 범위를 넘으면 해당 값은 빈 칸, 마지막 `DecodeError` 열에 이유를 표시하며 오류 행 수를 집계합니다.

CSV 열은 `PacketIndex`, `UtcTimestamp`, 송수신 IP/포트, 선택한 ICD 필드 값들, `DecodeError`입니다. IEEE754/부호/비트 필드/배율은 CSV ICD 규칙을 따릅니다. 행은 스트리밍으로 출력합니다.

guest 변환 요청은 서비스에서 허용 목록을 다시 검사합니다. 같은 NIC/IP 범위에 허용·제한 ICD가 겹쳐 프로토콜을 구분할 수 없으면 **CSV 변환만 차단**합니다. PCAP 수집은 계속 허용됩니다. 실제 IDLStudio CSV의 메시지 식별 규격이 제공되면 이 판별을 보강할 수 있습니다.

권한 변경은 다음 변환 요청에 적용됩니다. 이미 시작한 작업/내보낸 CSV/복사한 파일에 대한 소급 회수는 하지 않습니다. PCAP은 표준 원본이므로 **앱의 CSV 변환 권한이 외부 도구를 통한 분석까지 막지는 않습니다.**

## CSV ICD / 바이트 순서 선택

입력은 사용자의 IDLStudio CSV를 대상으로 하며 실제 출력 예시는 아직 받지 못했습니다. 현재 헤더/비트 규칙은 [명시적인 임시 어댑터](docs/CSV-ICD.md)이며 실제 형식 호환성을 확정하지 않았습니다.

- ICD마다 **Big endian / Little endian / CSV 필드별 설정**을 선택합니다. CSV에서 생략한 순서는 be이며 1바이트는 변환하지 않습니다.
- 정수/부호/1~64 bit/바이트 경계 교차/float32·64/bytes/scale·bias 지원.
- `msb0` 기본, 명시적 `lsb0` 번호 지원. 실제 bit offset 기준은 CSV 샘플로 대조해야 합니다.
- 프로파일에서 CSV 필드 표와 수동 Payload HEX 읽기·쓰기 미리보기를 제공합니다 (admin 전용).
- `samples/*.csv`는 공개 예제이며 실제 IDLStudio 출력이 아닙니다. `.idl` 파일은 구버전 참고용입니다.

## ICD 보호

ICD만 암호화하고 PCAP은 표준 파일로 유지합니다.

- admin의 CSV 원본·파일명은 암호에서 별도 파생한 키로 AES-256-GCM 암호화합니다. 암호 검증 해시를 암호화 키로 사용하지 않습니다. 키는 EXE/설정에 저장하지 않습니다.
- 허용한 ICD는 guest의 별도 ECDH P-256 공개키로도 감싼 암호문을 만듭니다. guest가 admin 암호 없이 **허용된 CSV 변환을 내부적으로 수행**할 수 있도록 한 것입니다. guest UI에는 원본 ICD 편집기를 제공하지 않습니다. 제한 ICD에는 guest 복호화용 암호문을 만들지 않습니다.
- 허용된 변환에서는 필드 이름/값이 CSV 결과에 드러납니다. 이것까지 숨기는 기능은 아닙니다. 허용 ICD의 처리를 위해 프로그램 메모리에 해석 정보가 존재하며, PC/프로세스/EXE를 완전히 제어하는 사용자에 대한 역공학 방지 보장은 없습니다.
- 설정은 `%LOCALAPPDATA%\LANscope\workspace.bin`의 DPAPI CurrentUser + Hidden 바이너리입니다. 원본 ICD 속성은 직렬화하지 않고 암호문만 저장합니다. 정책/매칭/권한은 admin 서명과 EXE의 고정 공개키로 검증합니다.
- guest 로그인은 ICD 원본을 복호화하지 않고 모든 인터페이스의 기록 메타데이터만 읽습니다. CSV 변환 요청에서 허용된 ICD만 내부 복호화합니다.
- 새 메타데이터에는 ICD 원본을 넣지 않습니다. 구버전 `session.bin`의 원본은 admin **기록 설정 → 이전 시험 메타데이터의 ICD 암호화**로 보호할 수 있으며 PCAP은 바꾸지 않습니다.
- 이전 설정은 admin 로그인으로 새 형식에 저장합니다. v0.4의 `GuestIcdAllowList`는 이제 **CSV 변환 허용 목록**입니다. guest용 변환 암호문이 없는 이전 설정은 admin이 권한을 다시 저장해야 합니다.
- 실제 기밀 ICD/키는 공개 저장소/Pages에 넣지 마세요. 가져온 원본 CSV 파일을 자동 삭제하지 않으므로 관리자 원본 위치도 관리해야 합니다.

**실제 ICD 사용 전 임시 Windows admin/guest 암호를 변경하세요.** `python scripts/set-accounts.py`는 계정 해시, 공개키와 암호화된 데모 리소스를 함께 재생성하며 SDK가 필요합니다. 기존 vault의 자동 키 회전은 미구현이므로 이미 저장한 실제 ICD가 있으면 기존 빌드/암호/원본을 보존하고 별도 이전해야 합니다. 웹 `admin/admin`은 Windows 키와 무관한 공개 데모 계정입니다.

## Visual Studio 2022에서 빌드

.NET 10 요구 사항을 제거하고 **net8.0-windows / C# 12**로 전환했습니다. VS2022는 .NET 8을 지원하는 **17.8 계열 이상의 최신 패치**를 사용하세요. 이 SDK의 최소 MSBuild 버전은 17.8.3이며 VS2022 최신 17.x 업데이트를 권장합니다. VS2026은 필요하지 않습니다.

1. Visual Studio Installer에서 **.NET 데스크톱 개발** 워크로드를 설치합니다.
2. [Windows x64 .NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)를 설치합니다. 포함된 오프라인 팩과 global.json은 **SDK 8.0.427 / 런타임 팩 8.0.33** 기준입니다. 런타임만 설치하면 소스를 빌드할 수 없습니다.
3. 전체 저장소 ZIP을 해제하고 루트의 **DRAS.sln**을 엽니다.
4. `DRAS`를 시작 프로젝트로 설정하고 Debug 또는 Release 빌드/F5를 사용합니다. Windows x64 타깃은 프로젝트에 지정했습니다.
5. Npcap이 없는 PC에서도 로그인 화면을 실행할 수 있지만 실제 NIC 캡처와 SharpPcap 기반 PCAP 읽기에는 Npcap이 필요합니다.

기존 계정/암호화 키 리소스는 변경하지 않았습니다. .NET 10에서 만든 암호화 데모 리소스와 공개키를 .NET 8 코드로 검증했습니다. 실제 Windows 설정/기록과 IDE 실행은 로컬에서 확인해야 합니다.

## 오프라인 직접 빌드

Windows x64 .NET SDK **8.0.427**을 먼저 설치하고 전체 저장소 ZIP을 받으세요. 원본 NuGet 패키지 11개와 해시/잠금 파일을 포함합니다. 코드 전용 `downloads/DRAS-source.zip`에는 용량 때문에 NuGet 피드와 설치 EXE를 제외합니다. 전체 저장소 ZIP에는 모두 포함됩니다.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-offline.ps1
```

결과는 `artifacts\windows-x64\DRAS.exe`. 실행 정책은 해당 호출에만 적용됩니다. Linux cross-build:

```sh
dotnet restore src/LanScope/LanScope.csproj -r win-x64 --locked-mode
dotnet publish src/LanScope/LanScope.csproj -c Release -r win-x64 --self-contained true --no-restore -o artifacts/windows-x64
```

## 검증

현재 .NET 8 핵심 검증 134개, 웹 파서 29개, Chromium UI 기능/권한/설정 검증을 통과했습니다. Windows 전용 DPAPI 검사 네 개는 Linux에서 건너뛰었습니다.

`tests/LanScope.Checks`는 암호/정책/ICD 보호, 전체 프레임 기록, guest 변환 허용·거절·취소, 실제 libpcap PCAP→CSV, CSV 비트 해석 등을 확인합니다. 임시 암호는 `LANSCOPE_TEST_ADMIN` / `LANSCOPE_TEST_GUEST` 바인딩으로 받고 출력하지 않습니다. Windows에서는 DPAPI/Hidden/재저장 검사도 실행하며 Linux에서는 네 검사를 건너뜁니다.

웹 시안은 별도 `admin/admin` 로그인, 동일 PCAP 기록 UI, 관리자 편집, ICD별 CSV 권한과 데모 다운로드를 검증합니다. 실제 Windows WPF/DPAPI/Npcap/라이브 NIC/드롭·디스크 부하 검증은 로컬에서 해야 합니다.

## 비트 필드 읽기·쓰기와 암호화 저장

CSV를 읽어 인터페이스로 **저장**하면 원본 CSV와 함께 선택한 헤더·정의는 암호화된 내부 저장소에 보관합니다. 가져오기·편집·저장은 admin만 가능하며 guest의 직접 저장 요청도 서비스에서 거절합니다. 선택했던 원본 CSV를 자동 삭제하지는 않습니다.

프로파일의 메시지/쓰기 필드/값을 선택하고 **필드값 쓰기**를 누르면 현재 HEX의 해당 물리 비트 범위만 변경합니다. 다른 필드와 주변 비트는 보존하며, 바로 읽기 결과를 갱신합니다. HEX가 비어 있으면 정의된 메시지 길이의 0 버퍼를 만듭니다. 기존 버퍼가 너무 짧거나 범위를 넘는 값이면 입력을 유지하고 오류를 표시합니다.

- 기본 입력은 실제값이며 `(값 - bias) / scale`로 역변환해 정수/부호/IEEE754로 씁니다. 정수로 정확히 표현되지 않는 값과 범위 초과를 거절합니다.
- **raw 값으로 쓰기**에서는 정수 필드의 raw 정수, float의 IEEE754 unsigned 비트 패턴을 입력합니다. bool은 true/false 또는 1/0, bytes는 정확한 길이의 HEX입니다.
- 바이트 순서는 Big/Little을 선택하고 1바이트는 그대로이며 1~64비트와 바이트 경계 교차, msb0/lsb0 번호를 지원합니다. scale=0은 실제값 역변환이 불가능하므로 raw 모드만 허용합니다.
- 이것은 버퍼/HEX 구성 및 검증 기능입니다. NIC 송신이나 원본 PCAP 덮어쓰기는 하지 않습니다.
