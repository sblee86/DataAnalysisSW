using System.ComponentModel;
using System.IO;
using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using Microsoft.Win32;
using SharpPcap.LibPcap;

namespace LanScope;
public partial class MainWindow : Window
{
    private LoginSession? session;
    private WorkspaceSettings settings=new();
    private readonly SettingsStore store=new();
    private readonly CaptureEngine engine=new();
    private readonly DispatcherTimer timer=new(){Interval=TimeSpan.FromSeconds(1)};
    private List<NicInfo> nics=[]; private List<LibPcapLiveDevice> devices=[];
    private bool busy; private int failedLogins;private DateTime blockedUntil;
    private DateTime startedAt;private TimeSpan elapsed;
    private string? editingProfileId;private byte[] selectedIcd=[];private string selectedIcdName="";
    private readonly string[] sampleNames=["샘플 A","샘플 B","샘플 C"];
    public MainWindow()
    {
        InitializeComponent();SampleBox.ItemsSource=sampleNames;SampleBox.SelectedIndex=0;
        timer.Tick+=(_,_)=>Tick();UserIdBox.Focus();
    }
    private static byte[] Resource(string suffix)
    {
        var assembly=Assembly.GetExecutingAssembly();
        var name=assembly.GetManifestResourceNames().Single(n=>n.EndsWith(suffix,StringComparison.Ordinal));
        using var stream=assembly.GetManifestResourceStream(name)!;using var output=new MemoryStream();stream.CopyTo(output);return output.ToArray();
    }
    private async void LoginClick(object sender,RoutedEventArgs e)
    {
        if(busy)return;
        if(DateTime.UtcNow<blockedUntil){LoginError.Text="잠시 후 다시 시도하세요. (30초 대기)";return;}
        busy=true;LoginButton.IsEnabled=false;LoginError.Text="";
        LoginSession? candidate=null;var id=UserIdBox.Text;var password=PasswordInput.Password;PasswordInput.Clear();
        try {
            var result=await Task.Run(()=>new AccountService(Resource("accounts.bin")).Login(id,password));
            candidate=result;password="";
            if(result==null){failedLogins++;if(failedLogins>=5){blockedUntil=DateTime.UtcNow.AddSeconds(30);failedLogins=0;}LoginError.Text="ID 또는 암호가 올바르지 않습니다.";return;}
            settings.ClearPlaintext();settings=store.Load(result);engine.ClearHistory();session=result;candidate=null;failedLogins=0;
            if(!File.Exists(store.FilePath)&&session.Role==UserRole.Admin) {
                using var reader=new BinaryReader(new MemoryStream(Resource("samples.bin")));
                int count=reader.ReadInt32();for(int i=0;i<count;i++) {
                    var p=new RecordProfile{Id=reader.ReadString(),Name=reader.ReadString(),IcdId=reader.ReadString()};p.EncryptedIcd=reader.ReadBytes(reader.ReadInt32());p.SenderIps=["192.0.2."+(10+i)];p.ReceiverIps=["198.51.100."+(20+i)];IcdProtection.Open(session,p);settings.Profiles.Add(p);
                }
            }
            LoginView.Visibility=Visibility.Collapsed;WorkspaceView.Visibility=Visibility.Visible;
            bool admin=session.Role==UserRole.Admin;ProfileNav.Visibility=SettingsNav.Visibility=admin?Visibility.Visible:Visibility.Collapsed;
            AccountText.Text=$"{session.UserId} / {session.Role.ToString().ToUpperInvariant()}";
            PermissionNote.Text=admin?"전체 설정과 기록을 관리할 수 있습니다.":"관리자가 허용한 ICD의\n기록·조회만 가능합니다.\nICD 원본과 구조는 비공개입니다.";
            ReloadEditors();ScanNics();ShowPage("dashboard");timer.Start();UpdateDashboard();
        } catch(Exception error) {candidate?.Dispose();session?.Dispose();session=null;timer.Stop();WorkspaceView.Visibility=Visibility.Collapsed;LoginView.Visibility=Visibility.Visible;LoginError.Text="로그인/설정 로드 실패: "+error.Message;}
        finally {busy=false;LoginButton.IsEnabled=true;UpdateControls();}
    }
    private void PasswordKeyDown(object sender,KeyEventArgs e){if(e.Key==Key.Enter)LoginClick(sender,new());}
    private bool AdminAction()
    {
        try{(session??throw new UnauthorizedAccessException("로그인이 필요합니다.")).RequireAdmin();if(engine.IsRunning||busy)throw new InvalidOperationException("기록 중에는 설정을 변경할 수 없습니다.");return true;}
        catch(Exception error){ShowError(error);return false;}
    }
    private void ShowError(Exception error){StatusText.Text=error.Message;MessageBox.Show(this,error.Message,"LANscope",MessageBoxButton.OK,MessageBoxImage.Warning);}
    private void SaveChange(Action<WorkspaceSettings> change)
    {
        if(!AdminAction())return;
        try {var next=IcdProtection.CloneForAdmin(session!,settings);change(next);store.Save(session!,next);engine.ClearHistory();settings.ClearPlaintext();settings=next;ReloadEditors();UpdateDashboard();StatusText.Text="설정 저장 완료 · Windows 사용자별 암호화된 숨김 바이너리";}
        catch(Exception error){ShowError(error);}
    }
    private void ReloadEditors(){ProfilesList.ItemsSource=session?.Role==UserRole.Admin?settings.Profiles:null;BindingProfiles.ItemsSource=session?.Role==UserRole.Admin?settings.Profiles:null;FolderBox.Text=settings.OutputDirectory;OutputText.Text="기록 폴더: "+settings.OutputDirectory;NewEditor();}
    private void ShowPage(string name)
    {
        if(name!="dashboard"&&(session?.Role!=UserRole.Admin||engine.IsRunning||busy))return;
        DashboardView.Visibility=name=="dashboard"?Visibility.Visible:Visibility.Collapsed;
        ProfilesView.Visibility=name=="profiles"?Visibility.Visible:Visibility.Collapsed;
        SettingsView.Visibility=name=="settings"?Visibility.Visible:Visibility.Collapsed;
        PageTitle.Text=name=="profiles"?"기록 프로파일":name=="settings"?"기록 설정":"기록 대시보드";
    }
    private void DashboardClick(object sender,RoutedEventArgs e)=>ShowPage("dashboard");
    private void ProfilesClick(object sender,RoutedEventArgs e){if(AdminAction())ShowPage("profiles");}
    private void SettingsClick(object sender,RoutedEventArgs e){if(AdminAction())ShowPage("settings");}
    private void NewEditor(){editingProfileId=null;ProfileNameBox.Text="";SenderBox.Text="";ReceiverBox.Text="";selectedIcd=[];selectedIcdName="";IcdText.Text="선택된 CSV 없음";currentSchema=null;IcdFields.ItemsSource=null;DecodeGrid.ItemsSource=null;MessageBoxSelect.ItemsSource=null;BothDirectionsBox.IsChecked=true;GuestIcdAllowedBox.IsChecked=false;}
    private void NewProfileClick(object sender,RoutedEventArgs e){if(AdminAction()){ProfilesList.SelectedItem=null;NewEditor();}}
    private void ProfileSelected(object sender,SelectionChangedEventArgs e)
    {
        if(ProfilesList.SelectedItem is not RecordProfile p)return;
        editingProfileId=p.Id;ProfileNameBox.Text=p.Name;SenderBox.Text=string.Join(", ",p.SenderIps);ReceiverBox.Text=string.Join(", ",p.ReceiverIps);selectedIcd=p.IcdContent;selectedIcdName=p.IcdName;BothDirectionsBox.IsChecked=p.BothDirections;GuestIcdAllowedBox.IsChecked=settings.GuestIcdAllowList.Contains(p.IcdId);UpdateIcdPreview();
    }
    private IcdSchema? currentSchema;
    private void UpdateIcdPreview()
    {
        currentSchema=null;IcdFields.ItemsSource=null;DecodeGrid.ItemsSource=null;MessageBoxSelect.ItemsSource=null;
        try {
            if(!selectedIcdName.EndsWith(".csv",StringComparison.OrdinalIgnoreCase))throw new ArgumentException("기존 IDL 원본을 유지합니다. CSV로 다시 선택한 후 저장하세요.");
            currentSchema=IcdCsv.Parse(selectedIcd);IcdFields.ItemsSource=currentSchema.Fields;MessageBoxSelect.ItemsSource=currentSchema.Messages;MessageBoxSelect.SelectedIndex=0;
            IcdText.Text=$"{selectedIcdName} · {currentSchema.Fields.Count} fields / {currentSchema.Messages.Length} messages · {currentSchema.EncodingName} · BIG ENDIAN";
            if(currentSchema.Warnings.Count>0)IcdText.Text+="\n"+string.Join(" / ",currentSchema.Warnings);
        }catch(ArgumentException error){IcdText.Text="CSV 오류: "+error.Message;}
    }
    private void DecodePayloadClick(object sender,RoutedEventArgs e)
    {
        if(!AdminAction())return;
        try {
            if(currentSchema==null||MessageBoxSelect.SelectedItem is not string message)throw new ArgumentException("정상 CSV와 메시지를 선택하세요.");
            var hex=new string(PayloadHexBox.Text.Where(c=>!char.IsWhiteSpace(c)).ToArray());
            if(hex.Length>65535*2)throw new ArgumentException("payload는 최대 65,535 bytes입니다.");
            DecodeGrid.ItemsSource=currentSchema.Decode(message,Convert.FromHexString(hex));
        }catch(Exception error) when(error is ArgumentException or FormatException){ShowError(error);}
    }
    private void ChooseIcdClick(object sender,RoutedEventArgs e)
    {
        if(!AdminAction())return;
        var d=new OpenFileDialog {Title="IDLStudio CSV ICD 선택",Filter="IDLStudio CSV (*.csv)|*.csv"};
        if(d.ShowDialog()!=true)return;
        try{var info=new FileInfo(d.FileName);if(info.Length==0||info.Length>16*1024*1024)throw new ArgumentException("ICD는 1 byte ~ 16 MB이어야 합니다.");var bytes=File.ReadAllBytes(d.FileName);IcdCsv.Parse(bytes);selectedIcd=bytes;selectedIcdName=info.Name;UpdateIcdPreview();}catch(Exception error){ShowError(error);}
    }
    private void UseSampleClick(object sender,RoutedEventArgs e){if(!AdminAction())return;var sample=settings.Profiles.FirstOrDefault(p=>p.Name=="인터페이스 "+(char)('A'+SampleBox.SelectedIndex));if(sample==null){ShowError(new ArgumentException("초기 샘플이 없습니다. CSV를 가져오세요."));return;}selectedIcdName=sample.IcdName;selectedIcd=[..sample.IcdContent];UpdateIcdPreview();}
    private static List<string> ParseIps(string text)=>text.Split([',',';','\r','\n',' ','\t'],StringSplitOptions.RemoveEmptyEntries).Select(x=>IPAddress.TryParse(x,out var ip)?ip.ToString():x).Distinct().ToList();
    private void SaveProfileClick(object sender,RoutedEventArgs e)
    {
        if(!AdminAction())return;
        try {
            var p=new RecordProfile {Id=editingProfileId??Guid.NewGuid().ToString("N"),Name=ProfileNameBox.Text.Trim(),IcdName=selectedIcdName,IcdContent=[..selectedIcd],SenderIps=ParseIps(SenderBox.Text),ReceiverIps=ParseIps(ReceiverBox.Text),BothDirections=BothDirectionsBox.IsChecked==true};p.Validate();IcdProtection.Seal(session!,p);var allowGuest=GuestIcdAllowedBox.IsChecked==true;
            SaveChange(next=>{if(next.Profiles.Any(x=>x.Id!=p.Id&&x.Name.Equals(p.Name,StringComparison.OrdinalIgnoreCase)))throw new ArgumentException("프로파일 이름이 중복되었습니다.");next.Profiles.RemoveAll(x=>x.Id==p.Id);next.Profiles.Add(p);next.GuestIcdAllowList.RemoveAll(id=>id==p.IcdId);if(allowGuest)next.GuestIcdAllowList.Add(p.IcdId);});
        }catch(Exception error){ShowError(error);}
    }
    private void DeleteProfileClick(object sender,RoutedEventArgs e)
    {
        if(!AdminAction()||editingProfileId==null)return;var id=editingProfileId;
        if(MessageBox.Show(this,"프로파일과 이 프로파일의 NIC 매칭을 삭제할까요?","삭제 확인",MessageBoxButton.YesNo)!=MessageBoxResult.Yes)return;
        SaveChange(next=>{next.Profiles.RemoveAll(p=>p.Id==id);foreach(var b in next.Bindings)b.ProfileIds.Remove(id);next.Bindings.RemoveAll(b=>b.ProfileIds.Count==0);});
    }
    private void ScanNics()
    {
        var scan=NicDiscovery.Scan();nics=scan.Nics;devices=scan.Devices;NicGrid.ItemsSource=nics;
        StatusText.Text=scan.Warning.Length>0?scan.Warning:$"NIC {nics.Count}개 검색 · Npcap 장치 {devices.Count}개";
    }
    private void RescanClick(object sender,RoutedEventArgs e){if(AdminAction()){ScanNics();UpdateDashboard();}}
    private void NicSelected(object sender,SelectionChangedEventArgs e)
    {
        BindingProfiles.UnselectAll();if(NicGrid.SelectedItem is not NicInfo nic)return;
        BindingTitle.Text=nic.Name+(nic.Capturable?" · 프로파일 매칭":" · Npcap 캡처 불가");
        var ids=settings.Bindings.FirstOrDefault(b=>b.DeviceId==nic.Id)?.ProfileIds??[];
        foreach(var p in settings.Profiles.Where(p=>ids.Contains(p.Id)))BindingProfiles.SelectedItems.Add(p);
    }
    private void SaveBindingClick(object sender,RoutedEventArgs e)
    {
        if(!AdminAction())return;
        if(NicGrid.SelectedItem is not NicInfo nic||!nic.Capturable){ShowError(new ArgumentException("캡처 가능한 NIC을 선택하세요."));return;}
        var ids=BindingProfiles.SelectedItems.Cast<RecordProfile>().Select(p=>p.Id).ToList();
        if(ids.Count==0){ShowError(new ArgumentException("프로파일을 1개 이상 선택하세요."));return;}
        SaveChange(next=>{next.Bindings.RemoveAll(b=>b.DeviceId==nic.Id);next.Bindings.Add(new NicBinding {DeviceId=nic.Id,DeviceName=nic.Name,ProfileIds=ids});});
    }
    private void RemoveBindingClick(object sender,RoutedEventArgs e){if(NicGrid.SelectedItem is NicInfo nic)SaveChange(next=>next.Bindings.RemoveAll(b=>b.DeviceId==nic.Id));}
    private void ChooseFolderClick(object sender,RoutedEventArgs e)
    {
        if(!AdminAction())return;var d=new OpenFolderDialog {Title="시험 PCAP 기록 폴더 선택"};if(d.ShowDialog()==true)FolderBox.Text=d.FolderName;
    }
    private void SaveFolderClick(object sender,RoutedEventArgs e)
    {
        if(!AdminAction())return;string folder=FolderBox.Text.Trim();
        SaveChange(next=>{if(!Path.IsPathFullyQualified(folder))throw new ArgumentException("기록 폴더는 절대 경로를 입력하세요.");Directory.CreateDirectory(folder);next.OutputDirectory=folder;});
    }
    private async void ProtectLegacyClick(object sender,RoutedEventArgs e)
    {
        if(!AdminAction())return;
        if(MessageBox.Show(this,"저장된 기록 폴더의 구버전 session.bin 안에 있는 ICD 원본을 암호화합니다. PCAP은 변경하지 않습니다. 진행할까요?","이전 ICD 보호",MessageBoxButton.YesNo)!=MessageBoxResult.Yes)return;
        busy=true;SettingsView.IsEnabled=false;UpdateControls();
        try{var result=await Task.Run(()=>LegacySessionProtection.ProtectFolder(session!,settings.OutputDirectory));StatusText.Text=$"메타데이터 암호화 {result.Updated}개 · 제외 {result.Skipped}개 · 실패 {result.Errors.Count}개";if(result.Errors.Count>0)ShowError(new IOException(string.Join("\n",result.Errors.Take(8))));}
        catch(Exception error){ShowError(error);}finally{busy=false;SettingsView.IsEnabled=true;UpdateControls();}
    }
    private async void StartClick(object sender,RoutedEventArgs e)
    {
        if(session==null||busy||engine.IsRunning)return;
        var name=TestNameBox.Text.Trim();busy=true;UpdateControls();
        try {await Task.Run(()=>engine.Start(session,settings,devices,name));startedAt=DateTime.UtcNow;elapsed=TimeSpan.Zero;SessionText.Text="기록 폴더: "+engine.SessionDirectory;StatusText.Text="기록 시작 · 시험 메타데이터에는 ICD 식별자만 저장하며 원본은 포함하지 않습니다.";}
        catch(Exception error){ShowError(error);}
        finally{busy=false;UpdateControls();UpdateDashboard();}
    }
    private async Task StopRecording()
    {
        if(busy)return;busy=true;UpdateControls();
        try{await Task.Run(engine.Stop);elapsed=DateTime.UtcNow-startedAt;StatusText.Text=engine.LastError.Length>0?engine.LastError:"기록 중지 · 파일 저장 완료";SessionText.Text="시험 폴더: "+engine.SessionDirectory+(session?.Role==UserRole.Admin?"\n"+engine.DriverSummary:"");}
        catch(Exception error){ShowError(error);}finally{busy=false;UpdateControls();UpdateDashboard();}
    }
    private async void StopClick(object sender,RoutedEventArgs e){if(session!=null&&engine.IsRunning)await StopRecording();}
    private void UpdateControls()
    {
        bool active=engine.IsRunning;
        StartButton.IsEnabled=session!=null&&!active&&!busy&&settings.Bindings.Count>0&&!settings.GuestRecordingConflict;
        StopButton.IsEnabled=active&&!busy;TestNameBox.IsEnabled=!active&&!busy;
        ProfileNav.IsEnabled=SettingsNav.IsEnabled=!active&&!busy;
        RunBadge.Text=active?"● 기록 중":busy?"● 처리 중":"● 대기 중";
    }
    private async void Tick()
    {
        if(busy||session==null)return;
        if(engine.IsRunning) {
            if(engine.LastError.Length>0||engine.UnexpectedStop()){var message=engine.LastError.Length>0?engine.LastError:"NIC 캡처가 예기치 않게 중지되었습니다.";await StopRecording();ShowError(new IOException(message));return;}
            try {engine.Flush();}catch(Exception error){await StopRecording();ShowError(error);return;}
        }
        UpdateDashboard();
    }
    private void UpdateDashboard()
    {
        if(session==null)return;if(settings.GuestRecordingConflict)SessionText.Text="허용/비허용 ICD의 IP가 겹쳐 guest 기록을 차단합니다. 관리자에게 매칭 분리를 요청하세요.";var snapshots=engine.Snapshot();
        if(snapshots.Count==0)snapshots=settings.Bindings.SelectMany(b=>b.ProfileIds.Select(id=>new MappingSnapshot(b.DeviceName,settings.Profiles.FirstOrDefault(p=>p.Id==id)?.Name??"삭제된 프로파일",0,0,0,0,0,"—",nics.Any(n=>n.Id==b.DeviceId&&n.Capturable)?"대기":"NIC 없음"))).ToList();
        MonitorGrid.ItemsSource=snapshots;MappingTotal.Text=snapshots.Count.ToString();PacketTotal.Text=snapshots.Sum(s=>s.Packets).ToString("N0");ByteTotal.Text=FormatBytes(snapshots.Sum(s=>s.Bytes));
        ElapsedText.Text=(engine.IsRunning?DateTime.UtcNow-startedAt:elapsed).ToString(@"hh\:mm\:ss");
        if(engine.IsRunning&&session.Role==UserRole.Guest)SessionText.Text="허용된 ICD만 기록 중 · 시험 폴더: "+engine.SessionDirectory;
        else if(engine.IsRunning)SessionText.Text=$"시험 폴더: {engine.SessionDirectory}\nNIC 관측 프레임: {engine.ObservedFrames:N0} · 해석 실패: {engine.ParseFailures:N0} · 각 NIC/프로파일별 독립 PCAP 기록";
        UpdateControls();
    }
    private static string FormatBytes(long value)=>value>=1048576?$"{value/1048576.0:F2} MB":value>=1024?$"{value/1024.0:F2} KB":$"{value} B";
    private async void LogoutClick(object sender,RoutedEventArgs e)
    {
        if(busy)return;
        if(engine.IsRunning){if(MessageBox.Show(this,"기록을 중지하고 로그아웃할까요?","로그아웃",MessageBoxButton.YesNo)!=MessageBoxResult.Yes)return;await StopRecording();}
        timer.Stop();settings.ClearPlaintext();NewEditor();ProfilesList.ItemsSource=null;BindingProfiles.ItemsSource=null;session?.Dispose();session=null;WorkspaceView.Visibility=Visibility.Collapsed;LoginView.Visibility=Visibility.Visible;UserIdBox.Clear();PasswordInput.Clear();LoginError.Text="";UserIdBox.Focus();
    }
    private void WindowClosing(object? sender,CancelEventArgs e)
    {
        if(busy){e.Cancel=true;return;}
        if(engine.IsRunning&&MessageBox.Show(this,"기록을 중지하고 종료할까요?","종료",MessageBoxButton.YesNo)!=MessageBoxResult.Yes){e.Cancel=true;return;}
        timer.Stop();engine.Dispose();settings.ClearPlaintext();session?.Dispose();
    }
}
