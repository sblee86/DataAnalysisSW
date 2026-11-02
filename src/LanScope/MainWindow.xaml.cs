using System.ComponentModel;
using System.IO;
using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using System.Windows.Media;
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
    private string? editingProfileId;private byte[] selectedIcd=[];private string selectedIcdName="";private List<StructSource> selectedStructs=[];
    private readonly string[] sampleNames=["샘플 A","샘플 B","샘플 C"];
    public MainWindow()
    {
        InitializeComponent();ApplyUiLayout(uiPreferences.LoadLayout(),false);UpdateNavColors("dashboard");SampleBox.ItemsSource=sampleNames;SampleBox.SelectedIndex=0;
        timer.Tick+=(_,_)=>Tick();UserIdBox.Focus();
    }
    private readonly UiPreferences uiPreferences=new();
    private void UpdateNavColors(string page)
    {
        foreach(var item in new[]{(DashboardNav,"dashboard"),(ProfileNav,"profiles"),(SettingsNav,"settings"),(ConvertNav,"conversion")}) {
            bool selected=item.Item2==page;item.Item1.Background=new SolidColorBrush((Color)ColorConverter.ConvertFromString(selected?"#2B4770":"#142238"));item.Item1.Foreground=new SolidColorBrush((Color)ColorConverter.ConvertFromString(selected?"#F8FAFC":"#CAD6E8"));item.Item1.FontWeight=selected?FontWeights.SemiBold:FontWeights.Normal;
        }
    }
    private UiLayoutOptions uiLayout=new();private Window? displaySettings;
    private void ApplyUiLayout(UiLayoutOptions value,bool persist)
    {
        value.Validate();uiLayout=value;
        foreach(var key in Resources.Keys.OfType<string>().Where(k=>k.StartsWith("UiFont")||k.StartsWith("UiLine")||k.StartsWith("UiHeight")||k.StartsWith("UiRow")).ToList()){
            var n=double.Parse(new string(key.Where(char.IsDigit).ToArray()),System.Globalization.CultureInfo.InvariantCulture);
            double ratio=key.StartsWith("UiFont")&&n>=18?value.Title/28.0:value.Body/13.0;
            if(key.StartsWith("UiRow"))ratio=Math.Max(1,Math.Max(value.Body/13.0,value.Title/28.0));
            if(key=="UiHeight40")ratio=value.Table/12.0;if(key=="UiHeight36")ratio=value.TableHeader/12.0;
            Resources[key]=key.StartsWith("UiRow")?new GridLength(n*ratio):(object)(n*ratio);
        }
        Resources["MenuFontSize"]=(double)value.Menu;Resources["TableFontSize"]=(double)value.Table;Resources["TableHeaderFontSize"]=(double)value.TableHeader;
        Resources["UiSidebar"]=new GridLength(216*Math.Max(1,value.Menu/13.0));
        ProfileColumn.Width=new GridLength(value.ProfileWidth);NicLeftColumn.Width=new GridLength(value.NicPercent,GridUnitType.Star);NicRightColumn.Width=new GridLength(100-value.NicPercent,GridUnitType.Star);
        if(persist)try{uiPreferences.SaveLayout(value);}catch(Exception e) when(e is IOException or UnauthorizedAccessException){StatusText.Text="화면 설정 저장 실패: "+e.Message;}
    }
    private void ScreenSettingsClick(object sender,RoutedEventArgs e){if(displaySettings!=null){displaySettings.Activate();return;}displaySettings=new DisplaySettingsWindow(uiLayout,v=>ApplyUiLayout(v,true)){Owner=this};displaySettings.Closed+=(_,_)=>displaySettings=null;displaySettings.Show();}
    private void PaneResized(object sender,System.Windows.Controls.Primitives.DragCompletedEventArgs e){displaySettings?.Close();ApplyUiLayout(uiLayout with{ProfileWidth=Math.Clamp((int)ProfileColumn.ActualWidth,180,500),NicPercent=Math.Clamp((int)(100*NicLeftColumn.ActualWidth/Math.Max(1,NicLeftColumn.ActualWidth+NicRightColumn.ActualWidth)),30,75)},true);}
    private static T? Ancestor<T>(DependencyObject? node) where T:DependencyObject
    {
        while(node!=null){if(node is T found)return found;node=node is System.Windows.ContentElement?LogicalTreeHelper.GetParent(node):VisualTreeHelper.GetParent(node);}return null;
    }
    private void ProfileRightClick(object sender,MouseButtonEventArgs e){var item=Ancestor<ListBoxItem>(e.OriginalSource as DependencyObject);if(item!=null)item.IsSelected=true;}
    private void GridRightClick(object sender,MouseButtonEventArgs e){var row=Ancestor<DataGridRow>(e.OriginalSource as DependencyObject);if(row!=null)row.IsSelected=true;}
    private void ProfileKeyDown(object sender,KeyEventArgs e){if(e.Key==Key.Delete&&ProfilesList.SelectedItem!=null){DeleteProfileClick(sender,new());e.Handled=true;}}
    private void EditContextOpened(object sender,RoutedEventArgs e)
    {
        if(sender is ContextMenu menu){menu.FontSize=uiLayout.Menu;foreach(var item in menu.Items.OfType<MenuItem>())item.IsEnabled=session?.Role==UserRole.Admin&&!engine.IsRunning&&!busy;}
    }
    private void RemoveBindingConfirmClick(object sender,RoutedEventArgs e)
    {
        if(!AdminAction()||NicGrid.SelectedItem is not NicInfo nic)return;
        if(MessageBox.Show(this,$"{nic.Name}의 프로파일 매칭을 모두 해제할까요? PCAP 원본은 유지됩니다.","매칭 해제",MessageBoxButton.YesNo)==MessageBoxResult.Yes)RemoveBindingClick(sender,e);
    }
    private void RemoveMonitorMappingClick(object sender,RoutedEventArgs e)
    {
        if(!AdminAction()||MonitorGrid.SelectedItem is not MappingSnapshot row)return;
        if(MessageBox.Show(this,$"{row.Nic} → {row.Profile} 매칭을 해제할까요? PCAP 원본은 유지됩니다.","매칭 해제",MessageBoxButton.YesNo)!=MessageBoxResult.Yes)return;
        SaveChange(next=>{foreach(var binding in next.Bindings.Where(b=>b.DeviceId==row.DeviceId))binding.ProfileIds.Remove(row.ProfileId);next.Bindings.RemoveAll(b=>b.ProfileIds.Count==0);});
    }
    private void ClearPcapSelectionClick(object sender,RoutedEventArgs e){if(!busy){ConvertInputBox.Clear();ConversionResultText.Text="PCAP 선택을 해제했습니다. 원본 파일은 유지됩니다.";}}
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
            PermissionNote.Text=admin?"전체 설정과 기록을 관리할 수 있습니다.":"모든 PCAP 기록이 가능합니다.\nICD별 CSV 변환은 제한됩니다.\n인터페이스 수정은 관리자 전용입니다.";
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
    private void ShowError(Exception error){StatusText.Text=error.Message;MessageBox.Show(this,error.Message,"DRAS",MessageBoxButton.OK,MessageBoxImage.Warning);}
    private void SaveChange(Action<WorkspaceSettings> change)
    {
        if(!AdminAction())return;
        try {var next=IcdProtection.CloneForAdmin(session!,settings);change(next);store.Save(session!,next);engine.ClearHistory();settings.ClearPlaintext();settings=next;ReloadEditors();UpdateDashboard();StatusText.Text="설정 저장 완료 · Windows 사용자별 암호화된 숨김 바이너리";}
        catch(Exception error){ShowError(error);}
    }
    private void ReloadEditors(){ProfilesList.ItemsSource=session?.Role==UserRole.Admin?settings.Profiles:null;BindingProfiles.ItemsSource=session?.Role==UserRole.Admin?settings.Profiles:null;FolderBox.Text=settings.OutputDirectory;OutputText.Text="기록 폴더: "+settings.OutputDirectory;NewEditor();}
    private void ShowPage(string name)
    {
        if((name=="profiles"||name=="settings")&&(session?.Role!=UserRole.Admin||engine.IsRunning||busy))return;
        DashboardView.Visibility=name=="dashboard"?Visibility.Visible:Visibility.Collapsed;
        ConversionView.Visibility=name=="conversion"?Visibility.Visible:Visibility.Collapsed;
        ProfilesView.Visibility=name=="profiles"?Visibility.Visible:Visibility.Collapsed;
        SettingsView.Visibility=name=="settings"?Visibility.Visible:Visibility.Collapsed;
        UpdateNavColors(name);
        PageTitle.Text=name=="conversion"?"PCAP → CSV 변환":name=="profiles"?"인터페이스 관리":name=="settings"?"기록 설정":"기록 대시보드";
    }
    private void DashboardClick(object sender,RoutedEventArgs e){if(!busy)ShowPage("dashboard");}
    private void ProfilesClick(object sender,RoutedEventArgs e){if(AdminAction())ShowPage("profiles");}
    private void SettingsClick(object sender,RoutedEventArgs e){if(AdminAction())ShowPage("settings");}
    private void NewEditor(){editingProfileId=null;ProfileNameBox.Text="";SenderBox.Text="";ReceiverBox.Text="";selectedIcd=[];selectedIcdName="";selectedStructs=[];ByteOrderBox.SelectedIndex=0;StructPackBox.SelectedIndex=0;StructBitBox.SelectedIndex=0;IcdEnabledBox.IsChecked=true;IcdText.Text="선택된 CSV 없음";currentSchema=null;IcdFields.ItemsSource=null;DecodeGrid.ItemsSource=null;MessageBoxSelect.ItemsSource=null;WriteFieldBox.ItemsSource=null;WriteValueBox.Text="0";WriteRawBox.IsChecked=false;BothDirectionsBox.IsChecked=true;GuestIcdAllowedBox.IsChecked=false;}
    private void NewProfileClick(object sender,RoutedEventArgs e){if(AdminAction()){ProfilesList.SelectedItem=null;NewEditor();}}
    private void ProfileSelected(object sender,SelectionChangedEventArgs e)
    {
        if(ProfilesList.SelectedItem is not RecordProfile p)return;
        editingProfileId=p.Id;ProfileNameBox.Text=p.Name;SenderBox.Text=string.Join(", ",p.SenderIps);ReceiverBox.Text=string.Join(", ",p.ReceiverIps);selectedIcd=p.IcdContent;selectedIcdName=p.IcdName;selectedStructs=p.StructSources.Select(x=>new StructSource(x.Name,[..x.Content])).ToList();ByteOrderBox.SelectedIndex=p.ByteOrder=="be"?1:p.ByteOrder=="le"?2:0;StructPackBox.SelectedIndex=Array.IndexOf(new[]{1,2,4,8},p.StructPack);StructBitBox.SelectedIndex=p.StructBitOrder=="msb0"?1:0;IcdEnabledBox.IsChecked=p.Enabled;BothDirectionsBox.IsChecked=p.BothDirections;GuestIcdAllowedBox.IsChecked=settings.GuestIcdAllowList.Contains(p.IcdId);UpdateIcdPreview();
    }
    private IcdSchema? currentSchema;
    private void UpdateIcdPreview()
    {
        currentSchema=null;IcdFields.ItemsSource=null;DecodeGrid.ItemsSource=null;MessageBoxSelect.ItemsSource=null;
        try {
            if(selectedIcd.Length==0){IcdText.Text="선택된 CSV 없음 · 헤더 "+selectedStructs.Count+"개";return;}
            if(!selectedIcdName.EndsWith(".csv",StringComparison.OrdinalIgnoreCase))throw new ArgumentException("기존 IDL 원본을 유지합니다. CSV로 다시 선택한 후 저장하세요.");
            currentSchema=IcdCsv.Parse(selectedIcd,SelectedByteOrder,selectedStructs,SelectedPack,SelectedBitOrder);IcdFields.ItemsSource=currentSchema.Fields;MessageBoxSelect.ItemsSource=currentSchema.Messages;MessageBoxSelect.SelectedIndex=0;
            IcdText.Text=$"{selectedIcdName} · {currentSchema.Fields.Count} fields / {currentSchema.Messages.Length} messages · {currentSchema.EncodingName} · {SelectedByteOrder.ToUpperInvariant()} · 헤더 {selectedStructs.Count}개";
            if(currentSchema.Warnings.Count>0)IcdText.Text+="\n"+string.Join(" / ",currentSchema.Warnings);
        }catch(ArgumentException error){IcdText.Text="CSV 오류: "+error.Message;}
    }
    private void WriteMessageSelected(object sender,SelectionChangedEventArgs e)
    {
        if(WriteFieldBox==null)return;WriteFieldBox.ItemsSource=currentSchema?.Fields.Where(f=>f.Message==MessageBoxSelect.SelectedItem as string).ToList();WriteFieldBox.SelectedIndex=0;
    }
    private void WriteFieldClick(object sender,RoutedEventArgs e)
    {
        if(!AdminAction())return;
        try {
            if(currentSchema==null||MessageBoxSelect.SelectedItem is not string message||WriteFieldBox.SelectedItem is not IcdField field)throw new ArgumentException("정상 CSV와 쓰기 필드를 선택하세요.");
            var hex=new string(PayloadHexBox.Text.Where(c=>!char.IsWhiteSpace(c)).ToArray());if(hex.Length>65535*2)throw new ArgumentException("payload는 최대 65,535 bytes입니다.");
            var bytes=hex.Length==0?new byte[currentSchema.RequiredBytes(message)]:Convert.FromHexString(hex);currentSchema.WriteValue(message,field.Name,WriteValueBox.Text,bytes,WriteRawBox.IsChecked==true);
            PayloadHexBox.Text=string.Join(" ",bytes.Select(b=>b.ToString("X2")));DecodeGrid.ItemsSource=currentSchema.Decode(message,bytes);StatusText.Text="선택 필드 값 쓰기 완료 · 다른 비트 보존 · 네트워크 송신 없음";
        }catch(Exception error) when(error is ArgumentException or FormatException or OverflowException){ShowError(error);}
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
    private string SelectedByteOrder=>ByteOrderBox.SelectedIndex==1?"be":ByteOrderBox.SelectedIndex==2?"le":"csv";
    private int SelectedPack=>new[]{1,2,4,8}[Math.Max(0,StructPackBox.SelectedIndex)];
    private string SelectedBitOrder=>StructBitBox.SelectedIndex==1?"msb0":"lsb0";
    private void IcdOptionChanged(object sender,SelectionChangedEventArgs e){if(IcdText!=null&&StructBitBox!=null&&StructPackBox!=null)UpdateIcdPreview();}
    private void ExportIcdClick(object sender,RoutedEventArgs e)=>ExportIcd(ExportFormatBox.SelectedIndex);
    private void ExportIcd(int format)
    {
        if(!AdminAction())return;
        try {
            // Export the current editor, including selected but not yet saved definitions/options.
            var p=new RecordProfile{IcdName=selectedIcdName,IcdContent=selectedIcd,StructSources=selectedStructs,ByteOrder=SelectedByteOrder,StructPack=SelectedPack,StructBitOrder=SelectedBitOrder,Enabled=IcdEnabledBox.IsChecked==true};
            bool package=format==2,structure=format==1;string extension=package?".zip":structure?".hpp":".csv";
            var bytes=package?IcdExport.Package(session!,p):structure?IcdExport.Struct(session!,p):IcdExport.Csv(session!,p);
            try {
                var d=new SaveFileDialog{Title="ICD 내보내기",Filter=package?"ICD package (*.zip)|*.zip":structure?"C++ struct (*.hpp)|*.hpp":"CSV UTF-8 (*.csv)|*.csv",DefaultExt=extension,FileName=package?"icd-export.zip":structure?"icd-struct.hpp":"icd-edit.csv",AddExtension=true,OverwritePrompt=true};
                if(d.ShowDialog(this)!=true)return;
                if(!Path.GetExtension(d.FileName).Equals(extension,StringComparison.OrdinalIgnoreCase))throw new ArgumentException("내보내기 확장자를 확인하세요.");
                var temp=d.FileName+"."+Guid.NewGuid().ToString("N")+".tmp";
                try{File.WriteAllBytes(temp,bytes);File.Move(temp,d.FileName,true);}finally{if(File.Exists(temp))File.Delete(temp);}
                StatusText.Text="ICD 내보내기 완료 · 평문 파일: "+d.FileName;
            }finally{System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);}
        }catch(Exception error){ShowError(error);}
    }
    private void ChooseStructClick(object sender,RoutedEventArgs e){if(!AdminAction())return;var d=new OpenFileDialog{Filter="C/C++ headers|*.h;*.hpp",Multiselect=true};if(d.ShowDialog(this)!=true)return;try{if(d.FileNames.Length>128||d.FileNames.Sum(f=>new FileInfo(f).Length)>16*1024*1024)throw new ArgumentException("헤더는 128개 / 합계 16 MB 이하로 선택하세요.");var items=d.FileNames.Select(f=>new StructSource(Path.GetFileName(f),File.ReadAllBytes(f))).ToList();CStructParser.Parse(items,SelectedPack,SelectedByteOrder=="le"?"le":"be",SelectedBitOrder);selectedStructs=items;UpdateIcdPreview();}catch(Exception error){ShowError(error);}}
    private void ClearStructClick(object sender,RoutedEventArgs e){if(!AdminAction())return;selectedStructs=[];UpdateIcdPreview();}
    private void ReloadIcdClick(object sender,RoutedEventArgs e){if(!AdminAction())return;try{var loaded=store.Load(session!);settings.ClearPlaintext();settings=loaded;ReloadEditors();UpdateDashboard();NewEditor();StatusText.Text="암호화 저장소의 ICD 목록을 다시 읽었습니다.";}catch(Exception error){ShowError(error);}}
    private void ChooseIcdClick(object sender,RoutedEventArgs e)
    {
        if(!AdminAction())return;
        var d=new OpenFileDialog {Title="IDLStudio CSV ICD 선택",Filter="IDLStudio CSV (*.csv)|*.csv"};
        if(d.ShowDialog()!=true)return;
        try{var info=new FileInfo(d.FileName);if(info.Length==0||info.Length>16*1024*1024)throw new ArgumentException("ICD는 1 byte ~ 16 MB이어야 합니다.");var bytes=File.ReadAllBytes(d.FileName);selectedIcd=bytes;selectedIcdName=info.Name;UpdateIcdPreview();}catch(Exception error){ShowError(error);}
    }
    private void UseSampleClick(object sender,RoutedEventArgs e){if(!AdminAction())return;var sample=settings.Profiles.FirstOrDefault(p=>p.Name=="인터페이스 "+(char)('A'+SampleBox.SelectedIndex));if(sample==null){ShowError(new ArgumentException("초기 샘플이 없습니다. CSV를 가져오세요."));return;}selectedIcdName=sample.IcdName;selectedIcd=[..sample.IcdContent];UpdateIcdPreview();}
    private static List<string> ParseIps(string text)=>text.Split([',',';','\r','\n',' ','\t'],StringSplitOptions.RemoveEmptyEntries).Select(x=>IPAddress.TryParse(x,out var ip)?ip.ToString():x).Distinct().ToList();
    private void SaveProfileClick(object sender,RoutedEventArgs e)
    {
        if(!AdminAction())return;
        try {
            var p=new RecordProfile {Id=editingProfileId??Guid.NewGuid().ToString("N"),Name=ProfileNameBox.Text.Trim(),IcdName=selectedIcdName,IcdContent=[..selectedIcd],StructSources=selectedStructs.Select(x=>new StructSource(x.Name,[..x.Content])).ToList(),ByteOrder=SelectedByteOrder,StructPack=SelectedPack,StructBitOrder=SelectedBitOrder,Enabled=IcdEnabledBox.IsChecked==true,SenderIps=ParseIps(SenderBox.Text),ReceiverIps=ParseIps(ReceiverBox.Text),BothDirections=BothDirectionsBox.IsChecked==true};p.Validate();IcdProtection.Seal(session!,p);var allowGuest=GuestIcdAllowedBox.IsChecked==true;
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
    private CancellationTokenSource? conversionCancellation;
    private void ConversionClick(object sender,RoutedEventArgs e)
    {
        if(session==null||busy||engine.IsRunning)return;
        ConversionProfileBox.ItemsSource=settings.Profiles;ShowPage("conversion");
    }
    private void ChoosePcapClick(object sender,RoutedEventArgs e)
    {
        if(session==null||busy)return;var d=new OpenFileDialog{Title="변환할 PCAP 선택",Filter="PCAP (*.pcap)|*.pcap"};if(d.ShowDialog()==true)ConvertInputBox.Text=d.FileName;
    }
    private void ConversionProfileSelected(object sender,SelectionChangedEventArgs e)
    {
        ConversionMessageBox.ItemsSource=null;ConvertButton.IsEnabled=false;
        if(session==null||ConversionProfileBox.SelectedItem is not RecordProfile p)return;
        try{var fresh=File.Exists(store.FilePath)?store.Load(session):settings;try{ConversionMessageBox.ItemsSource=PcapCsvConverter.Messages(session,fresh,p.Id);ConversionMessageBox.SelectedIndex=0;ConversionAccessText.Text="CSV 값 변환 허용 · ICD 원본/구조 편집은 관리자 전용";ConvertButton.IsEnabled=!busy;}finally{if(!ReferenceEquals(fresh,settings))fresh.ClearPlaintext();}}
        catch(Exception error){ConversionAccessText.Text=error.Message;}
    }
    private async void ConvertClick(object sender,RoutedEventArgs e)
    {
        if(session==null||busy||engine.IsRunning||ConversionProfileBox.SelectedItem is not RecordProfile p||ConversionMessageBox.SelectedItem is not string message)return;
        if(!File.Exists(ConvertInputBox.Text)){ShowError(new ArgumentException("PCAP 파일을 선택하세요."));return;}
        var dialog=new SaveFileDialog{Title="변환 CSV 저장",Filter="CSV (*.csv)|*.csv",FileName=Path.GetFileNameWithoutExtension(ConvertInputBox.Text)+"_values.csv"};if(dialog.ShowDialog()!=true)return;
        var input=ConvertInputBox.Text;busy=true;ConvertButton.IsEnabled=false;CancelConvertButton.IsEnabled=true;ConversionProfileBox.IsEnabled=false;conversionCancellation=new();UpdateControls();
        try{var fresh=File.Exists(store.FilePath)?store.Load(session):settings;try{var result=await Task.Run(()=>PcapCsvConverter.Convert(session,fresh,p.Id,message,input,dialog.FileName,conversionCancellation.Token));ConversionResultText.Text=$"변환 완료: {result.Rows:N0}행 · 전체 {result.Frames:N0}프레임 · 제외 {result.Skipped:N0}개 · 해석 오류 행 {result.RowsWithErrors:N0}개\n{dialog.FileName}";}finally{if(!ReferenceEquals(fresh,settings))fresh.ClearPlaintext();}}
        catch(OperationCanceledException){ConversionResultText.Text="변환을 취소했습니다. 미완료 CSV는 남기지 않습니다.";}
        catch(Exception error){ShowError(error);}
        finally{conversionCancellation.Dispose();conversionCancellation=null;busy=false;CancelConvertButton.IsEnabled=false;ConversionProfileBox.IsEnabled=true;UpdateControls();ConversionProfileSelected(this,new SelectionChangedEventArgs(System.Windows.Controls.Primitives.Selector.SelectionChangedEvent,Array.Empty<object>(),Array.Empty<object>()));}
    }
    private void CancelConvertClick(object sender,RoutedEventArgs e)=>conversionCancellation?.Cancel();
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
        try{await Task.Run(engine.Stop);elapsed=DateTime.UtcNow-startedAt;StatusText.Text=engine.LastError.Length>0?engine.LastError:"기록 중지 · 파일 저장 완료";SessionText.Text="시험 폴더: "+engine.SessionDirectory+("\n"+engine.DriverSummary);}
        catch(Exception error){ShowError(error);}finally{busy=false;UpdateControls();UpdateDashboard();}
    }
    private async void StopClick(object sender,RoutedEventArgs e){if(session!=null&&engine.IsRunning)await StopRecording();}
    private void UpdateControls()
    {
        bool active=engine.IsRunning;
        StartButton.IsEnabled=session!=null&&!active&&!busy&&settings.Bindings.Count>0;
        StopButton.IsEnabled=active&&!busy;TestNameBox.IsEnabled=!active&&!busy;
        ProfileNav.IsEnabled=SettingsNav.IsEnabled=ConvertNav.IsEnabled=!active&&!busy;
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
        if(session==null)return;var snapshots=engine.Snapshot();
        if(snapshots.Count==0)snapshots=settings.Bindings.SelectMany(b=>b.ProfileIds.Select(id=>new MappingSnapshot(b.DeviceName,settings.Profiles.FirstOrDefault(p=>p.Id==id)?.Name??"삭제된 프로파일",0,0,0,0,0,"—",nics.Any(n=>n.Id==b.DeviceId&&n.Capturable)?"대기":"NIC 없음",b.DeviceId,id))).ToList();
        MonitorGrid.ItemsSource=snapshots;MappingTotal.Text=snapshots.Count.ToString();PacketTotal.Text=engine.ObservedFrames.ToString("N0");ByteTotal.Text=FormatBytes(engine.RecordedBytes);
        ElapsedText.Text=(engine.IsRunning?DateTime.UtcNow-startedAt:elapsed).ToString(@"hh\:mm\:ss");
        if(engine.IsRunning)SessionText.Text=$"시험 폴더: {engine.SessionDirectory}\nNIC 관측 프레임: {engine.ObservedFrames:N0} · 해석 실패: {engine.ParseFailures:N0} · NIC별 전체 프레임 PCAP 기록";
        UpdateControls();
    }
    private static string FormatBytes(long value)=>value>=1048576?$"{value/1048576.0:F2} MB":value>=1024?$"{value/1024.0:F2} KB":$"{value} B";
    private async void LogoutClick(object sender,RoutedEventArgs e)
    {
        if(busy)return;
        if(engine.IsRunning){if(MessageBox.Show(this,"기록을 중지하고 로그아웃할까요?","로그아웃",MessageBoxButton.YesNo)!=MessageBoxResult.Yes)return;await StopRecording();}
        timer.Stop();settings.ClearPlaintext();NewEditor();ConversionProfileBox.ItemsSource=null;ConversionMessageBox.ItemsSource=null;ConversionAccessText.Text="";ConversionResultText.Text="";ProfilesList.ItemsSource=null;BindingProfiles.ItemsSource=null;session?.Dispose();session=null;WorkspaceView.Visibility=Visibility.Collapsed;LoginView.Visibility=Visibility.Visible;UserIdBox.Clear();PasswordInput.Clear();LoginError.Text="";UserIdBox.Focus();
    }
    private void WindowClosing(object? sender,CancelEventArgs e)
    {
        if(busy){e.Cancel=true;return;}
        if(engine.IsRunning&&MessageBox.Show(this,"기록을 중지하고 종료할까요?","종료",MessageBoxButton.YesNo)!=MessageBoxResult.Yes){e.Cancel=true;return;}
        timer.Stop();engine.Dispose();settings.ClearPlaintext();session?.Dispose();
    }
}
