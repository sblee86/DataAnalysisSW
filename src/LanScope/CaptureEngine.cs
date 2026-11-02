using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace LanScope;
public sealed record NicInfo(string Id,string Name,string Addresses,string State,bool Capturable)
{
    public override string ToString()=>$"{Name} · {Addresses} · {State}";
}
public static class NicDiscovery
{
    public static (List<NicInfo> Nics,List<LibPcapLiveDevice> Devices,string Warning) Scan()
    {
        var devices=new List<LibPcapLiveDevice>(); string warning="";
        try { CaptureDeviceList.Instance.Refresh();devices=CaptureDeviceList.Instance.OfType<LibPcapLiveDevice>().ToList(); }
        catch(Exception e) { warning="Npcap NIC 검색 실패: "+e.Message+". Windows에 Npcap을 설치하고 다시 검색하세요."; }
        var nics=new List<NicInfo>();
        foreach(var nic in NetworkInterface.GetAllNetworkInterfaces()) {
            var device=devices.FirstOrDefault(d=>d.Name.Contains(nic.Id.Trim('{','}'),StringComparison.OrdinalIgnoreCase));
            string ips;
            try {ips=string.Join(", ",nic.GetIPProperties().UnicastAddresses.Select(a=>a.Address).Where(a=>!a.IsIPv6LinkLocal));} catch {ips="조회 불가";}
            nics.Add(new(device?.Name??"os:"+nic.Id,nic.Name,ips,nic.OperationalStatus.ToString()+(device==null?" · 캡처 불가":""),device!=null));
        }
        foreach(var d in devices.Where(d=>nics.All(n=>n.Id!=d.Name))) nics.Add(new(d.Name,d.Description??d.Name,string.Join(", ",d.Addresses.Select(a=>a.Addr?.ToString())),"Npcap",true));
        return(nics,devices,warning);
    }
}
public sealed class CaptureEngine : IDisposable
{
    private readonly object gate=new();
    private readonly List<LibPcapLiveDevice> opened=[];
    private readonly Dictionary<string,NicRecording> recordings=[];
    public bool IsRunning {get;private set;}
    public string SessionDirectory {get;private set;}="";
    public string LastError {get;private set;}="";
    public string DriverSummary {get;private set;}="";
    public long ObservedFrames {get{lock(gate)return recordings.Values.Sum(r=>r.Total.Packets);}}
    public long RecordedBytes {get{lock(gate)return recordings.Values.Sum(r=>r.Total.Bytes);}}
    public long ParseFailures {get{lock(gate)return recordings.Values.Sum(r=>r.ParseFailures);}}
    public void Start(LoginSession session,WorkspaceSettings settings,List<LibPcapLiveDevice> available,string testName)
    {
        if(!Enum.IsDefined(session.Role))throw new UnauthorizedAccessException();
        if(IsRunning)throw new InvalidOperationException("이미 기록 중입니다.");
        settings=settings.ForSession(session);
        settings.ValidateForRecording(available.Select(d=>d.Name).ToList());
        if(string.IsNullOrWhiteSpace(testName)||testName.Length>80)throw new ArgumentException("시험 이름을 1~80자로 입력하세요.");
        if(testName.IndexOfAny(Path.GetInvalidFileNameChars())>=0 || testName.EndsWith('.') || testName.EndsWith(' '))throw new ArgumentException("시험 이름에는 파일명으로 사용할 수 있는 문자를 입력하세요.");
        recordings.Clear(); LastError="";DriverSummary="";
        SessionDirectory=Path.Combine(settings.OutputDirectory,DateTime.Now.ToString("yyyyMMdd_HHmmss")+"_"+testName+"_"+Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(SessionDirectory);
        try {
            foreach(var binding in settings.Bindings) {
                var device=available.Single(d=>d.Name==binding.DeviceId);
                opened.Add(device);
                device.Open(new DeviceConfiguration {Mode=DeviceModes.Promiscuous,ReadTimeout=250,Snaplen=65535});
                var profiles=binding.ProfileIds.Select(id=>settings.Profiles.Single(p=>p.Id==id)).ToList();
                recordings.Add(device.Name,new NicRecording(Path.Combine(SessionDirectory,$"nic{opened.Count:D2}.pcap"),binding.DeviceName,device.LinkType,profiles,device.Name));
                // No ICD/IP BPF: both roles persist ALL frames delivered by each selected NIC.
                device.OnPacketArrival+=PacketArrival;
            }
            WriteManifest(SessionDirectory,session,settings,testName);
            IsRunning=true;
            foreach(var device in opened)device.StartCapture();
        } catch { Stop(); throw; }
    }
    internal static void WriteManifest(string directory,LoginSession session,WorkspaceSettings settings,string name)
    {
        using var w=new BinaryWriter(File.Create(Path.Combine(directory,"session.bin")),Encoding.UTF8);
        w.Write("LANSCOPE-SESSION-3");w.Write(name);w.Write(DateTime.UtcNow.ToString("O"));w.Write(session.UserId);w.Write(settings.Bindings.Count);
        int index=0;
        foreach(var b in settings.Bindings) {
            index++;w.Write(b.DeviceId);w.Write(b.DeviceName);w.Write(b.ProfileIds.Count);
            foreach(var id in b.ProfileIds) {
                var p=settings.Profiles.Single(x=>x.Id==id);w.Write(p.Id);w.Write(p.Name);w.Write($"nic{index:D2}.pcap");
                w.Write(p.IcdId); // Reference only. No CSV filename, schema, raw ICD or encryption keys.
            }
        }
    }
    private void PacketArrival(object sender,PacketCapture e)
    {
        lock(gate) {
            if(!IsRunning||LastError.Length>0)return;
            try {
                recordings[((LibPcapLiveDevice)sender).Name].Write(e.GetPacket());
            } catch(Exception error) {LastError="패킷 기록 실패: "+error.Message;}
        }
    }
    public List<MappingSnapshot> Snapshot()
    {
        lock(gate) return recordings.Values.SelectMany(r=>r.Snapshot(LastError.Length>0?"오류":IsRunning?"기록 중":"중지")).ToList();
    }
    public void ClearHistory() { if(IsRunning)throw new InvalidOperationException("기록 중입니다.");lock(gate)recordings.Clear(); }
    public bool UnexpectedStop()=>IsRunning&&opened.Any(d=>!d.Started);
    public void Flush() { lock(gate) foreach(var r in recordings.Values)r.Flush(); }
    public void Stop()
    {
        // Stop outside gate: driver threads may be waiting to complete a callback.
        IsRunning=false;var reports=new List<string>();
        foreach(var d in opened) {
            try { if(d.Started)d.StopCapture(); } catch(Exception e){LastError="캡처 중지 실패: "+e.Message;}
            d.OnPacketArrival-=PacketArrival;
            try {reports.Add($"{d.Description}: {d.Statistics}");}catch{}
            try {d.Close();}catch(Exception e){LastError="장치 닫기 실패: "+e.Message;}
        }
        opened.Clear();DriverSummary=string.Join(" | ",reports);
        lock(gate) foreach(var r in recordings.Values)try{r.Dispose();}catch(Exception e){LastError="파일 닫기 실패: "+e.Message;}
    }
    public void Dispose()=>Stop();
}
