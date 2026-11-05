using PacketDotNet;
using SharpPcap;
namespace LanScope;
internal sealed class NicRecording : IDisposable
{
    private sealed class Entry(RecordProfile profile,PacketHeaderMatcher? matcher,PcapFile? file)
    {
        internal readonly RecordProfile Profile=profile;internal readonly PacketHeaderMatcher? Matcher=matcher;internal readonly PcapFile? File=file;internal readonly PacketCounter Counter=new();
    }
    private readonly List<Entry> mappings=[];private readonly string nic,deviceId;
    internal PacketCounter Observed {get;}=new();internal PacketCounter Total {get;}=new();
    internal long ParseFailures {get;private set;}internal long Rejected {get;private set;}
    internal Dictionary<string,long> RejectionReasons {get;}=[];
    private void Reject(string reason){Rejected++;RejectionReasons[reason]=RejectionReasons.GetValueOrDefault(reason)+1;}
    internal static string ProfilePath(string path,int index)=>index==0?path:System.IO.Path.Combine(System.IO.Path.GetDirectoryName(path)!,System.IO.Path.GetFileNameWithoutExtension(path)+$"_profile{index+1:D2}.pcap");
    internal NicRecording(string path,string nic,LinkLayers linkType,IEnumerable<RecordProfile> profiles,string deviceId="")
    {
        this.nic=nic;this.deviceId=deviceId;int index=0;
        try{foreach(var p in profiles){if(p.Enabled&&p.CapturePolicy==null)throw new ArgumentException(p.Name+": 공통헤더 검증 규칙이 없습니다.");mappings.Add(new(p,p.Enabled?p.CapturePolicy!.CreateMatcher(p):null,p.Enabled?new PcapFile(ProfilePath(path,index),linkType):null));index++;}}
        catch{Dispose();throw;}
    }
    internal void Write(RawCapture raw)
    {
        Observed.Add(raw.Data.Length,raw.Timeval.Date.ToUniversalTime());var datagram=ValidatedDatagram.Read(raw);if(datagram==null){ParseFailures++;Reject("프레임/UDP 경계");return;}
        var results=mappings.Where(m=>m.Matcher!=null).Select(m=>(Entry:m,Result:m.Matcher!.Match(datagram.Source,datagram.Destination,datagram.Payload))).ToArray();var accepted=results.Where(m=>m.Result.Accepted).Select(m=>m.Entry).ToArray();
        if(accepted.Length!=1){var failure=results.Select(m=>m.Result.Failure).DefaultIfEmpty(PacketMatchFailure.ConfigurationMissing).Max();Reject(accepted.Length>1?"인터페이스 중복":failure switch{PacketMatchFailure.EndpointMismatch=>"IP/방향",PacketMatchFailure.AmbiguousMessage=>"동일 크기 메시지 모호",PacketMatchFailure.UnknownMessageId=>"메시지 ID",PacketMatchFailure.LengthMismatch=>"선언 Length",PacketMatchFailure.IcdSizeMismatch=>"ICD 크기",PacketMatchFailure.TruncatedHeader=>"헤더 잘림",_=>"미설정/미일치"});return;}
        var entry=accepted[0];entry.File!.Write(raw.Data,raw.Timeval.Seconds,raw.Timeval.MicroSeconds);entry.Counter.Add(raw.Data.Length,raw.Timeval.Date.ToUniversalTime());Total.Add(raw.Data.Length,raw.Timeval.Date.ToUniversalTime());
    }
    internal IEnumerable<MappingSnapshot> Snapshot(string state)=>mappings.Select(m=>new MappingSnapshot(nic,m.Profile.Name,m.Counter.Packets,m.Counter.Bytes,m.Counter.MinSize,m.Counter.MaxSize,m.Counter.Average,m.Counter.LastPacket?.ToLocalTime().ToString("HH:mm:ss.fff")??"—",m.Profile.Enabled?state:"ICD 비활성 · 제외",deviceId,m.Profile.Id));
    internal void Flush(){foreach(var m in mappings)m.File?.Flush();}
    public void Dispose(){foreach(var m in mappings)m.File?.Dispose();}
}
