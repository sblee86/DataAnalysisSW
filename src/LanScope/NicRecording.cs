using PacketDotNet;
using SharpPcap;

namespace LanScope;
internal sealed class NicRecording(string path,string nic,LinkLayers linkType,IEnumerable<RecordProfile> profiles,string deviceId="") : IDisposable
{
    private readonly PcapFile file=new(path,linkType);
    private readonly List<(RecordProfile Profile,PacketCounter Counter)> mappings=profiles.Select(p=>(p,new PacketCounter())).ToList();
    internal PacketCounter Total {get;}=new();
    internal long ParseFailures {get;private set;}
    internal void Write(RawCapture raw)
    {
        // Persist before parsing/matching: ARP, unmatched IPs and malformed frames are retained too.
        file.Write(raw.Data,raw.Timeval.Seconds,raw.Timeval.MicroSeconds);Total.Add(raw.Data.Length,raw.Timeval.Date.ToUniversalTime());
        IPPacket? ip;try{ip=Packet.ParsePacket(raw.LinkLayerType,raw.Data).Extract<IPPacket>();}catch{ParseFailures++;return;}
        if(ip==null)return;
        foreach(var m in mappings.Where(m=>m.Profile.Matches(ip.SourceAddress,ip.DestinationAddress)))m.Counter.Add(raw.Data.Length,raw.Timeval.Date.ToUniversalTime());
    }
    internal IEnumerable<MappingSnapshot> Snapshot(string state)=>mappings.Select(m=>new MappingSnapshot(nic,m.Profile.Name,m.Counter.Packets,m.Counter.Bytes,m.Counter.MinSize,m.Counter.MaxSize,m.Counter.Average,m.Counter.LastPacket?.ToLocalTime().ToString("HH:mm:ss.fff")??"—",m.Profile.Enabled?state:"ICD 비활성 · PCAP 기록 유지",deviceId,m.Profile.Id));
    internal void Flush()=>file.Flush();
    public void Dispose()=>file.Dispose();
}
