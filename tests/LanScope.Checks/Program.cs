using System.Net;
using System.Reflection;
using System.Text;
using LanScope;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
int checks=0;
void Check(bool condition,string label) {if(!condition)throw new Exception("FAIL: "+label);checks++;Console.WriteLine("PASS: "+label);}
void Throws(Action action,string label) {try{action();}catch(ArgumentException){Check(true,label);return;}throw new Exception("FAIL: "+label);}
var root=Path.GetFullPath(args[0]);
var auth=new AccountService(File.ReadAllBytes(Path.Combine(root,"src/LanScope/Resources/accounts.bin")));
Check(auth.Login("admin","wrong")==null,"invalid password rejected");
Check(auth.Login("unknown","wrong")==null,"unknown user rejected");
// Tests accept passwords through named environment bindings; never log values.
var admin=auth.Login("admin",Environment.GetEnvironmentVariable("LANSCOPE_TEST_ADMIN")??"");
var guest=auth.Login("guest",Environment.GetEnvironmentVariable("LANSCOPE_TEST_GUEST")??"");
Check(admin?.Role==UserRole.Admin,"admin hash authentication");Check(guest?.Role==UserRole.Guest,"guest hash authentication");
try{guest!.RequireAdmin();throw new Exception("Guest elevated");}catch(UnauthorizedAccessException){Check(true,"guest configuration authorization denied");}
admin!.RequireAdmin();Check(true,"admin configuration authorization allowed");
var p=new RecordProfile {Name="Telemetry",IcdName="Telemetry.idl",IcdContent=Encoding.UTF8.GetBytes("module Sample {};"),SenderIps=["192.0.2.1"],ReceiverIps=["198.51.100.2"]};p.Validate();
Check(p.Matches(IPAddress.Parse("192.0.2.1"),IPAddress.Parse("198.51.100.2")),"forward matching");
Check(p.Matches(IPAddress.Parse("198.51.100.2"),IPAddress.Parse("192.0.2.1")),"reverse matching");
p.BothDirections=false;Check(!p.Matches(IPAddress.Parse("198.51.100.2"),IPAddress.Parse("192.0.2.1")),"unidirectional rejects response");
Check(!p.Matches(IPAddress.Parse("192.0.2.100"),IPAddress.Parse("198.51.100.2")),"unrelated packet rejected");
var v6=new RecordProfile {SenderIps=["2001:db8::1"],ReceiverIps=["2001:db8::2"]};Check(v6.Matches(IPAddress.Parse("2001:0db8:0:0:0:0:0:1"),IPAddress.Parse("2001:db8::2")),"IPv6 address normalization");
var invalid=new RecordProfile {Name="Bad",IcdName="Bad.idl",IcdContent=[1],SenderIps=["bad-ip"],ReceiverIps=["198.51.100.2"]};Throws(invalid.Validate,"invalid endpoint rejected");
var settings=new WorkspaceSettings {OutputDirectory=Path.GetTempPath(),Profiles=[p]};Throws(()=>settings.ValidateForRecording(["nic1"]),"no NIC mapping rejected");
settings.Bindings.Add(new NicBinding {DeviceId="nic1",DeviceName="Test NIC",ProfileIds=[]});Throws(()=>settings.ValidateForRecording(["nic1"]),"NIC requires at least one profile");
settings.Bindings[0].ProfileIds.Add(p.Id);settings.ValidateForRecording(["nic1"]);Check(true,"valid NIC mapping");
Throws(()=>settings.ValidateForRecording(["nic2"]),"disconnected NIC rejected");
settings.Bindings[0].ProfileIds.Add("missing");Throws(()=>settings.ValidateForRecording(["nic1"]),"stale profile ID rejected");settings.Bindings[0].ProfileIds.Remove("missing");
var counter=new PacketCounter();counter.Add(46,DateTime.UtcNow);counter.Add(90,DateTime.UtcNow);Check(counter.Packets==2&&counter.Bytes==136&&counter.MinSize==46&&counter.MaxSize==90&&counter.Average==68,"packet size statistics");
var frame=Convert.FromHexString("00112233445566778899AABB0800450000200000000040110000C0000201C633640230390035000C000054455354");
var output=Path.Combine(Path.GetTempPath(),"lanscope-check-"+Guid.NewGuid().ToString("N")+".pcap");
try {
 using(var file=new PcapFile(output,LinkLayers.Ethernet)){file.Write(frame,1700000000,123456);file.Flush();}
 using var reader=new CaptureFileReaderDevice(output);reader.Open();Check(reader.GetNextPacket(out var capture)==GetPacketStatus.PacketRead,"production PCAP readable by libpcap");var raw=capture.GetPacket();
 Check(raw.Data.SequenceEqual(frame)&&raw.Timeval.Seconds==1700000000&&raw.Timeval.MicroSeconds==123456,"PCAP exact bytes and timestamp");
 var packet=Packet.ParsePacket(raw.LinkLayerType,raw.Data);var ip=packet.Extract<IPPacket>();var udp=packet.Extract<UdpPacket>();
 Check(p.Matches(ip.SourceAddress,ip.DestinationAddress)&&udp.SourcePort==12345&&udp.DestinationPort==53&&Encoding.ASCII.GetString(udp.PayloadData)=="TEST","recorded packet matches profile and UDP payload");
 Check(reader.GetNextPacket(out _)==GetPacketStatus.NoRemainingPackets,"PCAP EOF");
}finally{File.Delete(output);}
// Session state is clean before any live device is opened.
var engine=new CaptureEngine();Check(engine.Snapshot().Count==0,"new session has no stale counters");engine.ClearHistory();engine.Dispose();
Check(File.ReadAllBytes(Path.Combine(root,"src/LanScope/Resources/accounts.bin")).AsSpan().IndexOf(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("LANSCOPE_TEST_ADMIN")!))<0,"account resource contains no plaintext password");
try {new SettingsStore().Save(guest!,settings);throw new Exception("Guest persisted settings");}catch(UnauthorizedAccessException){Check(true,"guest cannot write encrypted configuration service");}
if(OperatingSystem.IsWindows()) {
 var path=Path.Combine(Path.GetTempPath(),"lanscope-settings-"+Guid.NewGuid().ToString("N")+".bin");
 try {
  var store=new SettingsStore(path);store.Save(admin!,settings);var loaded=store.Load();
  Check(loaded.Profiles.Single().IcdContent.SequenceEqual(p.IcdContent)&&loaded.Bindings.Single().ProfileIds.Single()==p.Id,"Windows DPAPI configuration round-trip");
  Check(File.GetAttributes(path).HasFlag(FileAttributes.Hidden),"Windows settings hidden attribute");
  Check(!Encoding.UTF8.GetString(File.ReadAllBytes(path)).Contains(p.Name),"Windows settings plaintext concealed");
  store.Save(admin!,settings);Check(store.Load().Profiles.Count==1,"atomic settings replacement");
 }finally{if(File.Exists(path))File.Delete(path);}
}else Console.WriteLine("SKIP: four Windows DPAPI/hidden-file checks (Linux host)");
Console.WriteLine($"{checks} meaningful checks passed. Windows DPAPI/WPF/live NIC tests remain Windows-only.");
