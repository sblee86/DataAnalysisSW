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
var p=new RecordProfile {Name="Telemetry",IcdName="Telemetry.csv",IcdContent=File.ReadAllBytes(Path.Combine(root,"samples/Telemetry.csv")),SenderIps=["192.0.2.1"],ReceiverIps=["198.51.100.2"]};p.Validate();
Check(p.Matches(IPAddress.Parse("192.0.2.1"),IPAddress.Parse("198.51.100.2")),"forward matching");
Check(p.Matches(IPAddress.Parse("198.51.100.2"),IPAddress.Parse("192.0.2.1")),"reverse matching");
p.BothDirections=false;Check(!p.Matches(IPAddress.Parse("198.51.100.2"),IPAddress.Parse("192.0.2.1")),"unidirectional rejects response");
Check(!p.Matches(IPAddress.Parse("192.0.2.100"),IPAddress.Parse("198.51.100.2")),"unrelated packet rejected");
var v6=new RecordProfile {SenderIps=["2001:db8::1"],ReceiverIps=["2001:db8::2"]};Check(v6.Matches(IPAddress.Parse("2001:0db8:0:0:0:0:0:1"),IPAddress.Parse("2001:db8::2")),"IPv6 address normalization");
var invalid=new RecordProfile {Name="Bad",IcdName="Bad.csv",IcdContent=File.ReadAllBytes(Path.Combine(root,"samples/Telemetry.csv")),SenderIps=["bad-ip"],ReceiverIps=["198.51.100.2"]};Throws(invalid.Validate,"invalid endpoint rejected");
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
IcdSchema Parse(string csv)=>IcdCsv.Parse(Encoding.UTF8.GetBytes(csv));
string Header="message,name,byte_offset,bit_offset,bit_length,type,endian,bit_order,scale,bias,unit,description\n";
var telemetry=IcdCsv.Parse(File.ReadAllBytes(Path.Combine(root,"samples/Telemetry.csv")));
Check(telemetry.Fields.Count==6&&telemetry.RequiredBytes("Telemetry")==9,"CSV structure and required payload length");
var values=telemetry.Decode("Telemetry",Convert.FromHexString("0001B2FF9C41480000")).ToDictionary(f=>f.Name);
Check(values["sequence"].Value=="1"&&values["mode"].Value=="5"&&values["enabled"].Value=="true"&&values["status"].Value=="2","big-endian integer and MSB-numbered bit fields");
Check(decimal.Parse(values["temperature"].Value,System.Globalization.CultureInfo.InvariantCulture)==-10m&&values["voltage"].Value=="12.5","signed scale and big-endian IEEE float");
var control=IcdCsv.Parse(File.ReadAllBytes(Path.Combine(root,"samples/ControlCommand.csv"))).Decode("ControlCommand",Convert.FromHexString("0001B5A00064")).ToDictionary(f=>f.Name);
Check(control["channel"].Value=="346"&&decimal.Parse(control["target"].Value,System.Globalization.CultureInfo.InvariantCulture)==1m,"nine-bit cross-byte field");
var status=IcdCsv.Parse(File.ReadAllBytes(Path.Combine(root,"samples/StatusReport.csv"))).Decode("StatusReport",Convert.FromHexString("850000000112345678")).ToDictionary(f=>f.Name);
Check(status["healthy"].Value=="true"&&status["error_code"].Value=="5"&&status["device_id"].Value=="12345678","LSB numbering with big-endian communication and byte array");
var oneByte=Parse("name,byte_offset,bit_length,type\nvalue,0,8,uint");
bool unchanged=true;for(int i=0;i<256;i++)unchanged&=oneByte.Decode("Default",new byte[]{(byte)i})[0].Value==i.ToString();
Check(unchanged,"all 256 single-byte values remain unchanged");
Check(Parse("name,byte_offset,bit_length,type\nvalue,0,16,uint").Decode("Default",new byte[]{0x12,0x34})[0].Value=="4660","big endian is the default without endian column");
Throws(()=>Parse(Header+"M,x,0,0,16,uint,le,msb0,1,0,,no"),"little endian CSV rejected");
Check(Parse(Header+"M,x,0,4,8,uint,be,lsb0,1,0,,cross").Decode("M",new byte[]{0xab,0xcd})[0].Raw=="173","LSB-numbered cross-byte slice concatenation");
Check(Parse(Header+"M,x,0,4,8,uint,be,msb0,1,0,,cross").Decode("M",new byte[]{0xab,0xcd})[0].Raw=="188","MSB-numbered cross-byte slice concatenation");
Check(Parse("name,byte_offset,bit_length,type\nu,0,64,uint").Decode("Default",Enumerable.Repeat((byte)255,8).ToArray())[0].Raw=="18446744073709551615","unsigned 64-bit precision preserved");
Check(Parse("name,byte_offset,bit_length,type\ns,0,64,int").Decode("Default",Convert.FromHexString("8000000000000000"))[0].Raw=="-9223372036854775808","signed 64-bit minimum");
Check(Parse("name,byte_offset,bit_length,type\ns,0,3,int").Decode("Default",new byte[]{0xe0})[0].Raw=="-1","signed three-bit sign extension");
Check(telemetry.Decode("Telemetry",new byte[]{0,1}).Any(f=>f.Error.Contains("길이 부족")),"short payload produces per-field errors");
Throws(()=>Parse("name,byte_offset,type\nx,0,uint"),"missing CSV header rejected");
Throws(()=>Parse("name,byte_offset,bit_length,type\nx,0,65,uint"),"integer wider than 64 bits rejected");
Throws(()=>Parse("name,byte_offset,bit_length,type\nx,0,8,uint\ny,0,8,uint"),"overlapping physical bit ranges rejected");
Throws(()=>Parse("name,byte_offset,bit_length,type\nx,0,8,uint\nx,1,8,uint"),"duplicate field names rejected");
Throws(()=>Parse(Header+"M,x,0,7,32,float32,be,msb0,1,0,,float"),"unaligned float rejected");
Throws(()=>Parse("name,byte_offset,bit_length,type\nx,65535,8,uint"),"out-of-range byte offset rejected");
Throws(()=>Parse("name,byte_offset,bit_length,type\nx,0,8,uint,extra"),"mismatched column counts rejected");
Throws(()=>Parse("name,byte_offset,bit_length,type\n\"unfinished,0,8,uint"),"malformed CSV quotes rejected");
var quoted=Parse("name,byte_offset,bit_length,type,description\nvalue,0,8,uint,\"comma, quote \"\"ok\"\"\nsecond line\"");
Check(quoted.Fields[0].Description.Contains("comma, quote \"ok\"\nsecond line"),"RFC4180 comma, escaped quote and embedded newline");
var korean="필드명,바이트오프셋,비트수,자료형\n상태,0,8,uint";
Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
Check(IcdCsv.Parse(Encoding.GetEncoding(949).GetBytes(korean)).EncodingName=="CP949","CP949 Korean CSV import");
Check(IcdCsv.Parse(new byte[]{255,254}.Concat(Encoding.Unicode.GetBytes(korean)).ToArray()).Fields[0].Name=="상태","UTF16 BOM CSV import");
Check(Parse("name;byte_offset;bit_length;type\nx;0;8;uint").Fields.Count==1,"semicolon-delimited CSV");
Check(Parse("name\tbyte_offset\tbit_length\ttype\nx\t0\t8\tuint").Fields.Count==1,"tab-delimited export");
Check(Parse(Header+"M,x,0,0,8,uint,,,,,,").Fields[0].Endian=="be","blank optional columns use explicit defaults");
Console.WriteLine($"{checks} meaningful checks passed. Windows DPAPI/WPF/live NIC tests remain Windows-only.");
