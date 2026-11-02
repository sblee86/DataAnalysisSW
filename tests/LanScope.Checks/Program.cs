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
if(args.Contains("--prepare-resources")) {
 var names=new[]{"Telemetry.csv","ControlCommand.csv","StatusReport.csv"};
 var directory=Path.Combine(root,"src/LanScope/Resources");
 File.WriteAllBytes(Path.Combine(directory,"policy-public.bin"),IcdProtection.PublicKey(admin!));
 File.WriteAllBytes(Path.Combine(directory,"guest-conversion-public.bin"),GuestIcdAccess.PublicKey(guest!));
 using var writer=new BinaryWriter(File.Create(Path.Combine(directory,"samples.bin")),Encoding.UTF8);
 writer.Write(3);
 for(int i=0;i<names.Length;i++) {
  var profile=new RecordProfile{Id=(i+1).ToString().PadLeft(32,'0'),Name="인터페이스 "+(char)('A'+i),IcdName=names[i],IcdContent=File.ReadAllBytes(Path.Combine(root,"samples",names[i])),SenderIps=["192.0.2.10"],ReceiverIps=["198.51.100.20"]};
  IcdProtection.Seal(admin!,profile);writer.Write(profile.Id);writer.Write(profile.Name);writer.Write(profile.IcdId);writer.Write(profile.EncryptedIcd.Length);writer.Write(profile.EncryptedIcd);profile.ClearPlaintext();
 }
 Console.WriteLine("Prepared encrypted sample resources and public policy verification key");return;
}
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
  var store=new SettingsStore(path,IcdProtection.PublicKey(admin!),GuestIcdAccess.PublicKey(guest!));store.Save(admin!,settings);var loaded=store.Load(admin!);
  Check(loaded.Profiles.Single().IcdContent.SequenceEqual(p.IcdContent)&&loaded.Bindings.Single().ProfileIds.Single()==p.Id,"Windows DPAPI configuration round-trip");
  Check(File.GetAttributes(path).HasFlag(FileAttributes.Hidden),"Windows settings hidden attribute");
  Check(!Encoding.UTF8.GetString(File.ReadAllBytes(path)).Contains(p.Name),"Windows settings plaintext concealed");
  store.Save(admin!,settings);Check(store.Load(admin!).Profiles.Count==1,"atomic settings replacement");
 }finally{if(File.Exists(path))File.Delete(path);}
}else Console.WriteLine("SKIP: four Windows DPAPI/hidden-file checks (Linux host)");
void Denied(Action action,string label){try{action();}catch(UnauthorizedAccessException){Check(true,label);return;}throw new Exception("FAIL: "+label);}
void CryptoRejected(Action action,string label){try{action();}catch(System.Security.Cryptography.CryptographicException){Check(true,label);return;}throw new Exception("FAIL: "+label);}
IcdProtection.Seal(admin!,p);var originalCsv=p.IcdContent.ToArray();var originalName=p.IcdName;
Check(p.EncryptedIcd.AsSpan().IndexOf(originalCsv)<0&&!Encoding.UTF8.GetString(p.EncryptedIcd).Contains(originalName),"AES envelope contains no CSV source or filename");
var serialized=System.Text.Json.JsonSerializer.Serialize(p);
Check(!serialized.Contains("IcdContent")&&!serialized.Contains("IcdName")&&!serialized.Contains(originalName),"configuration serialization omits all plaintext ICD properties");
p.ClearPlaintext();IcdProtection.Open(admin!,p);Check(p.IcdContent.SequenceEqual(originalCsv)&&p.IcdName==originalName,"admin decrypts authenticated ICD envelope");
Denied(()=>IcdProtection.Open(guest!,p),"guest cannot decrypt ICD through vault service");
Denied(()=>IcdProtection.Seal(guest!,p),"guest cannot replace encrypted ICD");
var bad=p.EncryptedIcd.ToArray();bad[^1]^=1;CryptoRejected(()=>IcdProtection.Decrypt(admin!,"profile:"+p.Id,bad),"tampered encrypted ICD rejected");
CryptoRejected(()=>IcdProtection.Decrypt(admin!,"profile:"+Guid.NewGuid().ToString("N"),p.EncryptedIcd),"ciphertext copied to another profile rejected by authenticated binding");
using(var wrongKey=new LoginSession("test-admin",UserRole.Admin,System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)))CryptoRejected(()=>IcdProtection.Decrypt(wrongKey,"profile:"+p.Id,p.EncryptedIcd),"wrong admin key rejected");
var publicKey=IcdProtection.PublicKey(admin!);var policy=Encoding.UTF8.GetBytes("allowed ICD policy");var signature=IcdProtection.Sign(admin!,policy);IcdProtection.Verify(publicKey,policy,signature);Check(true,"guest policy independently verifies with public key");
policy[0]^=1;CryptoRejected(()=>IcdProtection.Verify(publicKey,policy,signature),"policy allowlist tampering rejected");
Denied(()=>IcdProtection.Sign(guest!,policy),"guest cannot sign a forged permission policy");
Check(settings.ForSession(guest!).Profiles.Count==1&&settings.ForSession(guest!).Bindings.Count==1,"guest records all configured interfaces with no CSV grants");
settings.GuestIcdAllowList.Add(p.IcdId);var guestView=settings.ForSession(guest!);
Check(guestView.Profiles.Count==1&&guestView.Bindings.Single().ProfileIds.Single()==p.Id,"guest recording retains all profile and NIC mappings");
Check(guestView.Profiles[0].IcdContent.Length==0&&guestView.Profiles[0].IcdName=="","guest view never carries decrypted ICD or filename");
var hidden=new RecordProfile{Name="Hidden ICD",IcdName="Hidden.csv",IcdContent=Encoding.UTF8.GetBytes("name,byte_offset,bit_length,type\nsecret,0,8,uint"),SenderIps=["203.0.113.1"],ReceiverIps=["203.0.113.2"]};IcdProtection.Seal(admin!,hidden);settings.Profiles.Add(hidden);settings.Bindings[0].ProfileIds.Add(hidden.Id);
Check(settings.ForSession(guest!).Profiles.Any(x=>x.Id==hidden.Id),"CSV-restricted interface remains visible for PCAP recording");
hidden.SenderIps=[..p.SenderIps];hidden.ReceiverIps=[..p.ReceiverIps];
Check(settings.HasGuestConversionConflict(p.Id),"same-endpoint mixed ICDs affect CSV conversion only");
Throws(()=>new CaptureEngine().Start(guest!,settings,[],"Unavailable"),"guest capture checks NIC availability, not CSV permissions");
settings.GuestIcdAllowList.Remove(p.IcdId);Check(settings.ForSession(guest!).Profiles.Count==2,"revoking CSV grant does not hide or disable PCAP recording");
var held=p.IcdContent;p.ClearPlaintext();Check(held.All(b=>b==0),"plaintext buffer is zeroed when clearing workspace");IcdProtection.Open(admin!,p);
using(var expired=auth.Login("admin",Environment.GetEnvironmentVariable("LANSCOPE_TEST_ADMIN")!)!){expired.Dispose();Denied(()=>IcdProtection.Sign(expired,policy),"logout/disposed session cannot use admin key");}
var manifestDirectory=Path.Combine(Path.GetTempPath(),"lanscope-manifest-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(manifestDirectory);
try {
 settings.GuestIcdAllowList.Add(p.IcdId);var permitted=settings.ForSession(guest!);CaptureEngine.WriteManifest(manifestDirectory,guest!,permitted,"Test");
 var manifest=File.ReadAllBytes(Path.Combine(manifestDirectory,"session.bin"));
 Check(manifest.AsSpan().IndexOf(originalCsv)<0&&!Encoding.UTF8.GetString(manifest).Contains(originalName),"session metadata excludes ICD source, CSV filename (recording includes all interface aliases)");
}finally{Directory.Delete(manifestDirectory,true);}
var legacyDirectory=Path.Combine(Path.GetTempPath(),"lanscope-legacy-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(legacyDirectory);
try {
 var path=Path.Combine(legacyDirectory,"session.bin");using(var writer=new BinaryWriter(File.Create(path))){writer.Write("LANSCOPE-SESSION-1");writer.Write(originalCsv);}
 var legacyBytes=File.ReadAllBytes(path);Denied(()=>LegacySessionProtection.ProtectFolder(guest!,legacyDirectory),"guest cannot migrate or decrypt legacy ICD metadata");
 var result=LegacySessionProtection.ProtectFolder(admin!,legacyDirectory);var protectedBytes=File.ReadAllBytes(path);
 Check(result.Updated==1&&result.Errors.Count==0&&protectedBytes.AsSpan().IndexOf(originalCsv)<0,"legacy session plaintext ICD is encrypted in place");
 Check(IcdProtection.Decrypt(admin!,"legacy-session-metadata",protectedBytes).SequenceEqual(legacyBytes),"legacy metadata remains exactly recoverable by admin");
 Check(LegacySessionProtection.ProtectFolder(admin!,legacyDirectory).Updated==0,"legacy metadata encryption is repeatable without double wrapping");
}finally{Directory.Delete(legacyDirectory,true);}
var conversionDirectory=Path.Combine(Path.GetTempPath(),"lanscope-convert-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(conversionDirectory);
try {
 var convertProfile=new RecordProfile{Name="Convert A",IcdName="private.csv",IcdContent=Encoding.UTF8.GetBytes("name,byte_offset,bit_length,type\nvalue,0,8,uint"),SenderIps=["192.0.2.1"],ReceiverIps=["198.51.100.2"]};IcdProtection.Seal(admin!,convertProfile);
 var csvSettings=new WorkspaceSettings{OutputDirectory=conversionDirectory,Profiles=[convertProfile],Bindings=[new NicBinding{DeviceId="nic",DeviceName="NIC",ProfileIds=[convertProfile.Id]}]};
 string input=Path.Combine(conversionDirectory,"all.pcap"),csv=Path.Combine(conversionDirectory,"values.csv");
 var unrelated=frame.ToArray();unrelated[29]=99;
 var arp=Convert.FromHexString("FFFFFFFFFFFF00112233445508060001080006040001001122334455C0000201000000000000C0000202");
 using(var recording=new NicRecording(input,"NIC",LinkLayers.Ethernet,[convertProfile])) {
  recording.Write(new RawCapture(LinkLayers.Ethernet,new PosixTimeval(1700000000,1),frame));recording.Write(new RawCapture(LinkLayers.Ethernet,new PosixTimeval(1700000000,2),unrelated));recording.Write(new RawCapture(LinkLayers.Ethernet,new PosixTimeval(1700000000,3),arp));recording.Flush();
  Check(recording.Total.Packets==3&&recording.Snapshot("stopped").Single().Packets==1,"NIC PCAP includes matching, unrelated and ARP frames; interface counters remain separate");
 }
 using(var reader=new CaptureFileReaderDevice(input)){reader.Open();int count=0;while(reader.GetNextPacket(out _)==GetPacketStatus.PacketRead)count++;Check(count==3,"whole NIC standard PCAP contains every received frame");}
 Denied(()=>PcapCsvConverter.Messages(guest!,csvSettings,convertProfile.Id),"guest CSV conversion denied by default while recording remains available");
 Denied(()=>PcapCsvConverter.Convert(guest!,csvSettings,convertProfile.Id,"Default",input,csv),"conversion service rejects forbidden ICD before output creation");Check(!File.Exists(csv),"denied conversion leaves no CSV file");
 csvSettings.GuestIcdAllowList.Add(convertProfile.IcdId);GuestIcdAccess.Seal(admin!,convertProfile,GuestIcdAccess.PublicKey(guest!));
 Check(PcapCsvConverter.Messages(guest!,csvSettings,convertProfile.Id).SequenceEqual(new[]{"Default"}),"authorized guest can use encrypted ICD for conversion without admin key");
 var result=PcapCsvConverter.Convert(guest!,csvSettings.ForSession(guest!),convertProfile.Id,"Default",input,csv);var text=File.ReadAllText(csv);
 Check(result.Frames==3&&result.Rows==1&&result.Skipped==2&&text.Contains("\"84\""),"allowed guest PCAP to CSV decodes UDP value and skips unrelated/ARP frames");
 File.Delete(csv);csvSettings.GuestIcdAllowList.Clear();Denied(()=>PcapCsvConverter.Convert(guest!,csvSettings,convertProfile.Id,"Default",input,csv),"revoked CSV permission checked on each conversion");
 var adminResult=PcapCsvConverter.Convert(admin!,csvSettings,convertProfile.Id,"Default",input,csv);Check(adminResult.Rows==1,"admin converts all interfaces without guest grants");
 Throws(()=>PcapCsvConverter.Convert(admin!,csvSettings,convertProfile.Id,"Default",input,input),"conversion cannot overwrite original PCAP");
 File.Delete(csv);using var canceled=new CancellationTokenSource();canceled.Cancel();try{PcapCsvConverter.Convert(admin!,csvSettings,convertProfile.Id,"Default",input,csv,canceled.Token);throw new Exception("Cancellation ignored");}catch(OperationCanceledException){Check(!File.Exists(csv),"canceled conversion removes incomplete output");}
 Check(Directory.GetFiles(conversionDirectory,"*.tmp").Length==0,"conversion does not leave plaintext temporary files");
}finally{Directory.Delete(conversionDirectory,true);}
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
