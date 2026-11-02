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
Check(IcdProtection.PublicKey(admin!).SequenceEqual(File.ReadAllBytes(Path.Combine(root,"src/LanScope/Resources/policy-public.bin"))),"policy signing identity matches existing deployed public key");
Check(GuestIcdAccess.PublicKey(guest!).SequenceEqual(File.ReadAllBytes(Path.Combine(root,"src/LanScope/Resources/guest-conversion-public.bin"))),"guest conversion identity matches existing deployed public key");
using(var samples=new BinaryReader(File.OpenRead(Path.Combine(root,"src/LanScope/Resources/samples.bin")))) {
 int count=samples.ReadInt32();bool compatible=count==3;
 for(int i=0;i<count;i++){var sample=new RecordProfile{Id=samples.ReadString(),Name=samples.ReadString(),IcdId=samples.ReadString()};sample.EncryptedIcd=samples.ReadBytes(samples.ReadInt32());try{IcdProtection.Open(admin!,sample);compatible&=IcdCsv.Parse(sample.IcdContent).Fields.Count>0;}finally{sample.ClearPlaintext();}}
 Check(compatible,"encrypted resources from previous runtime remain decryptable on .NET 8");
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
var uiDirectory=Path.Combine(Path.GetTempPath(),"das-ui-"+Guid.NewGuid().ToString("N"));
try{var ui=new UiPreferences(Path.Combine(uiDirectory,"ui.bin"));Check(ui.LoadFontSize()==13,"default UI font size");ui.SaveFontSize(18);Check(ui.LoadFontSize()==18,"UI font size persists independently of role configuration");Throws(()=>ui.SaveFontSize(30),"UI font size bounds protect layout");}finally{if(Directory.Exists(uiDirectory))Directory.Delete(uiDirectory,true);}
IcdSchema Parse(string csv)=>IcdCsv.Parse(Encoding.UTF8.GetBytes(csv));
string Header="message,name,byte_offset,bit_offset,bit_length,type,endian,bit_order,scale,bias,unit,description\n";
var telemetry=IcdCsv.Parse(File.ReadAllBytes(Path.Combine(root,"samples/Telemetry.csv")));
Check(telemetry.Fields.Count==6&&telemetry.RequiredBytes("Telemetry")==9,"CSV structure and required payload length");
var values=telemetry.Decode("Telemetry",Convert.FromHexString("0001B2FF9C41480000")).ToDictionary(f=>f.Name);
Check(values["sequence"].Value=="1"&&values["mode"].Value=="5"&&values["enabled"].Value=="true"&&values["status"].Value=="2","big-endian integer and MSB-numbered bit fields");
Check(decimal.Parse(values["temperature"].Value,System.Globalization.CultureInfo.InvariantCulture)==-10m&&values["voltage"].Value=="12.5","signed scale and big-endian IEEE float");
var originalPayload=Convert.FromHexString("0001B2FF9C41480000");var edited=originalPayload.ToArray();telemetry.WriteValue("Telemetry","mode","3",edited);
Check(edited[2]==0x72&&edited.Where((b,i)=>i!=2).SequenceEqual(originalPayload.Where((b,i)=>i!=2)),"writing MSB bit field preserves sibling bits and other bytes");
Check(telemetry.Decode("Telemetry",edited).Single(f=>f.Name=="mode").Raw=="3","written bit field reads back");
telemetry.WriteValue("Telemetry","temperature","-12.3",edited);Check(edited[3]==0xff&&edited[4]==0x85,"engineering value inversely scales to signed BE bits");
telemetry.WriteValue("Telemetry","voltage","3.25",edited);Check(Convert.ToHexString(edited.AsSpan(5,4))=="40500000","float32 writes big-endian IEEE bits");
telemetry.WriteValue("Telemetry","enabled","false",edited);Check((edited[2]&0x10)==0&&(edited[2]&0x0f)==2,"boolean bit write preserves neighboring fields");
var beforeFailure=edited.ToArray();Throws(()=>telemetry.WriteValue("Telemetry","mode","8",edited),"bit field overflow rejected");Check(edited.SequenceEqual(beforeFailure),"invalid write leaves payload unchanged");
var controlSchema=IcdCsv.Parse(File.ReadAllBytes(Path.Combine(root,"samples/ControlCommand.csv")));var cross=Convert.FromHexString("0001B5A00064");controlSchema.WriteValue("ControlCommand","channel","511",cross);
Check(Convert.ToHexString(cross)=="0001BFF00064","nine-bit cross-byte write preserves operation/reserved bits");
var lsbWrite=Parse(Header+"M,x,0,4,8,uint,be,lsb0,1,0,,cross");var lsbPayload=new byte[]{0xab,0xcd};lsbWrite.WriteValue("M","x","18",lsbPayload);Check(Convert.ToHexString(lsbPayload)=="1BC2","LSB-numbered cross-byte write preserves surrounding nibbles");
var msbWrite=Parse(Header+"M,x,0,4,8,uint,be,msb0,1,0,,cross");var msbPayload=new byte[]{0xab,0xcd};msbWrite.WriteValue("M","x","18",msbPayload);Check(Convert.ToHexString(msbPayload)=="A12D","MSB-numbered cross-byte write preserves surrounding nibbles");
var signedWrite=Parse("name,byte_offset,bit_length,type\ns,0,3,int");var signedPayload=new byte[]{0x1f};signedWrite.WriteValue("Default","s","-4",signedPayload);Check(signedPayload[0]==0x9f&&signedWrite.Decode("Default",signedPayload)[0].Raw=="-4","signed sub-byte write/read with sign extension");
var wideWrite=Parse("name,byte_offset,bit_length,type\nu,0,64,uint");var widePayload=new byte[8];wideWrite.WriteValue("Default","u","18446744073709551615",widePayload);Check(widePayload.All(b=>b==255),"uint64 write retains full precision");
var zeroScale=Parse("name,byte_offset,bit_length,type,scale,bias\nx,0,8,uint,0,5");var zeroPayload=new byte[1];Throws(()=>zeroScale.WriteValue("Default","x","5",zeroPayload),"zero-scale engineering write rejected");zeroScale.WriteValue("Default","x","3",zeroPayload,true);Check(zeroPayload[0]==3,"raw write bypasses non-invertible engineering scale");
Throws(()=>telemetry.Encode("Telemetry",new Dictionary<string,string>{{"mode","3"},{"status","16"}},originalPayload),"multi-field encoder rejects invalid member");Check(originalPayload.SequenceEqual(Convert.FromHexString("0001B2FF9C41480000")),"multi-field encoding is transactional for caller input");
telemetry.WriteValue("Telemetry","voltage","1095237632",edited,true);Check(Convert.ToHexString(edited.AsSpan(5,4))=="41480000","float raw IEEE bits round-trip exactly");
bool bitRanges=true;
foreach(var order in new[]{"msb0","lsb0"})for(int offset=0;offset<8;offset++)for(int length=1;length<=64;length++) {
 var layout=Parse(Header+$"M,x,1,{offset},{length},uint,be,{order},1,0,,range");var buffer=Enumerable.Repeat((byte)0xa5,12).ToArray();ulong mask=length==64?ulong.MaxValue:(1UL<<length)-1;ulong number=mask&0xA55AA55AA55AA55AUL;
 layout.WriteValue("M","x",number.ToString(System.Globalization.CultureInfo.InvariantCulture),buffer,true);bitRanges&=layout.Decode("M",buffer)[0].Raw==number.ToString(System.Globalization.CultureInfo.InvariantCulture);
 var changed=new HashSet<int>();for(int bit=0;bit<length;bit++){int position=offset+bit;changed.Add((1+position/8)*8+(order=="lsb0"?position%8:7-position%8));}
 for(int bit=0;bit<buffer.Length*8;bit++)if(!changed.Contains(bit))bitRanges&=((buffer[bit/8]>>(bit%8))&1)==((0xa5>>(bit%8))&1);
}
Check(bitRanges,"all 1..64 bit widths and 0..7 offsets preserve non-field bits for both numbering orders");
var control=IcdCsv.Parse(File.ReadAllBytes(Path.Combine(root,"samples/ControlCommand.csv"))).Decode("ControlCommand",Convert.FromHexString("0001B5A00064")).ToDictionary(f=>f.Name);
Check(control["channel"].Value=="346"&&decimal.Parse(control["target"].Value,System.Globalization.CultureInfo.InvariantCulture)==1m,"nine-bit cross-byte field");
var status=IcdCsv.Parse(File.ReadAllBytes(Path.Combine(root,"samples/StatusReport.csv"))).Decode("StatusReport",Convert.FromHexString("850000000112345678")).ToDictionary(f=>f.Name);
Check(status["healthy"].Value=="true"&&status["error_code"].Value=="5"&&status["device_id"].Value=="12345678","LSB numbering with big-endian communication and byte array");
var oneByte=Parse("name,byte_offset,bit_length,type\nvalue,0,8,uint");
bool unchanged=true;for(int i=0;i<256;i++)unchanged&=oneByte.Decode("Default",new byte[]{(byte)i})[0].Value==i.ToString();
Check(unchanged,"all 256 single-byte values remain unchanged");
Check(Parse("name,byte_offset,bit_length,type\nvalue,0,16,uint").Decode("Default",new byte[]{0x12,0x34})[0].Value=="4660","big endian is the default without endian column");
Check(Parse(Header+"M,x,0,0,16,uint,le,msb0,1,0,,yes").Decode("M",new byte[]{0x34,0x12})[0].Value=="4660","little endian CSV supported");
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
// DRAS: endian, explicit C layouts and sealed header bundles.
var structBytes=File.ReadAllBytes(Path.Combine(root,"samples/PacketLayout.h"));
var structCsv=File.ReadAllBytes(Path.Combine(root,"samples/StructTelemetry.csv"));
var headerSources=new List<StructSource>{new("PacketLayout.h",structBytes)};
var structSchema=IcdCsv.Parse(structCsv,"be",headerSources,1,"lsb0");
Check(structSchema.RequiredBytes("Envelope")==13&&structSchema.Fields.Count==8,"nested structs and fixed arrays flatten with packed offsets");
var structPayload=new byte[13];structPayload[3]=0xA5;structPayload[4]=0xDA;
var structBefore=structSchema.Decode("Envelope",structPayload).ToDictionary(f=>f.Name);
Check(structBefore["packet.telemetry.mode"].Value=="2"&&structBefore["packet.telemetry.count"].Value=="2653","big endian bit fields use integer storage unit, lsb allocation");
structSchema.WriteValue("Envelope","packet.telemetry.mode","5",structPayload);
Check(structPayload[3]==0xA5&&structPayload[4]==0xDD&&structSchema.Decode("Envelope",structPayload)[1].Error=="","storage bit write preserves surrounding bits");
var leSchema=IcdCsv.Parse(structCsv,"le",headerSources,1,"lsb0");
leSchema.WriteValue("Envelope","packet.telemetry.sequence","4660",structPayload);
Check(structPayload[1]==0x34&&structPayload[2]==0x12,"little endian nested struct scalar write");
leSchema.WriteValue("Envelope","packet.telemetry.count","4095",structPayload);
Check(leSchema.Decode("Envelope",structPayload).Single(f=>f.Name=="packet.telemetry.count").Value=="4095","little endian storage bit read/write");
var msbSchema=IcdCsv.Parse(structCsv,"be",headerSources,1,"msb0");
var structMsbPayload=new byte[13];msbSchema.WriteValue("Envelope","packet.telemetry.mode","5",structMsbPayload);
Check(structMsbPayload[3]==0xA0&&structMsbPayload[4]==0,"explicit msb0 storage allocation");
var natural=CStructParser.Parse([new("padding.h",Encoding.UTF8.GetBytes("struct Padding { uint8_t x; uint32_t y; uint8_t z; };"))],4);
Check(natural["Padding"].Size==12&&natural["Padding"].Fields[1].ByteOffset==4,"natural alignment and tail padding with pack4");
Throws(()=>CStructParser.Parse([new("bad.h",Encoding.UTF8.GetBytes("struct Bad { uint8_t *pointer; };"))]),"C pointer declarations rejected");
Throws(()=>CStructParser.Parse([new("bad.h",Encoding.UTF8.GetBytes("struct Recursive { Recursive value; };"))]),"recursive structs rejected");
Throws(()=>IcdCsv.Parse(structCsv),"struct CSV requires external header");
var bundled=new RecordProfile{Name="Bundle",IcdName="StructTelemetry.csv",IcdContent=[..structCsv],StructSources=headerSources.Select(s=>new StructSource(s.Name,[..s.Content])).ToList(),ByteOrder="le",SenderIps=["192.0.2.1"],ReceiverIps=["192.0.2.2"]};
bundled.Validate();IcdProtection.Seal(admin,bundled);GuestIcdAccess.Seal(admin,bundled,GuestIcdAccess.PublicKey(guest!));
Check(!Encoding.UTF8.GetString(bundled.EncryptedIcd).Contains("TelemetryHeader"),"external header is absent from encrypted bundle plaintext search");
var bundleId=bundled.IcdId;bundled.ClearPlaintext();IcdProtection.Open(admin,bundled);
Check(bundled.StructSources.Count==1&&bundled.StructSources[0].Content.SequenceEqual(structBytes)&&bundled.ParseSchema().RequiredBytes("Envelope")==13,"encrypted CSV and headers reopen together");
var guestBundle=GuestIcdAccess.Open(guest!,bundled);var guestTemporary=new RecordProfile();try{IcdBundle.Unpack(guestBundle,guestTemporary);Check(guestTemporary.StructSources.Count==1&&IcdBundle.Fingerprint(guestTemporary)==bundleId,"authorized guest recipient can open sealed struct bundle internally");}finally{System.Security.Cryptography.CryptographicOperations.ZeroMemory(guestBundle);guestTemporary.ClearPlaintext();}
var enabledSettings=new WorkspaceSettings{Profiles=[bundled]};bundled.Enabled=false;
Check(!bundled.Matches(IPAddress.Parse("192.0.2.1"),IPAddress.Parse("192.0.2.2")),"inactive ICD classification disabled");
try{PcapCsvConverter.Messages(admin,enabledSettings,bundled.Id);throw new Exception("inactive conversion allowed");}catch(UnauthorizedAccessException){Check(true,"inactive ICD conversion denied independently of capture");}
var layoutFolder=Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString("N"));try{var prefs=new UiPreferences(Path.Combine(layoutFolder,"layout.bin"));var layout=new UiLayoutOptions(17,14,11,20,32,350,45);prefs.SaveLayout(layout);Check(prefs.LoadLayout()==layout,"independent fonts and pane widths persist");}finally{Directory.Delete(layoutFolder,true);}

var bundleRecordingDirectory=Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString("N"));Directory.CreateDirectory(bundleRecordingDirectory);
try {
 bundled.ReceiverIps=["198.51.100.2"];bundled.Enabled=true;var complete=frame.Take(42).Concat(new byte[13]).ToArray();complete[16]=0;complete[17]=41;complete[38]=0;complete[39]=21;complete[42]=7;complete[43]=0x34;complete[44]=0x12;
 var input=Path.Combine(bundleRecordingDirectory,"struct.pcap");using(var writer=new NicRecording(input,"NIC",LinkLayers.Ethernet,[bundled])){writer.Write(new RawCapture(LinkLayers.Ethernet,new PosixTimeval(1700000000,1),complete));}
 enabledSettings.GuestIcdAllowList=[bundled.IcdId];var structOutput=Path.Combine(bundleRecordingDirectory,"struct.csv");var converted=PcapCsvConverter.Convert(guest!,enabledSettings.ForSession(guest!),bundled.Id,"Envelope",input,structOutput);Check(converted.Rows==1&&File.ReadAllText(structOutput).Contains("\"4660\""),"guest PCAP CSV conversion uses sealed external struct and little endian options");
 bundled.Enabled=false;using(var writer=new NicRecording(Path.Combine(bundleRecordingDirectory,"inactive.pcap"),"NIC",LinkLayers.Ethernet,[bundled])){writer.Write(new RawCapture(LinkLayers.Ethernet,new PosixTimeval(1700000000,2),complete));Check(writer.Total.Packets==1&&writer.Snapshot("recording").Single().Packets==0,"inactive ICD still retains whole NIC PCAP frames");}
 using(var reader=new CaptureFileReaderDevice(Path.Combine(bundleRecordingDirectory,"inactive.pcap"))){reader.Open();Check(reader.GetNextPacket(out var captured)==GetPacketStatus.PacketRead&&captured.GetPacket().Data.SequenceEqual(complete),"inactive ICD standard PCAP frame bytes unchanged");}
}finally{Directory.Delete(bundleRecordingDirectory,true);bundled.ClearPlaintext();}
var aliasLayout=CStructParser.Parse([new("alias.h",Encoding.UTF8.GetBytes("struct Value { uint16_t number; }; typedef struct Value Value; typedef struct Value Alias; struct Packet { Alias item; };"))]);Check(aliasLayout["Packet"].Size==2,"common typedef struct tag aliases supported");
// Explicit administrator ICD export / Excel edit / reimport.
var exportProfile=new RecordProfile{Name="Export",IcdName="source.csv",IcdContent=File.ReadAllBytes(Path.Combine(root,"samples/StructTelemetry.csv")),StructSources=[new("../PacketLayout.h",File.ReadAllBytes(Path.Combine(root,"samples/PacketLayout.h")))],ByteOrder="le"};
IcdProtection.Seal(admin!,exportProfile);var exportCipher=exportProfile.EncryptedIcd.ToArray();exportProfile.ClearPlaintext();
Denied(()=>IcdExport.Csv(guest!,exportProfile),"guest cannot export ICD definition CSV even with conversion access");
Denied(()=>IcdExport.Package(guest!,exportProfile),"guest cannot export original headers or C++ package");
var exportedCsv=IcdExport.Csv(admin!,exportProfile);Check(exportedCsv.AsSpan(0,3).SequenceEqual(new byte[]{0xEF,0xBB,0xBF}),"Excel export is UTF-8 with BOM");
var exportedSchema=IcdCsv.Parse(exportedCsv);var expectedSchema=IcdCsv.Parse(structCsv,"le",headerSources,1,"lsb0");
Check(exportedSchema.Fields.Select(f=>f with{SourceLine=0}).SequenceEqual(expectedSchema.Fields.Select(f=>f with{SourceLine=0}))&&exportedSchema.RequiredBytes("Envelope")==13,"flattened CSV retains external struct storage-unit metadata and names");
var roundPayload=new byte[13];expectedSchema.WriteValue("Envelope","packet.telemetry.count","2730",roundPayload);Check(exportedSchema.Decode("Envelope",roundPayload).SequenceEqual(expectedSchema.Decode("Envelope",roundPayload)),"export and reimport preserve little endian C bit values");
var editedText=Encoding.UTF8.GetString(exportedCsv).Replace("packet.telemetry.count","packet.telemetry.edited_count");var editedSchema=IcdCsv.Parse(Encoding.UTF8.GetBytes(editedText));Check(editedSchema.Fields.Any(f=>f.Name.EndsWith("edited_count")),"Excel-style field edit reimports without external headers");
var packedExport=IcdExport.Package(admin!,exportProfile);using(var archive=new System.IO.Compression.ZipArchive(new MemoryStream(packedExport))){Check(archive.Entries.Any(e=>e.FullName=="icd-edit.csv")&&archive.Entries.Any(e=>e.FullName=="dras-wire.hpp")&&archive.Entries.Any(e=>e.FullName=="import-options.json"),"ICD package includes CSV, C++ wire structs and import settings");Check(archive.Entries.All(e=>!e.FullName.Split('/').Contains("..")),"untrusted source filename cannot escape export ZIP");using var source=archive.GetEntry("original/source.csv")!.Open();using var sourceBuffer=new MemoryStream();source.CopyTo(sourceBuffer);Check(sourceBuffer.ToArray().SequenceEqual(structCsv),"original CSV bytes preserved for original-header editing");using var header=archive.Entries.Single(e=>e.FullName.StartsWith("original/headers/")).Open();using var headerBuffer=new MemoryStream();header.CopyTo(headerBuffer);Check(headerBuffer.ToArray().SequenceEqual(structBytes),"original header bytes preserved exactly");
var cppCheckDirectory=Environment.GetEnvironmentVariable("DRAS_CPP_CHECK_DIR");if(!string.IsNullOrEmpty(cppCheckDirectory)){Directory.CreateDirectory(cppCheckDirectory);using var wire=archive.GetEntry("dras-wire.hpp")!.Open();using var target=File.Create(Path.Combine(cppCheckDirectory,"dras-wire.hpp"));wire.CopyTo(target);}}
Check(exportProfile.IcdContent.Length==0&&exportProfile.StructSources.Count==0&&exportProfile.EncryptedIcd.SequenceEqual(exportCipher),"export leaves encrypted profile and plaintext state unchanged");
var paddedProfile=new RecordProfile{IcdName="padding.csv",IcdContent=Encoding.UTF8.GetBytes("message,name,byte_offset,type,struct_name\nPadding,p,0,struct,Padding"),StructSources=[new("padding.h",Encoding.UTF8.GetBytes("struct Padding { uint32_t a; uint8_t b; };"))],StructPack=4};
Check(IcdCsv.Parse(IcdExport.Csv(admin!,paddedProfile)).RequiredBytes("Padding")==8,"CSV roundtrip retains C struct tail padding");
var boolProfile=new RecordProfile{IcdName="bool.csv",IcdContent=Encoding.UTF8.GetBytes("name,byte_offset,type,struct_name\np,0,struct,Flag"),StructSources=[new("bool.h",Encoding.UTF8.GetBytes("struct Flag { bool active; };"))]};Check(IcdCsv.Parse(IcdExport.Csv(admin!,boolProfile)).Decode("Default",new byte[]{0xFF})[0].Value=="true","C bool byte survives normalized CSV reimport");
Throws(()=>Parse("name,byte_offset,bit_length,type,storage_bits,storage_bit_offset\nx,0,12,uint,8,0"),"CSV rejects storage bit overflow");
Throws(()=>Parse("name,byte_offset,bit_length,type,message_size\nx,1,16,uint,2"),"CSV rejects message size shorter than fields");
Denied(()=>IcdExport.Struct(guest!,exportProfile),"guest cannot export plain C++ declarations");
var declarations=Encoding.UTF8.GetString(IcdExport.Struct(admin!,exportProfile));
Check(declarations.Contains("struct Envelope {")&&declarations.Contains("uint16_t packet_telemetry_sequence;")&&declarations.Contains("uint16_t packet_telemetry_mode : 3;"),"plain C++ export contains real typed fields and bitfield declarations");
Check(!declarations.Contains("wire[")&&!declarations.Contains("read_field")&&!declarations.Contains("namespace "),"declaration export omits wire buffer and helper functions");
Check(CStructParser.Parse([new("icd-struct.hpp",Encoding.UTF8.GetBytes(declarations))]).ContainsKey("Envelope"),"generated declaration header can be read by restricted struct importer");
var declarationDirectory=Environment.GetEnvironmentVariable("DRAS_CPP_CHECK_DIR");if(!string.IsNullOrEmpty(declarationDirectory))File.WriteAllText(Path.Combine(declarationDirectory,"icd-struct.hpp"),declarations);
var sampleDeclarations=Encoding.UTF8.GetString(IcdExport.Struct(admin!,new RecordProfile{IcdContent=File.ReadAllBytes(Path.Combine(root,"samples/Telemetry.csv"))}));Check(sampleDeclarations.Contains("uint16_t sequence;")&&sampleDeclarations.Contains("uint8_t mode : 3;")&&sampleDeclarations.Contains("float voltage;"),"CSV-only ICD exports normal scalar and bitfield struct");
if(!string.IsNullOrEmpty(declarationDirectory))File.WriteAllText(Path.Combine(declarationDirectory,"telemetry-struct.hpp"),sampleDeclarations);
var arrayDeclarations=Encoding.UTF8.GetString(IcdExport.Struct(admin!,new RecordProfile{IcdContent=Encoding.UTF8.GetBytes("name,byte_offset,bit_length,type\nclass,0,8,uint\nicd_class,1,8,uint\nblob,2,32,bytes")}));Check(arrayDeclarations.Contains("uint8_t icd_class;")&&arrayDeclarations.Contains("uint8_t icd_class_2;")&&arrayDeclarations.Contains("uint8_t blob[4];"),"C++ identifiers handle keywords/collisions and byte arrays");
if(!string.IsNullOrEmpty(declarationDirectory))File.WriteAllText(Path.Combine(declarationDirectory,"array-struct.hpp"),arrayDeclarations);
var credentialDir=Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString("N"));Directory.CreateDirectory(credentialDir);
try {
 string credentialBinding="",credentialPath=Path.Combine(credentialDir,"admin-login.bin"),oldPassword=Environment.GetEnvironmentVariable("LANSCOPE_TEST_ADMIN")!,newPassword="Changed-"+Guid.NewGuid().ToString("N");
 var credentials=new AdminCredentials(File.ReadAllBytes(Path.Combine(root,"src/LanScope/Resources/accounts.bin")),IcdProtection.PublicKey(admin!),()=>credentialBinding,credentialPath);
 using(var initial=credentials.Login("admin",oldPassword))Check(initial?.Role==UserRole.Admin,"embedded admin authentication before password change");
 Denied(()=>credentials.Change(guest!,oldPassword,newPassword,_=>{}),"guest cannot change admin password");
 Denied(()=>credentials.Change(admin!,"wrong",newPassword,_=>{}),"current password required for admin password change");
 Throws(()=>credentials.Change(admin!,oldPassword,"short",_=>{}),"new password minimum length checked");
 credentials.Change(admin!,oldPassword,newPassword,d=>credentialBinding=d);Check(credentialBinding.Length==64&&File.Exists(credentialPath),"password envelope and signed-config binding prepared atomically");
 Check(credentials.Login("admin",oldPassword)==null,"old admin password rejected after change");
 using(var changed=credentials.Login("admin",newPassword)){Check(changed?.Role==UserRole.Admin&&IcdProtection.PublicKey(changed!).SequenceEqual(IcdProtection.PublicKey(admin!)),"new password restores original signing and ICD root key");var testProfile=new RecordProfile{Id=exportProfile.Id,IcdId=exportProfile.IcdId,EncryptedIcd=exportProfile.EncryptedIcd};try{IcdProtection.Open(changed!,testProfile);Check(testProfile.IcdContent.SequenceEqual(structCsv),"existing encrypted ICD opens with changed password");}finally{testProfile.ClearPlaintext();}}
 Check(!Encoding.UTF8.GetString(File.ReadAllBytes(credentialPath)).Contains(newPassword),"plaintext password is never written to credential envelope");
 using(var guestAfter=credentials.Login("guest",Environment.GetEnvironmentVariable("LANSCOPE_TEST_GUEST")!))Check(guestAfter?.Role==UserRole.Guest,"guest authentication unchanged by admin password update");
 try{credentials.Change(admin!,newPassword,"Next-"+Guid.NewGuid().ToString("N"),_=>throw new IOException("simulated config save failure"));throw new Exception("save failure expected");}catch(IOException){using var stillValid=credentials.Login("admin",newPassword);Check(stillValid?.Role==UserRole.Admin,"failed configuration commit preserves previous admin login");}
 var savedCredential=File.ReadAllBytes(credentialPath);File.Delete(credentialPath);CryptoRejected(()=>credentials.Login("admin",oldPassword),"deleted override cannot fall back to old embedded password");File.WriteAllBytes(credentialPath,savedCredential);
 savedCredential[^1]^=1;File.WriteAllBytes(credentialPath,savedCredential);CryptoRejected(()=>credentials.Login("admin",newPassword),"tampered password envelope rejected");
}finally{Directory.Delete(credentialDir,true);}
var newLayoutPath=Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString("N"),"ui.bin");try{var prefs=new UiPreferences(newLayoutPath);var customized=new UiLayoutOptions(TestNameFont:28,TestNameWidth:740,TestNameHeight:120);prefs.SaveLayout(customized);Check(prefs.LoadLayout()==customized,"record name font and resize settings roundtrip");}finally{Directory.Delete(Path.GetDirectoryName(newLayoutPath)!,true);}
Console.WriteLine($"{checks} meaningful checks passed. Windows DPAPI/WPF/live NIC tests remain Windows-only.");
