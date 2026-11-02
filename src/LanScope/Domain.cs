using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using PacketDotNet;

namespace LanScope;
public enum UserRole { Guest, Admin }
public sealed class LoginSession : IDisposable
{
    private byte[]? adminKey;
    public string UserId {get;}
    public UserRole Role {get;}
    internal LoginSession(string userId,UserRole role,byte[]? key=null){UserId=userId;Role=role;adminKey=key;}
    public void RequireAdmin(){if(Role!=UserRole.Admin||adminKey is not {Length:32})throw new UnauthorizedAccessException("관리자 인증이 필요합니다.");}
    internal ReadOnlySpan<byte> Key {get{RequireAdmin();return adminKey;}}
    internal ReadOnlySpan<byte> SessionKey {get{if(adminKey is not {Length:32})throw new UnauthorizedAccessException("로그인이 만료되었습니다.");return adminKey;}}
    public void Dispose(){if(adminKey!=null)CryptographicOperations.ZeroMemory(adminKey);adminKey=null;}
}
public sealed class AccountService
{
    private readonly byte[] data;
    public AccountService(byte[] binary) => data = binary;
    public LoginSession? Login(string id, string password)
    {
        using var reader = new BinaryReader(new MemoryStream(data), Encoding.UTF8);
        if(reader.ReadString() != "LANSCOPE-AUTH-1") throw new InvalidDataException("계정 리소스 형식 오류");
        var count = reader.ReadInt32(); LoginSession? result = null;
        for(var i=0;i<count;i++) {
            var name=reader.ReadString(); var role=(UserRole)reader.ReadByte(); var iterations=reader.ReadInt32();
            var salt=reader.ReadBytes(16); var hash=reader.ReadBytes(32);
            var actual=Rfc2898DeriveBytes.Pbkdf2(password,salt,iterations,HashAlgorithmName.SHA256,32);
            if(CryptographicOperations.FixedTimeEquals(actual,hash) && string.Equals(name,id.Trim(),StringComparison.Ordinal)) {result?.Dispose();byte[]? key=null;{var keySalt=SHA256.HashData(salt.Concat(Encoding.UTF8.GetBytes(role==UserRole.Admin?"LANscope ICD key v1":"LANscope guest conversion key v1")).ToArray());key=Rfc2898DeriveBytes.Pbkdf2(password,keySalt,600000,HashAlgorithmName.SHA256,32);}result=new(name,role,key);}
            CryptographicOperations.ZeroMemory(actual);
        }
        return result;
    }
}
public sealed class RecordProfile
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "";
    [JsonIgnore] public string IcdName { get; set; } = "";
    [JsonIgnore] public byte[] IcdContent { get; set; } = [];
    public string IcdId {get;set;}="";
    public byte[] EncryptedIcd {get;set;}=[];
    public byte[] GuestConversionIcd {get;set;}=[];
    public void ClearPlaintext(){CryptographicOperations.ZeroMemory(IcdContent);IcdContent=[];IcdName="";}
    public List<string> SenderIps { get; set; } = [];
    public List<string> ReceiverIps { get; set; } = [];
    public bool BothDirections { get; set; } = true;
    public void Validate()
    {
        if(!Guid.TryParseExact(Id,"N",out _)) throw new ArgumentException("프로파일 ID 형식 오류");
        if(string.IsNullOrWhiteSpace(Name) || Name.Length>80) throw new ArgumentException("프로파일 이름을 1~80자로 입력하세요.");
        if(IcdContent.Length>0) {
            if(!IcdName.EndsWith(".csv",StringComparison.OrdinalIgnoreCase))throw new ArgumentException("ICD를 CSV 파일로 다시 선택하세요.");
            IcdCsv.Parse(IcdContent);
        }else if(EncryptedIcd.Length==0||IcdId.Length!=64)throw new ArgumentException("관리자가 ICD를 가져와 암호화 저장해야 합니다.");
        ValidateEndpoints();
    }
    public void ValidateEndpoints()
    {
        if(!Guid.TryParseExact(Id,"N",out _)||string.IsNullOrWhiteSpace(Name))throw new ArgumentException("인터페이스 ID/이름 오류");
        if(SenderIps.Count==0 || ReceiverIps.Count==0) throw new ArgumentException("송신 IP와 수신 IP를 각각 1개 이상 입력하세요.");
        if(SenderIps.Concat(ReceiverIps).Any(x=>!IPAddress.TryParse(x,out _))) throw new ArgumentException("유효한 IPv4 또는 IPv6 주소를 입력하세요.");
    }
    public bool Matches(IPAddress source, IPAddress destination)
    {
        bool Has(List<string> list, IPAddress address)=>list.Any(x=>IPAddress.TryParse(x,out var ip)&&ip.Equals(address));
        return (Has(SenderIps,source)&&Has(ReceiverIps,destination)) || (BothDirections&&Has(SenderIps,destination)&&Has(ReceiverIps,source));
    }
    public override string ToString()=>Name;
}
public sealed class NicBinding
{
    public string DeviceId { get; set; } = "";
    public string DeviceName { get; set; } = "";
    public List<string> ProfileIds { get; set; } = [];
}
public sealed class WorkspaceSettings
{
    public string OutputDirectory { get; set; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),"LANscope","Records");
    public List<RecordProfile> Profiles { get; set; } = [];
    public List<NicBinding> Bindings { get; set; } = [];
    public List<string> GuestIcdAllowList {get;set;}=[];
    public bool HasGuestConversionConflict(string profileId)
    {
        foreach(var binding in Bindings) {
            var profiles=Profiles.Where(p=>binding.ProfileIds.Contains(p.Id)).ToList();
            var allowed=profiles.Where(p=>p.Id==profileId&&GuestIcdAllowList.Contains(p.IcdId));
            var denied=profiles.Where(p=>!GuestIcdAllowList.Contains(p.IcdId));
            foreach(var a in allowed)foreach(var d in denied) {
                foreach(var source in a.SenderIps)foreach(var destination in a.ReceiverIps) {
                    if(IPAddress.TryParse(source,out var src)&&IPAddress.TryParse(destination,out var dst)&&
                      (d.Matches(src,dst)||(a.BothDirections&&d.Matches(dst,src))))return true;
                }
            }
        }
        return false;
    }
    public WorkspaceSettings ForSession(LoginSession session)
    {
        _=session.SessionKey;
        if(session.Role==UserRole.Admin){session.RequireAdmin();return this;}
        if(session.Role!=UserRole.Guest)throw new UnauthorizedAccessException();
        var allowed=Profiles.ToList();
        var ids=allowed.Select(p=>p.Id).ToHashSet();
        return new WorkspaceSettings {OutputDirectory=OutputDirectory,GuestIcdAllowList=[..GuestIcdAllowList],
            Profiles=allowed.Select(p=>new RecordProfile{Id=p.Id,Name=p.Name,IcdId=p.IcdId,EncryptedIcd=[..p.EncryptedIcd],GuestConversionIcd=[..p.GuestConversionIcd],SenderIps=[..p.SenderIps],ReceiverIps=[..p.ReceiverIps],BothDirections=p.BothDirections}).ToList(),
            Bindings=Bindings.Select(b=>new NicBinding{DeviceId=b.DeviceId,DeviceName=b.DeviceName,ProfileIds=b.ProfileIds.Where(ids.Contains).ToList()}).Where(b=>b.ProfileIds.Count>0).ToList()};
    }
    public void ClearPlaintext(){foreach(var p in Profiles)p.ClearPlaintext();}

    public void ValidateForRecording(IReadOnlyCollection<string> available)
    {
        if(string.IsNullOrWhiteSpace(OutputDirectory)||!Path.IsPathFullyQualified(OutputDirectory)) throw new ArgumentException("기록 폴더를 절대 경로로 지정하세요.");
        if(Bindings.Count==0) throw new ArgumentException("NIC에 프로파일을 1개 이상 매칭하세요.");
        if(Bindings.Select(x=>x.DeviceId).Distinct().Count()!=Bindings.Count) throw new ArgumentException("NIC 매칭이 중복되었습니다.");
        foreach(var b in Bindings) {
            if(!available.Contains(b.DeviceId)) throw new ArgumentException($"NIC을 사용할 수 없습니다: {b.DeviceName}");
            if(b.ProfileIds.Count==0 || b.ProfileIds.Distinct().Count()!=b.ProfileIds.Count) throw new ArgumentException("각 NIC에는 중복 없이 프로파일을 1개 이상 선택해야 합니다.");
            foreach(var id in b.ProfileIds) (Profiles.SingleOrDefault(p=>p.Id==id)??throw new ArgumentException("삭제된 프로파일 매칭입니다.")).ValidateEndpoints();
        }
    }
}
public sealed record MappingSnapshot(string Nic, string Profile, long Packets, long Bytes, int MinSize, int MaxSize, double AverageSize, string LastPacket, string State, string DeviceId="", string ProfileId="");
public sealed class PacketCounter
{
    public long Packets {get;private set;} public long Bytes {get;private set;}
    public int MinSize {get;private set;} public int MaxSize {get;private set;}
    public DateTime? LastPacket {get;private set;}
    public void Add(int length, DateTime utc) { Packets++; Bytes+=length; MinSize=Packets==1?length:Math.Min(MinSize,length); MaxSize=Math.Max(MaxSize,length); LastPacket=utc; }
    public double Average=>Packets==0?0:(double)Bytes/Packets;
}
public sealed class PcapFile : IDisposable
{
    private readonly BinaryWriter writer;
    public PcapFile(string path, LinkLayers linkType)
    {
        writer=new BinaryWriter(new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read,65536));
        writer.Write(0xa1b2c3d4u); writer.Write((ushort)2); writer.Write((ushort)4);writer.Write(0);writer.Write(0u);writer.Write(65535u);writer.Write((uint)linkType);
    }
    public void Write(byte[] bytes,ulong seconds,ulong microseconds)
    {
        if(bytes.Length>65535 || seconds>uint.MaxValue || microseconds>=1000000) throw new InvalidDataException("지원하지 않는 프레임 크기/타임스탬프입니다.");
        writer.Write((uint)seconds);writer.Write((uint)microseconds);writer.Write((uint)bytes.Length);writer.Write((uint)bytes.Length);writer.Write(bytes);
    }
    public void Flush()=>writer.Flush();
    public void Dispose()=>writer.Dispose();
}
