using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LanScope;
public static class IcdProtection
{
    private static readonly byte[] Magic=Encoding.ASCII.GetBytes("LSICD001");
    public static byte[] Encrypt(LoginSession admin,string purpose,ReadOnlySpan<byte> plaintext)
    {
        admin.RequireAdmin();var nonce=RandomNumberGenerator.GetBytes(12);var cipher=new byte[plaintext.Length];var tag=new byte[16];
        using var aes=new AesGcm(admin.Key,16);aes.Encrypt(nonce,plaintext,cipher,tag,Encoding.UTF8.GetBytes(purpose));
        return Magic.Concat(nonce).Concat(tag).Concat(cipher).ToArray();
    }
    public static byte[] Decrypt(LoginSession admin,string purpose,byte[] envelope)
    {
        admin.RequireAdmin();
        if(envelope.Length<36||!envelope.AsSpan(0,8).SequenceEqual(Magic))throw new CryptographicException("암호화 ICD 형식 오류");
        var plain=new byte[envelope.Length-36];
        try{using var aes=new AesGcm(admin.Key,16);aes.Decrypt(envelope.AsSpan(8,12),envelope.AsSpan(36),envelope.AsSpan(20,16),plain,Encoding.UTF8.GetBytes(purpose));return plain;}
        catch{CryptographicOperations.ZeroMemory(plain);throw;}
    }
    public static void Seal(LoginSession admin,RecordProfile profile)
    {
        admin.RequireAdmin();
        if(!Guid.TryParseExact(profile.Id,"N",out _))throw new ArgumentException("프로파일 ID 오류");
        if(profile.IcdContent.Length==0) {Open(admin,profile);}
        if(profile.IcdContent.Length==0||profile.IcdContent.Length>16*1024*1024||string.IsNullOrWhiteSpace(profile.IcdName))throw new ArgumentException("ICD 파일 크기/이름 오류");
        profile.IcdId=Convert.ToHexString(SHA256.HashData(profile.IcdContent));
        using var output=new MemoryStream();
        using(var w=new BinaryWriter(output,Encoding.UTF8,true)){w.Write(profile.IcdName);w.Write(profile.IcdContent.Length);w.Write(profile.IcdContent);}
        var bytes=output.ToArray();try{profile.EncryptedIcd=Encrypt(admin,"profile:"+profile.Id,bytes);}finally{CryptographicOperations.ZeroMemory(bytes);if(output.TryGetBuffer(out var buffer))CryptographicOperations.ZeroMemory(buffer.AsSpan());}
    }
    public static void Open(LoginSession admin,RecordProfile profile)
    {
        var bytes=Decrypt(admin,"profile:"+profile.Id,profile.EncryptedIcd);
        try {
            using var reader=new BinaryReader(new MemoryStream(bytes),Encoding.UTF8);
            var name=reader.ReadString();int length=reader.ReadInt32();if(length<1||length>16*1024*1024||reader.BaseStream.Length-reader.BaseStream.Position!=length)throw new CryptographicException("ICD 길이 오류");
            var content=reader.ReadBytes(length);
            if(Convert.ToHexString(SHA256.HashData(content))!=profile.IcdId){CryptographicOperations.ZeroMemory(content);throw new CryptographicException("ICD 지문 오류");}
            profile.IcdName=name;profile.IcdContent=content;
        }finally{CryptographicOperations.ZeroMemory(bytes);}
    }
    public static WorkspaceSettings CloneForAdmin(LoginSession admin,WorkspaceSettings settings)
    {
        admin.RequireAdmin();
        var clone=JsonSerializer.Deserialize<WorkspaceSettings>(JsonSerializer.Serialize(settings))!;
        foreach(var profile in clone.Profiles)Open(admin,profile);
        return clone;
    }
    // Domain-separated deterministic ECDSA private scalar, never persisted with configuration.
    private static ECDsa Signer(LoginSession admin)
    {
        admin.RequireAdmin();var d=HMACSHA256.HashData(admin.Key,Encoding.UTF8.GetBytes("LANscope policy signing v1"));
        // Constrain to 255 bits; every nonzero 255-bit scalar is valid for P-256.
        d[0]&=0x7f;if(d.All(b=>b==0))d[^1]=1;
        try {return ECDsa.Create(new ECParameters{Curve=ECCurve.NamedCurves.nistP256,D=d});}
        finally{CryptographicOperations.ZeroMemory(d);}
    }
    public static byte[] PublicKey(LoginSession admin){using var signer=Signer(admin);return signer.ExportSubjectPublicKeyInfo();}
    public static byte[] Sign(LoginSession admin,byte[] bytes){using var signer=Signer(admin);return signer.SignData(bytes,HashAlgorithmName.SHA256);}
    public static void Verify(byte[] publicKey,byte[] bytes,byte[] signature)
    {
        using var verifier=ECDsa.Create();verifier.ImportSubjectPublicKeyInfo(publicKey,out var read);
        if(read!=publicKey.Length||!verifier.VerifyData(bytes,signature,HashAlgorithmName.SHA256))throw new CryptographicException("설정 서명이 유효하지 않습니다. 관리자 설정 원본을 복원하세요.");
    }
}
