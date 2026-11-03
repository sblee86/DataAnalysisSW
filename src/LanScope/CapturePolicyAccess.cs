using System.IO;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
namespace LanScope;
internal static class CapturePolicyAccess
{
    private static string Purpose(RecordProfile p)=>"capture-policy:"+p.Id+":"+p.IcdId;
    internal static void Seal(LoginSession admin,RecordProfile p,byte[] publicKey)
    {
        admin.RequireAdmin();if(p.CapturePolicy==null){p.EncryptedCapturePolicy=[];p.GuestCapturePolicy=[];return;}
        p.CapturePolicy.Prepare(p.ParseSchema());var bytes=JsonSerializer.SerializeToUtf8Bytes(p.CapturePolicy);
        try{p.EncryptedCapturePolicy=IcdProtection.Encrypt(admin,Purpose(p),bytes);}finally{CryptographicOperations.ZeroMemory(bytes);}
        var minimal=p.CapturePolicy.Minimal();var plain=JsonSerializer.SerializeToUtf8Bytes(minimal);minimal.Clear();
        try {
            using var recipient=ECDiffieHellman.Create();recipient.ImportSubjectPublicKeyInfo(publicKey,out var read);if(read!=publicKey.Length)throw new CryptographicException("수신 키 오류");
            using var ephemeral=ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);var key=ephemeral.DeriveKeyFromHash(recipient.PublicKey,HashAlgorithmName.SHA256);var nonce=RandomNumberGenerator.GetBytes(12);var tag=new byte[16];var cipher=new byte[plain.Length];
            try{using var aes=new AesGcm(key,16);aes.Encrypt(nonce,plain,cipher,tag,Encoding.UTF8.GetBytes(Purpose(p)));}finally{CryptographicOperations.ZeroMemory(key);}
            using var m=new MemoryStream();using(var w=new BinaryWriter(m,Encoding.UTF8,true)){w.Write("DRAS-MATCH-1");var pub=ephemeral.ExportSubjectPublicKeyInfo();w.Write(pub.Length);w.Write(pub);w.Write(nonce);w.Write(tag);w.Write(cipher);}p.GuestCapturePolicy=m.ToArray();
        }finally{CryptographicOperations.ZeroMemory(plain);}
    }
    internal static void OpenAdmin(LoginSession admin,RecordProfile p)
    {
        if(p.EncryptedCapturePolicy.Length==0){p.CapturePolicy=null;return;}var bytes=IcdProtection.Decrypt(admin,Purpose(p),p.EncryptedCapturePolicy);
        try{p.CapturePolicy=JsonSerializer.Deserialize<CapturePolicy>(bytes)??throw new InvalidDataException("헤더 설정 오류");p.CapturePolicy.Prepare(p.ParseSchema());}finally{CryptographicOperations.ZeroMemory(bytes);}
    }
    internal static CapturePolicy? OpenGuest(LoginSession guest,RecordProfile p)
    {
        if(p.GuestCapturePolicy.Length==0)return null;if(guest.Role!=UserRole.Guest)throw new UnauthorizedAccessException();
        if(p.GuestCapturePolicy.Length>512*1024)throw new CryptographicException("헤더 규칙 크기 초과");
        using var r=new BinaryReader(new MemoryStream(p.GuestCapturePolicy));if(r.ReadString()!="DRAS-MATCH-1")throw new CryptographicException("헤더 규칙 형식 오류");int n=r.ReadInt32();if(n is <1 or >256)throw new CryptographicException("헤더 키 오류");var pub=r.ReadBytes(n);var nonce=r.ReadBytes(12);var tag=r.ReadBytes(16);var cipher=r.ReadBytes(512*1024);
        using var ephemeral=ECDiffieHellman.Create();ephemeral.ImportSubjectPublicKeyInfo(pub,out var read);if(read!=pub.Length)throw new CryptographicException("헤더 키 오류");using var recipient=GuestIcdAccess.Recipient(guest);var key=recipient.DeriveKeyFromHash(ephemeral.PublicKey,HashAlgorithmName.SHA256);var plain=new byte[cipher.Length];
        try{using var aes=new AesGcm(key,16);aes.Decrypt(nonce,cipher,tag,plain,Encoding.UTF8.GetBytes(Purpose(p)));var policy=JsonSerializer.Deserialize<CapturePolicy>(plain)??throw new CryptographicException("헤더 규칙 없음");policy.Validate();return policy;}finally{CryptographicOperations.ZeroMemory(key);CryptographicOperations.ZeroMemory(plain);}
    }
}
