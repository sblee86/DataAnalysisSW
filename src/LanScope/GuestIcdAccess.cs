using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace LanScope;
internal static class GuestIcdAccess
{
    private static ECDiffieHellman Recipient(LoginSession session)
    {
        var d=HMACSHA256.HashData(session.SessionKey,Encoding.UTF8.GetBytes("LANscope guest CSV recipient v1"));d[0]&=0x7f;if(d.All(b=>b==0))d[^1]=1;
        try{return ECDiffieHellman.Create(new ECParameters{Curve=ECCurve.NamedCurves.nistP256,D=d});}finally{CryptographicOperations.ZeroMemory(d);}
    }
    internal static byte[] PublicKey(LoginSession guest){if(guest.Role!=UserRole.Guest)throw new UnauthorizedAccessException();using var recipient=Recipient(guest);return recipient.ExportSubjectPublicKeyInfo();}
    internal static byte[] EmbeddedPublicKey()
    {
        using var stream=typeof(GuestIcdAccess).Assembly.GetManifestResourceStream("LanScope.Resources.guest-conversion-public.bin")??throw new InvalidDataException("guest 변환 공개키가 없습니다.");using var output=new MemoryStream();stream.CopyTo(output);return output.ToArray();
    }
    internal static void Seal(LoginSession admin,RecordProfile profile,byte[] publicKey)
    {
        admin.RequireAdmin();
        using var recipient=ECDiffieHellman.Create();recipient.ImportSubjectPublicKeyInfo(publicKey,out var read);if(read!=publicKey.Length)throw new CryptographicException("guest 공개키 오류");
        using var ephemeral=ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);var key=ephemeral.DeriveKeyFromHash(recipient.PublicKey,HashAlgorithmName.SHA256);
        var payload=IcdBundle.Pack(profile);var nonce=RandomNumberGenerator.GetBytes(12);var cipher=new byte[payload.Length];var tag=new byte[16];
        try{using var aes=new AesGcm(key,16);aes.Encrypt(nonce,payload,cipher,tag,Encoding.UTF8.GetBytes(profile.Id+":"+profile.IcdId));}finally{CryptographicOperations.ZeroMemory(key);CryptographicOperations.ZeroMemory(payload);}
        using var buffer=new MemoryStream();using(var w=new BinaryWriter(buffer,Encoding.UTF8,true)){w.Write("LSGCSV001");var pub=ephemeral.ExportSubjectPublicKeyInfo();w.Write(pub.Length);w.Write(pub);w.Write(nonce);w.Write(tag);w.Write(cipher);}profile.GuestConversionIcd=buffer.ToArray();
    }
    internal static byte[] Open(LoginSession guest,RecordProfile profile)
    {
        if(guest.Role!=UserRole.Guest)throw new UnauthorizedAccessException();
        using var reader=new BinaryReader(new MemoryStream(profile.GuestConversionIcd),Encoding.UTF8);
        if(reader.ReadString()!="LSGCSV001")throw new CryptographicException("guest 변환 암호문 오류");int n=reader.ReadInt32();if(n<1||n>256)throw new CryptographicException("변환 공개키 길이 오류");
        var pub=reader.ReadBytes(n);var nonce=reader.ReadBytes(12);var tag=reader.ReadBytes(16);var cipher=reader.ReadBytes(33*1024*1024+1);if(cipher.Length>33*1024*1024)throw new CryptographicException("ICD 크기 초과");
        using var ephemeral=ECDiffieHellman.Create();ephemeral.ImportSubjectPublicKeyInfo(pub,out var read);if(read!=pub.Length)throw new CryptographicException("변환 공개키 오류");using var recipient=Recipient(guest);var key=recipient.DeriveKeyFromHash(ephemeral.PublicKey,HashAlgorithmName.SHA256);var plain=new byte[cipher.Length];
        try {using var aes=new AesGcm(key,16);aes.Decrypt(nonce,cipher,tag,plain,Encoding.UTF8.GetBytes(profile.Id+":"+profile.IcdId));var temp=new RecordProfile();try{IcdBundle.Unpack(plain,temp);if(IcdBundle.Fingerprint(temp)!=profile.IcdId)throw new CryptographicException("ICD 지문 오류");}finally{temp.ClearPlaintext();}return plain;}
        catch{CryptographicOperations.ZeroMemory(plain);throw;}finally{CryptographicOperations.ZeroMemory(key);}
    }
}
