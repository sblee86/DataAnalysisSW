using System.IO;
using System.Security.Cryptography;
using System.Text;
namespace LanScope;

/// <summary>Admin-signed guest password envelope committed atomically inside the signed workspace.</summary>
public sealed class GuestCredentials(byte[] accounts,byte[] publicKey,Func<byte[]> envelope)
{
    public LoginSession? Login(string id,string password)
    {
        if(id.Trim()=="admin")return null;
        var bytes=envelope();if(bytes.Length==0){var session=new AccountService(accounts).Login(id,password);if(session?.Role==UserRole.Guest)return session;session?.Dispose();return null;}
        if(bytes.Length<160||bytes.Length>1024)throw new CryptographicException("게스트 인증 형식 오류");
        var payload=bytes[..^64];IcdProtection.Verify(publicKey,payload,bytes[^64..]);
        using var r=new BinaryReader(new MemoryStream(payload),Encoding.UTF8);if(r.ReadString()!="DRAS-GUEST-1")throw new CryptographicException("게스트 인증 버전 오류");var name=r.ReadString();
        var salt=r.ReadBytes(32);var nonce=r.ReadBytes(12);var tag=r.ReadBytes(16);var cipher=r.ReadBytes(32);if(cipher.Length!=32||r.BaseStream.Position!=r.BaseStream.Length)throw new CryptographicException("게스트 인증 길이 오류");
        if(id.Trim()!=name)return null;var key=Rfc2898DeriveBytes.Pbkdf2(password,salt,600000,HashAlgorithmName.SHA256,32);var root=new byte[32];
        try{using var aes=new AesGcm(key,16);aes.Decrypt(nonce,cipher,tag,root,Encoding.UTF8.GetBytes("DRAS guest login v1:"+name));return new LoginSession(name,UserRole.Guest,root);}
        catch(AuthenticationTagMismatchException){CryptographicOperations.ZeroMemory(root);return null;}finally{CryptographicOperations.ZeroMemory(key);}
    }
    public static void Change(LoginSession admin,string id,string password,Action<string,byte[],byte[]> persist)
    {
        admin.RequireAdmin();id=id.Trim();if(id.Length is <1 or >64||id.Equals("admin",StringComparison.OrdinalIgnoreCase)||id.Any(c=>!char.IsAsciiLetterOrDigit(c)&&c is not ('_' or '-' or '.')))throw new ArgumentException("게스트 ID는 영문·숫자·_.- 1~64자이며 admin은 사용할 수 없습니다.");
        if(password.Length is <8 or >128)throw new ArgumentException("게스트 비밀번호는 8~128자로 입력하세요.");
        using var guest=new LoginSession(id,UserRole.Guest,RandomNumberGenerator.GetBytes(32));var salt=RandomNumberGenerator.GetBytes(32);var nonce=RandomNumberGenerator.GetBytes(12);var tag=new byte[16];var cipher=new byte[32];var key=Rfc2898DeriveBytes.Pbkdf2(password,salt,600000,HashAlgorithmName.SHA256,32);
        try{using var aes=new AesGcm(key,16);aes.Encrypt(nonce,guest.SessionKey,cipher,tag,Encoding.UTF8.GetBytes("DRAS guest login v1:"+id));}finally{CryptographicOperations.ZeroMemory(key);}
        using var memory=new MemoryStream();using(var w=new BinaryWriter(memory,Encoding.UTF8,true)){w.Write("DRAS-GUEST-1");w.Write(id);w.Write(salt);w.Write(nonce);w.Write(tag);w.Write(cipher);}var payload=memory.ToArray();
        persist(id,payload.Concat(IcdProtection.Sign(admin,payload)).ToArray(),GuestIcdAccess.PublicKey(guest));
    }
}
