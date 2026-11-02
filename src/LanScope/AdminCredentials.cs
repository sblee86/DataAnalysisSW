using System.IO;
using System.Security.Cryptography;
using System.Text;
namespace LanScope;

/// <summary>Password-derived envelope for the existing root key. The pinned signing key never changes.</summary>
public sealed class AdminCredentials(byte[] accounts,byte[] publicKey,Func<string> binding,string? filePath=null)
{
    private readonly string file=filePath??Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"LANscope","admin-login.bin");
    public LoginSession? Login(string id,string password)
    {
        if(id.Trim()!="admin")return new AccountService(accounts).Login(id,password);
        string digest=binding();if(digest.Length==0)return new AccountService(accounts).Login(id,password);
        if(digest.Length!=64||!digest.All(Uri.IsHexDigit))throw new CryptographicException("관리자 인증 설정 오류");
        var pending=file+"."+digest+".pending";byte[]? bytes=null;
        foreach(var path in new[]{file,pending})if(File.Exists(path)){var candidate=File.ReadAllBytes(path);if(Convert.ToHexString(SHA256.HashData(candidate))==digest){bytes=candidate;break;}}
        if(bytes==null)throw new CryptographicException("관리자 인증 파일이 없거나 변경되었습니다. 설정과 인증 파일의 백업을 함께 복원하세요.");
        return Open(id.Trim(),password,bytes);
    }
    private LoginSession? Open(string id,string password,byte[] bytes)
    {
        if(bytes.Length<160||bytes.Length>512)throw new CryptographicException("관리자 인증 형식 오류");var payload=bytes[..^64];IcdProtection.Verify(publicKey,payload,bytes[^64..]);
        using var r=new BinaryReader(new MemoryStream(payload),Encoding.UTF8);if(r.ReadString()!="DRAS-ADMIN-1"||r.ReadString()!=id)throw new CryptographicException("관리자 인증 ID 오류");
        var salt=r.ReadBytes(32);var nonce=r.ReadBytes(12);var tag=r.ReadBytes(16);var cipher=r.ReadBytes(32);if(cipher.Length!=32||r.BaseStream.Position!=r.BaseStream.Length)throw new CryptographicException("관리자 인증 길이 오류");
        var key=Rfc2898DeriveBytes.Pbkdf2(password,salt,600000,HashAlgorithmName.SHA256,32);var root=new byte[32];
        try{using var aes=new AesGcm(key,16);aes.Decrypt(nonce,cipher,tag,root,Encoding.UTF8.GetBytes("DRAS admin login v1:"+id));return new LoginSession(id,UserRole.Admin,root);}
        catch(AuthenticationTagMismatchException){CryptographicOperations.ZeroMemory(root);return null;}finally{CryptographicOperations.ZeroMemory(key);}
    }
    public void Change(LoginSession session,string currentPassword,string newPassword,Action<string> persistBinding)
    {
        session.RequireAdmin();if(session.UserId!="admin")throw new UnauthorizedAccessException("관리자 계정만 변경할 수 있습니다.");
        if(newPassword.Length is <8 or >128)throw new ArgumentException("새 비밀번호는 8~128자로 입력하세요.");if(newPassword==currentPassword)throw new ArgumentException("현재와 다른 비밀번호를 입력하세요.");
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(file))!);
        using var changeLock=new FileStream(file+".lock",FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None,1,FileOptions.DeleteOnClose);
        using var authenticated=Login(session.UserId,currentPassword);if(authenticated==null||!CryptographicOperations.FixedTimeEquals(authenticated.Key,session.Key))throw new UnauthorizedAccessException("현재 비밀번호가 올바르지 않습니다.");
        var salt=RandomNumberGenerator.GetBytes(32);var nonce=RandomNumberGenerator.GetBytes(12);var tag=new byte[16];var cipher=new byte[32];var key=Rfc2898DeriveBytes.Pbkdf2(newPassword,salt,600000,HashAlgorithmName.SHA256,32);
        try{using var aes=new AesGcm(key,16);aes.Encrypt(nonce,session.Key,cipher,tag,Encoding.UTF8.GetBytes("DRAS admin login v1:"+session.UserId));}finally{CryptographicOperations.ZeroMemory(key);}
        using var m=new MemoryStream();using(var w=new BinaryWriter(m,Encoding.UTF8,true)){w.Write("DRAS-ADMIN-1");w.Write(session.UserId);w.Write(salt);w.Write(nonce);w.Write(tag);w.Write(cipher);}var payload=m.ToArray();var bytes=payload.Concat(IcdProtection.Sign(session,payload)).ToArray();string digest=Convert.ToHexString(SHA256.HashData(bytes));var pending=file+"."+digest+".pending";
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(file))!);using(var f=new FileStream(pending,FileMode.CreateNew,FileAccess.Write)){f.Write(bytes);f.Flush(true);}File.SetAttributes(pending,FileAttributes.Hidden);
        try{persistBinding(digest);}catch{File.Delete(pending);throw;}
        // The signed binding is the commit point. A pending envelope is valid after a power loss or locked final file.
        try{File.Move(pending,file,true);File.SetAttributes(file,FileAttributes.Hidden);}catch(IOException){}catch(UnauthorizedAccessException){}
    }
}
