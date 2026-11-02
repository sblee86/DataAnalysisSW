using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace LanScope;
public sealed record ProtectionMigration(int Updated,int Skipped,List<string> Errors);
public static class LegacySessionProtection
{
    public static ProtectionMigration ProtectFolder(LoginSession admin,string root)
    {
        admin.RequireAdmin();int updated=0,skipped=0;var errors=new List<string>();
        if(!Directory.Exists(root))throw new DirectoryNotFoundException("기록 폴더가 없습니다.");
        var options=new EnumerationOptions{RecurseSubdirectories=true,AttributesToSkip=FileAttributes.ReparsePoint,IgnoreInaccessible=false};
        foreach(var path in Directory.EnumerateFiles(root,"session.bin",options)) {
            byte[]? bytes=null;
            try {
                if(new FileInfo(path).Length>128*1024*1024)throw new IOException("128 MB 초과 메타데이터는 자동 변환하지 않습니다.");
                bytes=File.ReadAllBytes(path);string header;
                try{using var reader=new BinaryReader(new MemoryStream(bytes),Encoding.UTF8);header=reader.ReadString();}catch{skipped++;continue;}
                if(header!="LANSCOPE-SESSION-1"){skipped++;continue;}
                var encrypted=IcdProtection.Encrypt(admin,"legacy-session-metadata",bytes);string temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
                try{using(var file=new FileStream(temp,FileMode.CreateNew,FileAccess.Write)){file.Write(encrypted);file.Flush(true);}File.SetAttributes(temp,FileAttributes.Hidden);File.Replace(temp,path,null);updated++;}
                finally{if(File.Exists(temp))File.Delete(temp);}
            }catch(Exception error) when(error is IOException or UnauthorizedAccessException or CryptographicException){errors.Add(Path.GetRelativePath(root,path)+": "+error.Message);}
            finally{if(bytes!=null)CryptographicOperations.ZeroMemory(bytes);}
        }
        return new(updated,skipped,errors);
    }
}
