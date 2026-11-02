using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LanScope;
public sealed class SettingsStore(string? filePath = null)
{
    public string FilePath { get; } = filePath ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"LANscope","workspace.bin");
    public WorkspaceSettings Load()
    {
        if(!File.Exists(FilePath)) return new();
        var bytes=File.ReadAllBytes(FilePath);
        if(bytes.Length<8 || Encoding.ASCII.GetString(bytes,0,8)!="LSCFG001") throw new InvalidDataException("설정파일 형식 오류. 원본 파일은 유지됩니다.");
        var plain=Protect(bytes[8..],false);
        try { return JsonSerializer.Deserialize<WorkspaceSettings>(plain)??throw new InvalidDataException("설정파일이 비어 있습니다."); }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }
    public void Save(LoginSession session, WorkspaceSettings settings)
    {
        session.RequireAdmin();
        var plain=JsonSerializer.SerializeToUtf8Bytes(settings); byte[] encrypted;
        try { encrypted=Protect(plain,true); } finally { CryptographicOperations.ZeroMemory(plain); }
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        var temp=FilePath+"."+Guid.NewGuid().ToString("N")+".tmp";
        try {
            using(var file=new FileStream(temp,FileMode.CreateNew,FileAccess.Write)) { file.Write(Encoding.ASCII.GetBytes("LSCFG001"));file.Write(encrypted);file.Flush(true); }
            File.SetAttributes(temp,FileAttributes.Hidden);
            if(File.Exists(FilePath)) File.Replace(temp,FilePath,null); else File.Move(temp,FilePath);
        } finally { if(File.Exists(temp)) File.Delete(temp); }
    }
    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Size; public IntPtr Data; }
    [DllImport("crypt32.dll",SetLastError=true,CharSet=CharSet.Unicode)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref Blob input,string description,IntPtr entropy,IntPtr reserved,IntPtr prompt,int flags,out Blob output);
    [DllImport("crypt32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref Blob input,IntPtr description,IntPtr entropy,IntPtr reserved,IntPtr prompt,int flags,out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    private static byte[] Protect(byte[] bytes,bool encrypt)
    {
        var input=new Blob {Size=bytes.Length,Data=Marshal.AllocHGlobal(bytes.Length)}; Blob output=default;
        try {
            Marshal.Copy(bytes,0,input.Data,bytes.Length);
            bool ok=encrypt?CryptProtectData(ref input,"LANscope workspace",IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,1,out output):CryptUnprotectData(ref input,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,1,out output);
            if(!ok) throw new CryptographicException(Marshal.GetLastWin32Error());
            var result=new byte[output.Size]; Marshal.Copy(output.Data,result,0,result.Length);return result;
        } finally { for(int i=0;i<input.Size;i++) Marshal.WriteByte(input.Data,i,0);Marshal.FreeHGlobal(input.Data);if(output.Data!=IntPtr.Zero)LocalFree(output.Data); }
    }
}
