using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LanScope;
public sealed class SettingsStore(string? filePath = null, byte[]? policyPublicKey = null, byte[]? guestPublicKey = null)
{
    public string FilePath { get; } = filePath ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"LANscope","workspace.bin");
    private byte[] PublicKey()
    {
        if(policyPublicKey!=null)return policyPublicKey;
        var assembly=typeof(SettingsStore).Assembly;
        using var stream=assembly.GetManifestResourceStream("LanScope.Resources.policy-public.bin")??throw new InvalidDataException("설정 검증키가 없습니다.");
        using var output=new MemoryStream();stream.CopyTo(output);return output.ToArray();
    }
    public string ReadCredentialDigest()=>ReadAuthProperty("AdminCredentialDigest");
    public byte[] ReadGuestLoginEnvelope()=>Convert.FromBase64String(ReadAuthProperty("GuestLoginEnvelope"));
    private string ReadAuthProperty(string property)
    {
        if(!File.Exists(FilePath))return "";var bytes=File.ReadAllBytes(FilePath);
        if(bytes.Length<8)throw new InvalidDataException("설정파일 형식 오류");if(Encoding.ASCII.GetString(bytes,0,8)=="LSCFG001")return "";
        if(bytes.Length<72||Encoding.ASCII.GetString(bytes,0,8)!="LSCFG002")throw new InvalidDataException("설정파일 형식 오류");
        IcdProtection.Verify(PublicKey(),bytes[..8].Concat(bytes[72..]).ToArray(),bytes[8..72]);var plain=Protect(bytes[72..],false);
        try{using var json=JsonDocument.Parse(plain);return json.RootElement.TryGetProperty(property,out var digest)?digest.GetString()??"":"";}finally{CryptographicOperations.ZeroMemory(plain);}
    }
    public WorkspaceSettings Load(LoginSession session)
    {
        if(!File.Exists(FilePath)) return new();
        var bytes=File.ReadAllBytes(FilePath);
        if(bytes.Length<8)throw new InvalidDataException("설정파일 형식 오류. 원본 파일은 유지됩니다.");
        string magic=Encoding.ASCII.GetString(bytes,0,8);
        if(magic=="LSCFG001") {
            session.RequireAdmin();var legacy=Protect(bytes[8..],false);
            try {
                using var json=JsonDocument.Parse(legacy);var upgraded=JsonSerializer.Deserialize<WorkspaceSettings>(legacy)!;
                var old=json.RootElement.GetProperty("Profiles").EnumerateArray().ToList();
                for(int i=0;i<upgraded.Profiles.Count;i++) {
                    var p=upgraded.Profiles[i];p.IcdName=old[i].GetProperty("IcdName").GetString()??"";p.IcdContent=old[i].GetProperty("IcdContent").GetBytesFromBase64();
                    // Legacy IDL must remain recoverable even though it is no longer a valid recording schema.
                    IcdProtection.Seal(session,p);
                }
                upgraded.GuestIcdAllowList.Clear();Save(session,upgraded);return upgraded;
            }finally{CryptographicOperations.ZeroMemory(legacy);}
        }
        if(magic!="LSCFG002"||bytes.Length<72)throw new InvalidDataException("설정파일 형식 오류. 원본 파일은 유지됩니다.");
        var ciphertext=bytes[72..];IcdProtection.Verify(PublicKey(),bytes[..8].Concat(ciphertext).ToArray(),bytes[8..72]);
        var plain=Protect(ciphertext,false);
        try {
            var settings=JsonSerializer.Deserialize<WorkspaceSettings>(plain)??throw new InvalidDataException("설정파일이 비어 있습니다.");
            if(session.Role==UserRole.Admin)CapturePolicyAccess.OpenShared(session,settings);
            if(session.Role==UserRole.Admin)foreach(var p in settings.Profiles){IcdProtection.Open(session,p);CapturePolicyAccess.OpenAdmin(session,p);}
            return settings.ForSession(session);
        }finally{CryptographicOperations.ZeroMemory(plain);}
    }
    public void Save(LoginSession session, WorkspaceSettings settings)
    {
        session.RequireAdmin();CapturePolicyAccess.SealShared(session,settings);
        foreach(var profile in settings.Profiles){IcdProtection.Seal(session,profile);CapturePolicyAccess.Seal(session,profile,(settings.GuestRecipientPublicKey.Length>0?settings.GuestRecipientPublicKey:guestPublicKey??GuestIcdAccess.EmbeddedPublicKey()));if(settings.GuestIcdAllowList.Contains(profile.IcdId))GuestIcdAccess.Seal(session,profile,(settings.GuestRecipientPublicKey.Length>0?settings.GuestRecipientPublicKey:guestPublicKey??GuestIcdAccess.EmbeddedPublicKey()));else profile.GuestConversionIcd=[];}
        settings.ValidateCaptureConflicts();
        settings.GuestIcdAllowList.RemoveAll(id=>!settings.Profiles.Any(p=>p.IcdId==id));
        var plain=JsonSerializer.SerializeToUtf8Bytes(settings); byte[] encrypted;
        try { encrypted=Protect(plain,true); } finally { CryptographicOperations.ZeroMemory(plain); }
        var signed=Encoding.ASCII.GetBytes("LSCFG002").Concat(encrypted).ToArray();
        var signature=IcdProtection.Sign(session,signed);IcdProtection.Verify(PublicKey(),signed,signature);
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        if(OperatingSystem.IsWindows()){var directory=Path.GetDirectoryName(FilePath)!;File.SetAttributes(directory,File.GetAttributes(directory)|FileAttributes.Hidden);}
        var temp=FilePath+"."+Guid.NewGuid().ToString("N")+".tmp";
        try {
            using(var file=new FileStream(temp,FileMode.CreateNew,FileAccess.Write)) { file.Write(Encoding.ASCII.GetBytes("LSCFG002"));file.Write(signature);file.Write(encrypted);file.Flush(true); }
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
