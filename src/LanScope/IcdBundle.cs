using System.IO;
using System.Text;
using System.Security.Cryptography;
namespace LanScope;
internal static class IcdBundle
{
    private static readonly byte[] Magic=Encoding.ASCII.GetBytes("DRASICD2");
    internal static byte[] Pack(RecordProfile p)
    {
        if(p.IcdContent.Length is <1 or >16777216||p.StructSources.Count>128||p.StructSources.Sum(s=>(long)s.Content.Length)>16777216||p.StructSources.Any(s=>s.Content.Length==0||s.Name.Length>255))throw new ArgumentException("ICD 번들 크기/이름 오류");
        if(p.StructSources.Count==0)return [..p.IcdContent];
        using var m=new MemoryStream();using(var w=new BinaryWriter(m,Encoding.UTF8,true)){w.Write(Magic);w.Write(p.IcdContent.Length);w.Write(p.IcdContent);w.Write(p.StructSources.Count);foreach(var s in p.StructSources.OrderBy(s=>s.Name,StringComparer.Ordinal)){w.Write(s.Name);w.Write(s.Content.Length);w.Write(s.Content);}}return m.ToArray();
    }
    internal static void Unpack(byte[] data,RecordProfile p)
    {
        if(!data.AsSpan().StartsWith(Magic)){p.IcdContent=[..data];return;}
        using var r=new BinaryReader(new MemoryStream(data),Encoding.UTF8);r.ReadBytes(8);
        byte[] Read(){int n=r.ReadInt32();if(n<1||n>16*1024*1024||n>r.BaseStream.Length-r.BaseStream.Position)throw new InvalidDataException("ICD bundle 크기 오류");return r.ReadBytes(n);}
        p.IcdContent=Read();int count=r.ReadInt32();if(count<1||count>128)throw new InvalidDataException("헤더 개수 오류");p.StructSources=[];
        for(int i=0;i<count;i++){string name=r.ReadString();if(name.Length>255)throw new InvalidDataException("헤더 이름 오류");p.StructSources.Add(new(name,Read()));}
        if(r.BaseStream.Position!=r.BaseStream.Length||p.StructSources.Sum(s=>(long)s.Content.Length)>16*1024*1024)throw new InvalidDataException("ICD bundle 형식 오류");
    }
    internal static string Fingerprint(RecordProfile p){var b=Pack(p);try{return Convert.ToHexString(SHA256.HashData(b));}finally{CryptographicOperations.ZeroMemory(b);}}
}
