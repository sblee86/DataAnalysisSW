using System.IO;
namespace LanScope;
public sealed class UiPreferences(string? path=null)
{
    private readonly string file=path??Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"SAAM_DAS","ui-preferences.bin");
    public int LoadFontSize()
    {
        try{if(!File.Exists(file))return 13;using var reader=new BinaryReader(File.OpenRead(file));if(reader.ReadString()!="DAS-UI-1")return 13;int size=reader.ReadInt32();return size is >=12 and <=18?size:13;}catch(IOException){return 13;}catch(UnauthorizedAccessException){return 13;}
    }
    public void SaveFontSize(int size)
    {
        if(size is <12 or >18)throw new ArgumentOutOfRangeException(nameof(size));Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(file))!);var temp=file+"."+Guid.NewGuid().ToString("N")+".tmp";
        try{using(var writer=new BinaryWriter(File.Create(temp))){writer.Write("DAS-UI-1");writer.Write(size);}File.SetAttributes(temp,FileAttributes.Hidden);if(File.Exists(file))File.Replace(temp,file,null);else File.Move(temp,file);}
        finally{if(File.Exists(temp))File.Delete(temp);}
    }
}
