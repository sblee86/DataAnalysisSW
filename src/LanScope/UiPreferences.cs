using System.IO;
namespace LanScope;
public sealed record UiLayoutOptions(int Body=13,int Menu=13,int Table=12,int TableHeader=12,int Title=28,int ProfileWidth=260,int NicPercent=60)
{
    public void Validate(){if(Body is <12 or >20||Menu is <12 or >20||Table is <10 or >20||TableHeader is <11 or >22||Title is <20 or >36||ProfileWidth is <180 or >500||NicPercent is <30 or >75)throw new ArgumentOutOfRangeException(nameof(UiLayoutOptions));}
}
public sealed class UiPreferences(string? path=null)
{
    private readonly string file=path??Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"DRAS","ui-preferences.bin");
    public UiLayoutOptions LoadLayout()
    {
        try{if(!File.Exists(file))return new();using var r=new BinaryReader(File.OpenRead(file));string magic=r.ReadString();if(magic=="DAS-UI-1")return new(Body:Math.Clamp(r.ReadInt32(),12,18));if(magic!="DRAS-UI-2")return new();var v=new UiLayoutOptions(r.ReadInt32(),r.ReadInt32(),r.ReadInt32(),r.ReadInt32(),r.ReadInt32(),r.ReadInt32(),r.ReadInt32());v.Validate();return v;}catch(Exception e) when(e is IOException or UnauthorizedAccessException or ArgumentOutOfRangeException){return new();}
    }
    public int LoadFontSize()=>LoadLayout().Body;
    public void SaveFontSize(int size){if(size is <12 or >18)throw new ArgumentOutOfRangeException(nameof(size));SaveLayout(LoadLayout() with{Body=size});}
    public void SaveLayout(UiLayoutOptions value)
    {
        value.Validate();Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(file))!);var temp=file+"."+Guid.NewGuid().ToString("N")+".tmp";
        try{using(var w=new BinaryWriter(File.Create(temp))){w.Write("DRAS-UI-2");foreach(int n in new[]{value.Body,value.Menu,value.Table,value.TableHeader,value.Title,value.ProfileWidth,value.NicPercent})w.Write(n);}File.SetAttributes(temp,FileAttributes.Hidden);if(File.Exists(file))File.Replace(temp,file,null);else File.Move(temp,file);}
        finally{if(File.Exists(temp))File.Delete(temp);}
    }
}
