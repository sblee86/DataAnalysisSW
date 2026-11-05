using System.IO;
namespace LanScope;
public sealed record UiLayoutOptions(int Body=13,int Menu=13,int Table=12,int TableHeader=12,int Title=28,int ProfileWidth=260,int NicPercent=60,int TestNameFont=18,int TestNameWidth=520,int TestNameHeight=72,int WindowWidth=1600,int WindowHeight=1000,bool Maximized=true,int IcdTableHeight=360)
{
    public void Validate(){if(Body is <12 or >20||Menu is <12 or >20||Table is <10 or >20||TableHeader is <11 or >22||Title is <20 or >36||ProfileWidth is <180 or >500||NicPercent is <30 or >75||TestNameFont is <12 or >36||TestNameWidth is <240 or >900||TestNameHeight is <56 or >180||WindowWidth is <1000 or >3840||WindowHeight is <680 or >2160||IcdTableHeight is <200 or >1200)throw new ArgumentOutOfRangeException(nameof(UiLayoutOptions));}
}
public sealed class UiPreferences(string? path=null)
{
    private readonly string file=path??Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"DRAS","ui-preferences.bin");
    public UiLayoutOptions LoadLayout()
    {
        try{if(!File.Exists(file))return new();using var r=new BinaryReader(File.OpenRead(file));string magic=r.ReadString();if(magic=="DAS-UI-1")return new(Body:Math.Clamp(r.ReadInt32(),12,18));if(magic is not ("DRAS-UI-2" or "DRAS-UI-3" or "DRAS-UI-4"))return new();var v=new UiLayoutOptions(r.ReadInt32(),r.ReadInt32(),r.ReadInt32(),r.ReadInt32(),r.ReadInt32(),r.ReadInt32(),r.ReadInt32());if(magic is "DRAS-UI-3" or "DRAS-UI-4")v=v with{TestNameFont=r.ReadInt32(),TestNameWidth=r.ReadInt32(),TestNameHeight=r.ReadInt32()};if(magic=="DRAS-UI-4")v=v with{WindowWidth=r.ReadInt32(),WindowHeight=r.ReadInt32(),Maximized=r.ReadBoolean(),IcdTableHeight=r.ReadInt32()};v.Validate();return v;}catch(Exception e) when(e is IOException or UnauthorizedAccessException or ArgumentOutOfRangeException){return new();}
    }
    public int LoadFontSize()=>LoadLayout().Body;
    public void SaveFontSize(int size){if(size is <12 or >18)throw new ArgumentOutOfRangeException(nameof(size));SaveLayout(LoadLayout() with{Body=size});}
    public void SaveLayout(UiLayoutOptions value)
    {
        value.Validate();Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(file))!);var temp=file+"."+Guid.NewGuid().ToString("N")+".tmp";
        try{using(var w=new BinaryWriter(File.Create(temp))){w.Write("DRAS-UI-4");foreach(int n in new[]{value.Body,value.Menu,value.Table,value.TableHeader,value.Title,value.ProfileWidth,value.NicPercent,value.TestNameFont,value.TestNameWidth,value.TestNameHeight})w.Write(n);w.Write(value.WindowWidth);w.Write(value.WindowHeight);w.Write(value.Maximized);w.Write(value.IcdTableHeight);}File.SetAttributes(temp,FileAttributes.Hidden);if(File.Exists(file))File.Replace(temp,file,null);else File.Move(temp,file);}
        finally{if(File.Exists(temp))File.Delete(temp);}
    }
}
