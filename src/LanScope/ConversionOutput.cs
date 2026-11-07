using System.Globalization;
using System.IO;
namespace LanScope;
public sealed record ConversionSaveOptions(bool Automatic=false,bool TimestampFolder=false,string OutputDirectory="")
{
    public string Folder {get{if(!string.IsNullOrWhiteSpace(OutputDirectory))return OutputDirectory;var documents=Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);if(documents.Length==0)documents=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),"Documents");return Path.Combine(documents,"DRAS","CsvExports");}}
    public void Validate(){if(!Path.IsPathFullyQualified(Folder))throw new ArgumentException("CSV 저장 경로는 절대 경로로 입력하세요.");}
}
public sealed class ConversionPreferences(string? path=null)
{
    private readonly string file=path??Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"DRAS","conversion-preferences.bin");
    public ConversionSaveOptions Load(){try{if(!File.Exists(file))return new();using var r=new BinaryReader(File.OpenRead(file));if(r.ReadString()!="DRAS-CSV-1")return new();var value=new ConversionSaveOptions(r.ReadBoolean(),r.ReadBoolean(),r.ReadString());value.Validate();return value;}catch(Exception e) when(e is IOException or UnauthorizedAccessException or ArgumentException){return new();}}
    public void Save(ConversionSaveOptions value){value.Validate();Directory.CreateDirectory(Path.GetDirectoryName(file)!);string temp=file+"."+Guid.NewGuid().ToString("N")+".tmp";try{using(var w=new BinaryWriter(File.Create(temp))){w.Write("DRAS-CSV-1");w.Write(value.Automatic);w.Write(value.TimestampFolder);w.Write(value.Folder);}File.SetAttributes(temp,FileAttributes.Hidden);if(File.Exists(file))File.Replace(temp,file,null);else File.Move(temp,file);}finally{if(File.Exists(temp))File.Delete(temp);}}
}
public static class ConversionOutput
{
    public static string LogPath(string csv)=>Path.Combine(Path.GetDirectoryName(csv)!,Path.GetFileNameWithoutExtension(csv)+".conversion.log.txt");
    public static string FileStem(string name){const string invalid="<>:\"/\\|?*";string safe=new(name.Select(c=>char.IsControl(c)||invalid.Contains(c)?'_':c).Take(80).ToArray());safe=safe.Trim().Trim('.');return safe.Length==0?"interface":safe;}
    public static string Plan(ConversionSaveOptions options,string interfaceName,DateTime localTime,string? manualPath=null)
    {
        options.Validate();string stamp=localTime.ToString("yyyyMMdd_HHmmss",CultureInfo.InvariantCulture);string folder=options.Automatic?options.Folder:Path.GetDirectoryName(Path.GetFullPath(manualPath??throw new ArgumentException("수동 저장 파일을 선택하세요.")))!;
        if(options.TimestampFolder){string root=Path.Combine(folder,stamp);folder=root;for(int i=1;Directory.Exists(folder)||File.Exists(folder);i++)folder=root+"_"+i.ToString("D3",CultureInfo.InvariantCulture);}
        Directory.CreateDirectory(folder);string file=options.Automatic?FileStem(interfaceName)+"_"+stamp+".csv":Path.GetFileName(manualPath!);
        if(!Path.GetExtension(file).Equals(".csv",StringComparison.OrdinalIgnoreCase))throw new ArgumentException("CSV 파일 확장자는 .csv여야 합니다.");
        string output=Path.Combine(folder,file);if(options.Automatic){string stem=Path.GetFileNameWithoutExtension(file);for(int i=1;File.Exists(output)||Directory.Exists(output)||File.Exists(LogPath(output));i++)output=Path.Combine(folder,stem+"_"+i.ToString("D3",CultureInfo.InvariantCulture)+".csv");}return output;
    }
}
