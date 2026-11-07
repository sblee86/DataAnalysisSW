using System.Text;
namespace LanScope;

/// <summary>Build a validated editor candidate before replacing any current source.</summary>
public static class IcdImport
{
    public static byte[] DeleteMessage(IcdSchema schema,string message)
    {
        if(!schema.Messages.Contains(message))throw new ArgumentException("삭제할 메시지를 선택하세요.");
        var result=new IcdSchema();result.Fields.AddRange(schema.Fields.Where(f=>f.Message!=message));if(result.Fields.Count==0)return [];
        foreach(var m in result.Messages)result.MessageSizes[m]=schema.RequiredBytes(m);
        var bytes=IcdExport.CsvSchema(result);IcdCsv.Parse(bytes);return bytes;
    }
    public static byte[] Merge(IcdSchema current,IcdSchema incoming)
    {
        var combined=new IcdSchema();combined.Fields.AddRange(current.Fields);combined.Fields.AddRange(incoming.Fields);
        foreach(var message in combined.Messages)combined.MessageSizes[message]=Math.Max(current.RequiredBytes(message),incoming.RequiredBytes(message));
        var bytes=IcdExport.CsvSchema(combined);IcdCsv.Parse(bytes);return bytes;
    }
    public static byte[] FromHeaders(IReadOnlyList<StructSource> sources,int pack,string endian,string bitOrder,IReadOnlySet<string>? messageFiles=null,string excludedType="")
    {
        _ = excludedType; // Legacy argument: choosing a header role never suppresses a selected message type.
        var layouts=CStructParser.Parse(sources,pack,endian,bitOrder);var schema=new IcdSchema();
        var selectedFiles=messageFiles?.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var candidates=layouts.Values.DistinctBy(x=>x.Name).Where(x=>selectedFiles==null||selectedFiles.Contains(x.SourceName)).ToList();
        // Choosing fields from a full message does not turn that entire type into a header-only dependency.
        // Only nested helper types of the selected messages are dependencies, regardless of the chosen header name.
        var dependencies=candidates.SelectMany(x=>x.ReferencedTypes??[]).ToHashSet(StringComparer.Ordinal);
        foreach(var layout in candidates.Where(x=>!dependencies.Contains(x.Name))){
            schema.Fields.AddRange(layout.Fields);schema.MessageSizes[layout.Name]=layout.Size;
        }
        if(schema.Fields.Count==0)throw new ArgumentException("선택 파일에 가져올 메시지 구조체가 없습니다. 선택 파일의 최상위 메시지 구조체를 확인하세요.");var bytes=IcdExport.CsvSchema(schema);IcdCsv.Parse(bytes);return bytes;
    }
    public static List<StructSource> CombineHeaders(IReadOnlyList<StructSource> current,IReadOnlyList<StructSource> incoming)
    {
        var result=current.Select(s=>new StructSource(s.Name,[..s.Content])).ToList();
        foreach(var source in incoming){var old=result.FirstOrDefault(s=>s.Name.Equals(source.Name,StringComparison.OrdinalIgnoreCase));if(old!=null){if(!old.Content.SequenceEqual(source.Content))throw new ArgumentException("같은 이름의 헤더 내용이 다릅니다. 교체를 사용하세요: "+source.Name);continue;}result.Add(new(source.Name,[..source.Content]));}
        return result;
    }
}
