using System.Text;
namespace LanScope;

/// <summary>Build a validated editor candidate before replacing any current source.</summary>
public static class IcdImport
{
    public static byte[] Merge(IcdSchema current,IcdSchema incoming)
    {
        var combined=new IcdSchema();combined.Fields.AddRange(current.Fields);combined.Fields.AddRange(incoming.Fields);
        foreach(var message in combined.Messages)combined.MessageSizes[message]=Math.Max(current.RequiredBytes(message),incoming.RequiredBytes(message));
        var bytes=IcdExport.CsvSchema(combined);IcdCsv.Parse(bytes);return bytes;
    }
    public static byte[] FromHeaders(IReadOnlyList<StructSource> sources,int pack,string endian,string bitOrder)
    {
        var layouts=CStructParser.Parse(sources,pack,endian,bitOrder);var schema=new IcdSchema();
        foreach(var layout in layouts.Values.DistinctBy(x=>x.Name)){
            schema.Fields.AddRange(layout.Fields);schema.MessageSizes[layout.Name]=layout.Size;
        }
        var bytes=IcdExport.CsvSchema(schema);IcdCsv.Parse(bytes);return bytes;
    }
    public static List<StructSource> CombineHeaders(IReadOnlyList<StructSource> current,IReadOnlyList<StructSource> incoming)
    {
        var result=current.Select(s=>new StructSource(s.Name,[..s.Content])).ToList();
        foreach(var source in incoming){var old=result.FirstOrDefault(s=>s.Name.Equals(source.Name,StringComparison.OrdinalIgnoreCase));if(old!=null){if(!old.Content.SequenceEqual(source.Content))throw new ArgumentException("같은 이름의 헤더 내용이 다릅니다. 교체를 사용하세요: "+source.Name);continue;}result.Add(new(source.Name,[..source.Content]));}
        return result;
    }
}
