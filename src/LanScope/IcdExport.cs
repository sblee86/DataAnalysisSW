using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
namespace LanScope;

/// <summary>Explicit administrator plaintext export; never writes into the encrypted store.</summary>
public static class IcdExport
{
    public static readonly string[] Columns=["message","name","byte_offset","bit_offset","bit_length","type","endian","bit_order","scale","bias","unit","description","storage_bits","storage_bit_offset","message_size"];
    public static byte[] Csv(LoginSession session,RecordProfile profile)=>WithSource(session,profile,p=>CsvSchema(p.ParseSchema()));
    public static byte[] Struct(LoginSession session,RecordProfile profile)=>WithSource(session,profile,p=>Encoding.UTF8.GetBytes(CppStructExport.Generate(p.ParseSchema())));
    public static byte[] Package(LoginSession session,RecordProfile profile)=>WithSource(session,profile,p=>{
        var schema=p.ParseSchema();using var memory=new MemoryStream();
        using(var zip=new ZipArchive(memory,ZipArchiveMode.Create,true)){
            void Add(string path,byte[] content){using var file=zip.CreateEntry(path,CompressionLevel.Optimal).Open();file.Write(content);}
            Add("icd-edit.csv",CsvSchema(schema));Add("original/source.csv",p.IcdContent);
            int i=0;foreach(var source in p.StructSources)Add($"original/headers/{++i:D3}_{SafeName(source.Name)}",source.Content);
            Add("icd-struct.hpp",Encoding.UTF8.GetBytes(CppStructExport.Generate(schema)));
            Add("dras-wire.hpp",Encoding.UTF8.GetBytes(Cpp(schema)));
            Add("import-options.json",JsonSerializer.SerializeToUtf8Bytes(new{p.ByteOrder,p.StructPack,p.StructBitOrder,p.Enabled,p.IcdName,Headers=p.StructSources.Select((s,n)=>new{OriginalName=s.Name,ExportPath=$"original/headers/{n+1:D3}_{SafeName(s.Name)}"})}));
            Add("README.txt",Encoding.UTF8.GetBytes("DRAS administrator plaintext export\r\n1. Edit icd-edit.csv in Excel, save CSV UTF-8, and import it alone with byte order 'CSV field settings'. Expanded fields include storage_bits/storage_bit_offset/message_size; retain these columns for bit layout and tail padding.\r\n2. To edit the original C/C++ struct instead, edit original/headers and import them together with original/source.csv using import-options.json settings. Original bytes and original field names are retained.\r\n3. icd-struct.hpp contains editable typed struct declarations (native ABI is compiler-dependent; CSV retains wire offsets/scaling). dras-wire.hpp is generated C++17 wire-buffer structs with raw field read/write helpers and metadata. It uses explicit byte/bit mappings, not compiler bitfield ABI. It is for C++ integration, not an input header for the restricted struct importer. Re-import the CSV or original declaration headers.\r\nExports are plaintext by explicit administrator request. Internal storage remains encrypted. No passwords, keys or capture files are exported.\r\n"));
        }return memory.ToArray();
    });
    private static T WithSource<T>(LoginSession session,RecordProfile source,Func<RecordProfile,T> action)
    {
        session.RequireAdmin();if(source.IcdContent.Length>0)return action(source);
        var temporary=new RecordProfile{Id=source.Id,IcdId=source.IcdId,EncryptedIcd=source.EncryptedIcd,ByteOrder=source.ByteOrder,StructPack=source.StructPack,StructBitOrder=source.StructBitOrder,Enabled=source.Enabled};
        try{IcdProtection.Open(session,temporary);return action(temporary);}finally{temporary.ClearPlaintext();}
    }
    private static string SafeName(string name){var safe=new string(name.Select(c=>char.IsAsciiLetterOrDigit(c)||c is '.' or '_' or '-'?c:'_').ToArray());return safe.Length==0?"source.h":safe;}
    private static byte[] CsvSchema(IcdSchema schema)
    {
        string Quote(string value)=>"\""+value.Replace("\"","\"\"")+"\"";
        string N(object value)=>Convert.ToString(value,CultureInfo.InvariantCulture)!;
        var text=new StringBuilder();text.AppendLine(string.Join(",",Columns.Select(Quote)));
        foreach(var f in schema.Fields)text.AppendLine(string.Join(",",new[]{f.Message,f.Name,N(f.ByteOffset),N(f.BitOffset),N(f.BitLength),f.Type,f.Endian,f.BitOrder,N(f.Scale),N(f.Bias),f.Unit,f.Description,N(f.StorageBits),N(f.StorageBitOffset),N(schema.RequiredBytes(f.Message))}.Select(Quote)));
        var utf8=new UTF8Encoding(true);return utf8.GetPreamble().Concat(utf8.GetBytes(text.ToString())).ToArray();
    }
    private static string CppString(string value)=>"\""+string.Concat(Encoding.UTF8.GetBytes(value).Select(b=>b is >=32 and <=126 && b is not (34 or 92)?((char)b).ToString():"\\"+Convert.ToString(b,8).PadLeft(3,'0')))+"\"";
    private static string CppNumber(decimal value){var text=value.ToString(CultureInfo.InvariantCulture);return text.Contains('.')?text:text+".0";}
    private static string Cpp(IcdSchema schema)
    {
        // Names are numeric to avoid invalid identifiers, keywords and collisions; source names are strings.
        var b=new StringBuilder("// DRAS generated C++17 wire structs. Raw values; signed/IEEE/scaling described by metadata.\n#pragma once\n#include <cstdint>\n#include <cstddef>\n#include <stdexcept>\nnamespace dras {\nstruct field_info { const char* name; const char* type; const char* unit; double scale; double bias; };\n");
        int messageIndex=0;foreach(var message in schema.Messages){var fields=schema.Fields.Where(f=>f.Message==message).ToArray();string type="message_"+(++messageIndex);int size=schema.RequiredBytes(message);
            b.AppendLine($"struct {type} {{");b.AppendLine($"  std::uint8_t wire[{size}]{{}};");b.AppendLine($"  static constexpr const char* message_name = {CppString(message)};");
            int fieldIndex=0;foreach(var f in fields){string id="field_"+(++fieldIndex);b.AppendLine($"  inline static constexpr field_info {id}{{{CppString(f.Name)}, {CppString(f.Type)}, {CppString(f.Unit)}, {CppNumber(f.Scale)}, {CppNumber(f.Bias)}}};");
                if(f.Type=="bytes"){b.AppendLine($"  std::uint8_t* {id}_bytes() {{ return wire + {f.ByteOffset}; }}");b.AppendLine($"  const std::uint8_t* {id}_bytes() const {{ return wire + {f.ByteOffset}; }}");b.AppendLine($"  static constexpr std::size_t {id}_size = {f.BitLength/8};");continue;}
                // Map numeric bit index -> physical bit; independent of host endian/ABI.
                var mappings=NumericPhysicalBits(f);b.AppendLine($"  inline static constexpr unsigned {id}_bits[{f.BitLength}]{{{string.Join(",",mappings)}}};");
                b.AppendLine($"  std::uint64_t read_{id}() const {{ std::uint64_t v=0; for(unsigned i=0;i<{f.BitLength};++i) {{ const auto p={id}_bits[i]; v |= std::uint64_t((wire[p/8]>>(p%8))&1u)<<i; }} return v; }}");
                b.AppendLine($"  void write_{id}(std::uint64_t v) {{ {(f.BitLength<64?$"if(v >> {f.BitLength}) throw std::out_of_range(\"raw field width\");":"")} for(unsigned i=0;i<{f.BitLength};++i) {{ const auto p={id}_bits[i]; const unsigned mask=1u<<(p%8); wire[p/8]=std::uint8_t((wire[p/8]&~mask)|(((v>>i)&1u)<<(p%8))); }} }}");
            }b.AppendLine("};");b.AppendLine($"static_assert(sizeof({type}) == {size}, \"wire size\");");
        }return b.AppendLine("} // namespace dras").ToString();
    }
    internal static int[] NumericPhysicalBits(IcdField f)
    {
        var bits=new int[f.BitLength];if(f.StorageBits>0){int start=f.BitOrder=="lsb0"?f.StorageBitOffset:f.StorageBits-f.StorageBitOffset-f.BitLength;for(int i=0;i<f.BitLength;i++){int bit=start+i,offset=f.Endian=="le"?bit/8:f.StorageBits/8-1-bit/8;bits[i]=(f.ByteOffset+offset)*8+bit%8;}}
        else {int left=f.BitLength,index=f.ByteOffset,position=f.BitOffset,done=0;while(left>0){int take=Math.Min(8-position,left),shift=f.BitOrder=="lsb0"?position:8-position-take,numeric=f.Endian=="le"?done:left-take;for(int k=0;k<take;k++)bits[numeric+k]=index*8+shift+k;left-=take;done+=take;index++;position=0;}}return bits;
    }
}
