using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
namespace LanScope;

/// <summary>Readable C/C++ declarations. Native structure ABI is separate from ICD wire offsets.</summary>
internal static class CppStructExport
{
    private static readonly HashSet<string> Keywords=new(("alignas alignof and and_eq asm atomic_cancel atomic_commit atomic_noexcept auto bitand bitor bool break case catch char char8_t char16_t char32_t class compl concept const consteval constexpr constinit const_cast continue co_await co_return co_yield decltype default delete do double dynamic_cast else enum explicit export extern false float for friend goto if inline int long mutable namespace new noexcept not not_eq nullptr operator or or_eq private protected public reflexpr register reinterpret_cast requires return short signed sizeof static static_assert static_cast struct switch synchronized template this thread_local throw true try typedef typeid typename union unsigned using virtual void volatile wchar_t while xor xor_eq uint8_t uint16_t uint32_t uint64_t int8_t int16_t int32_t int64_t").Split(' '));
    private static string Identifier(string source,string fallback,HashSet<string> used)
    {
        string name=Regex.Replace(source,"[^A-Za-z0-9_]","_");if(name.Length==0||name.All(c=>c=='_'))name=fallback;
        if(!char.IsAsciiLetter(name[0])||Keywords.Contains(name)||name.Contains("__"))name="icd_"+Regex.Replace(name,"_+","_").Trim('_');
        string candidate=name;int n=2;while(!used.Add(candidate))candidate=name+"_"+n++;return candidate;
    }
    internal static string Generate(IcdSchema schema)
    {
        var b=new StringBuilder("// DRAS - editable C/C++ structure declarations\n// Native endian/bitfield ABI depends on compiler. CSV retains exact wire offsets and scaling.\n#pragma once\n#include <stdint.h>\n#pragma pack(push, 1)\n\n");var types=new HashSet<string>();
        foreach(var message in schema.Messages){string name=Identifier(message,"Message",types);b.AppendLine($"// ICD message: {Comment(message)} | wire bytes: {schema.RequiredBytes(message)}");b.AppendLine($"struct {name} {{");var members=new HashSet<string>();int index=0;
            foreach(var f in schema.Fields.Where(f=>f.Message==message)){
                string member=Identifier(f.Name,"field_"+(++index),members);int bits=f.StorageBits>0?f.StorageBits:f.BitLength<=8?8:f.BitLength<=16?16:f.BitLength<=32?32:64;
                string type=f.Type switch{"float32"=>"float","float64"=>"double","bool" when f.BitLength==8=>"bool","int"=>"int"+bits+"_t",_=>"uint"+bits+"_t"};
                bool isBits=f.Type is "int" or "uint" or "bool"&&(f.StorageBits>0||f.BitOffset!=0||f.BitLength is not (8 or 16 or 32 or 64));
                string declaration=f.Type=="bytes"?$"uint8_t {member}[{f.BitLength/8}]":$"{type} {member}"+(isBits?$" : {f.BitLength}":"");
                string note=$"{f.Name} | byte={f.ByteOffset}, bit={f.BitOffset}, bits={f.BitLength}, endian={f.Endian}, bit_order={f.BitOrder}, scale={f.Scale.ToString(CultureInfo.InvariantCulture)}, bias={f.Bias.ToString(CultureInfo.InvariantCulture)}";
                if(f.Minimum.HasValue||f.Maximum.HasValue)note+=$", min={f.Minimum?.ToString(CultureInfo.InvariantCulture)??"none"}, max={f.Maximum?.ToString(CultureInfo.InvariantCulture)??"none"}";
                if(f.StorageBits>0)note+=$", storage={f.StorageBits}:{f.StorageBitOffset}";
                if(f.Unit.Length>0)note+=" | unit="+f.Unit;if(f.Description.Length>0)note+=" | "+f.Description;
                b.AppendLine($"    {declaration}; // {Comment(note)} |");
            }b.AppendLine("};\n");
        }
        return b.AppendLine("#pragma pack(pop)").ToString();
    }
    private static string Comment(string value)=>new(value.Select(c=>char.IsControl(c)||c is '\u2028' or '\u2029'?' ':c).ToArray());
}
