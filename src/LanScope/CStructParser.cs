using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace LanScope;
public sealed record StructSource(string Name,byte[] Content);
public sealed record StructLayoutInfo(string Name,int Size,int Alignment,IReadOnlyList<IcdField> Fields);
public static class CStructParser
{
    private sealed record Definition(string Name,string Body,int Pack);
    private sealed record Scalar(int Bytes,string Type);
    public static Dictionary<string,StructLayoutInfo> Parse(IReadOnlyList<StructSource> sources,int defaultPack=1,string endian="be",string bitOrder="lsb0")
    {
        if(defaultPack is not (1 or 2 or 4 or 8)||endian is not ("be" or "le")||bitOrder is not ("msb0" or "lsb0"))throw new ArgumentException("struct 패킹/엔디언/비트 순서 오류");
        if(sources.Count>128||sources.Sum(s=>(long)s.Content.Length)>16*1024*1024)throw new ArgumentException("struct 파일 합계는 최대 16 MB입니다.");
        var definitions=new Dictionary<string,Definition>(StringComparer.Ordinal);var aliases=new Dictionary<string,string>(StringComparer.Ordinal);var constants=new Dictionary<string,int>(StringComparer.Ordinal);
        var primitives=new Dictionary<string,Scalar>(StringComparer.OrdinalIgnoreCase){["uint8_t"]=new(1,"uint"),["int8_t"]=new(1,"int"),["uint16_t"]=new(2,"uint"),["int16_t"]=new(2,"int"),["uint32_t"]=new(4,"uint"),["int32_t"]=new(4,"int"),["uint64_t"]=new(8,"uint"),["int64_t"]=new(8,"int"),["uint8"]=new(1,"uint"),["uint16"]=new(2,"uint"),["uint32"]=new(4,"uint"),["uint64"]=new(8,"uint"),["unsigned char"]=new(1,"uint"),["signed char"]=new(1,"int"),["unsigned short"]=new(2,"uint"),["short"]=new(2,"int"),["unsigned int"]=new(4,"uint"),["int"]=new(4,"int"),["float"]=new(4,"float32"),["double"]=new(8,"float64"),["bool"]=new(1,"bool"),["BYTE"]=new(1,"uint"),["WORD"]=new(2,"uint"),["DWORD"]=new(4,"uint")};
        // Windows LLP64: char=1 (signed default), short=2, int/long=4, long long=8.
        foreach(var (names,bytes,kind) in new[]{("char",1,"int"),("signed short|short int|signed short int",2,"int"),("unsigned short int",2,"uint"),("long|long int|signed long|signed long int",4,"int"),("unsigned|unsigned long|unsigned long int",4,"uint"),("long long|long long int|signed long long|signed long long int|__int64",8,"int"),("unsigned long long|unsigned long long int|unsigned __int64",8,"uint")})
            foreach(var name in names.Split('|'))primitives[name]=new(bytes,kind);
        primitives["signed"]=primitives["signed int"]=new(4,"int");
        string Normalize(string value)=>Regex.Replace(Regex.Replace(value,@"\b(const|volatile)\b", " ").Trim(),@"\s+"," ");
        // Expand comma-separated members while retaining their shared declaration type.
        string Expand(string body)=>string.Join(";",body.Split(';').SelectMany(raw=>{
            var parts=raw.Split(',');if(parts.Length==1)return new[]{raw};
            var first=Regex.Match(parts[0].Trim(),@"^(?<type>(?:[A-Za-z_]\w*\s+)+)(?<member>[A-Za-z_]\w*(?:\s*\[.*?\])?(?:\s*:\s*\w+)?)$");
            if(!first.Success)throw new ArgumentException("미지원 복합 선언: "+raw);
            return new[]{parts[0]}.Concat(parts.Skip(1).Select(part=>first.Groups["type"].Value+part.Trim()));
        }));
        int Number(string text){text=text.Trim();if(constants.TryGetValue(text,out int value))return value;return text.StartsWith("0x",StringComparison.OrdinalIgnoreCase)?int.Parse(text[2..],NumberStyles.HexNumber,CultureInfo.InvariantCulture):int.Parse(text,CultureInfo.InvariantCulture);}
        string RemoveComments(string value)=>Regex.Replace(value,@"/\*[\s\S]*?\*/|//[^\r\n]*",m=>new string(m.Value.Select(c=>c is '\n' or '\r'?c:' ').ToArray()));
        foreach(var source in sources) {
            if(source.Content.Length==0)throw new ArgumentException("빈 struct 파일: "+source.Name);
            string text=RemoveComments(IcdCsv.DecodeText(source.Content).Text);var packEvents=new List<(int Index,int Pack)>{(0,defaultPack)};var stack=new Stack<int>();int pack=defaultPack;
            var directives=Regex.Matches(text,@"(?m)^\s*#([^\r\n]*)");string? guard=null;
            foreach(Match directive in directives) {
                string line=directive.Groups[1].Value.Trim();var pragma=Regex.Match(line,@"^pragma\s+pack\s*\(\s*(.*?)\s*\)$");
                if(pragma.Success){var args=pragma.Groups[1].Value.Split(',').Select(s=>s.Trim()).ToArray();if(args[0]=="push"){stack.Push(pack);if(args.Length==2)pack=Number(args[1]);else if(args.Length!=1)throw new ArgumentException("pragma pack 형식 오류");}else if(args[0]=="pop"){if(stack.Count==0||args.Length!=1)throw new ArgumentException("pragma pack pop 불일치");pack=stack.Pop();}else if(args.Length==1)pack=Number(args[0]);else throw new ArgumentException("pragma pack 형식 오류");if(pack is not (1 or 2 or 4 or 8))throw new ArgumentException("pack은 1/2/4/8만 지원합니다.");packEvents.Add((directive.Index+directive.Length,pack));}
                else if(line.StartsWith("include ")||line.StartsWith("include<")||line.StartsWith("pragma once")){/* Includes are not loaded or executed; select required headers explicitly. */}
                else if(Regex.IsMatch(line,@"^ifndef\s+\w+$")&&guard==null){guard=line.Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries)[1];}
                else if(Regex.IsMatch(line,@"^define\s+\w+(?:\s+(?:\d+|0x[0-9a-fA-F]+))?\s*$")){var parts=line.Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries);if(parts.Length==2){if(parts[1]!=guard)throw new ArgumentException("값 없는 define은 include guard만 지원합니다.");}else{int number=Number(parts[2]);if(!constants.TryAdd(parts[1],number)&&constants[parts[1]]!=number)throw new ArgumentException("중복 상수: "+parts[1]);}}
                else if(line=="endif"&&guard!=null){guard=null;}
                else throw new ArgumentException(source.Name+": 미지원 전처리 지시문 #"+line);
            }
            if(stack.Count!=0||guard!=null)throw new ArgumentException(source.Name+": 닫히지 않은 pack/include guard");
            text=Regex.Replace(text,@"(?m)^\s*#[^\r\n]*",m=>new string(' ',m.Length));
            if(Regex.IsMatch(text,@"\b(namespace|class|union|template|enum)\b"))throw new ArgumentException("namespace/class/union/template/enum은 명시적 CSV 필드로 변환해 주세요.");
            var matches=Regex.Matches(text,@"(?<typedef>typedef\s+)?struct(?:\s+(?<tag>[A-Za-z_]\w*))?\s*\{(?<body>[^{}]*)\}\s*(?<alias>[A-Za-z_]\w*)?\s*;");
            var residual=text.ToCharArray();
            foreach(Match match in matches) {
                var tag=match.Groups["tag"].Value;var alias=match.Groups["alias"].Value;string name=alias.Length>0?alias:tag;
                if(!match.Groups["typedef"].Success&&alias.Length>0)throw new ArgumentException("struct 인스턴스 선언은 지원하지 않습니다.");
                if(name.Length==0||definitions.ContainsKey(name))throw new ArgumentException("이름 없는/중복 struct: "+name);
                int ownPack=packEvents.Last(e=>e.Index<=match.Index).Pack;definitions.Add(name,new(name,Expand(match.Groups["body"].Value),ownPack));if(tag.Length>0&&tag!=name)aliases[tag]=name;
                for(int i=match.Index;i<match.Index+match.Length;i++)residual[i]=' ';
            }
            string rest=new(residual);
            rest=Regex.Replace(rest,@"using\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*)\s*;",m=>{if(!aliases.TryAdd(m.Groups[1].Value,Normalize(m.Groups[2].Value)))throw new ArgumentException("중복 alias: "+m.Groups[1].Value);return "";});foreach(Match alias in Regex.Matches(rest,@"typedef\s+(?:struct\s+)?([A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*?)\s+([A-Za-z_]\w*)\s*;")){if(alias.Groups[2].Value==alias.Groups[1].Value)continue;if(!aliases.TryAdd(alias.Groups[2].Value,Normalize(alias.Groups[1].Value)))throw new ArgumentException("중복 typedef: "+alias.Groups[2].Value);}
            rest=Regex.Replace(rest,@"typedef\s+(?:struct\s+)?[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*?\s+[A-Za-z_]\w*\s*;","");
            if(!string.IsNullOrWhiteSpace(rest.Replace(";","")))throw new ArgumentException(source.Name+": 미지원 선언이 남았습니다. 포인터/함수/inline struct/동적 배열은 지원하지 않습니다.");
        }
        var result=new Dictionary<string,StructLayoutInfo>(StringComparer.Ordinal);var active=new HashSet<string>();
        int Align(int n,int alignment)=>checked((n+alignment-1)/alignment*alignment);
        string Resolve(string name){var seen=new HashSet<string>();while(aliases.TryGetValue(name,out var next)){if(!seen.Add(name))throw new ArgumentException("typedef 순환 참조: "+name);name=next;}return name;}
        StructLayoutInfo Compile(string name,int depth)
        {
            name=Resolve(name);if(result.TryGetValue(name,out var cached))return cached;
            if(depth>16||!active.Add(name))throw new ArgumentException("struct 순환/깊이 초과: "+name);if(!definitions.TryGetValue(name,out var definition))throw new ArgumentException("찾을 수 없는 struct/type: "+name);
            int cursor=0,maxAlignment=1,unitOffset=-1,unitBytes=0,usedBits=0;string unitType="";var fields=new List<IcdField>();var names=new HashSet<string>();
            foreach(var raw in definition.Body.Split(';',StringSplitOptions.RemoveEmptyEntries)) {
                string declaration=Regex.Replace(raw.Trim(),@"\s+"," ");if(declaration.Length==0)continue;
                var member=Regex.Match(declaration,@"^(?<type>(?:struct )?[A-Za-z_]\w*(?: [A-Za-z_]\w*)*?)\s+(?<name>[A-Za-z_]\w*)?(?:\s*\[\s*(?<count>[A-Za-z_]\w*|0x[0-9a-fA-F]+|\d+)\s*\])?(?:\s*:\s*(?<bits>\d+))?$");
                if(!member.Success)throw new ArgumentException(name+": 미지원 멤버 선언: "+declaration);
                string type=Resolve(Normalize(member.Groups["type"].Value.Replace("struct ",""))),fieldName=member.Groups["name"].Value;bool isBits=member.Groups["bits"].Success;int count=member.Groups["count"].Success?Number(member.Groups["count"].Value):1;
                if(count<1||count>1024||(isBits&&member.Groups["count"].Success))throw new ArgumentException("고정 배열 길이/비트 필드 배열 오류");
                if(fieldName.Length>0&&!names.Add(fieldName))throw new ArgumentException("중복 struct 필드: "+fieldName);
                bool scalar=primitives.TryGetValue(type,out var primitive);var nested=scalar?null:Compile(type,depth+1);int bytes=scalar?primitive!.Bytes:nested!.Size,alignment=Math.Min(scalar?bytes:nested!.Alignment,definition.Pack);maxAlignment=Math.Max(maxAlignment,alignment);
                if(isBits) {
                    if(!scalar||primitive!.Type is not ("uint" or "int"))throw new ArgumentException("비트 필드 기본 타입은 고정 길이 정수여야 합니다.");
                    int bits=Number(member.Groups["bits"].Value);if(bits<0||bits>bytes*8)throw new ArgumentException("비트 필드가 저장 단위를 넘습니다.");
                    if(bits==0){if(fieldName.Length>0)throw new ArgumentException("0비트는 이름 없는 경계 필드만 허용합니다.");cursor=Align(cursor,alignment);unitOffset=-1;continue;}
                    if(unitOffset<0||unitType!=type||usedBits+bits>bytes*8){cursor=Align(cursor,alignment);unitOffset=cursor;unitBytes=bytes;unitType=type;usedBits=0;cursor=checked(cursor+bytes);}
                    if(fieldName.Length>0)fields.Add(new(name,fieldName,unitOffset,usedBits%8,bits,primitive.Type,endian,bitOrder,1,0,"","C bit storage unit",0,unitBytes*8,usedBits));usedBits+=bits;
                }else {
                    if(fieldName.Length==0)throw new ArgumentException("struct 필드명이 필요합니다.");unitOffset=-1;cursor=Align(cursor,alignment);
                    for(int i=0;i<count;i++) {string label=fieldName+(count==1?"":"["+i+"]");int offset=checked(cursor+i*bytes);if(scalar)fields.Add(new(name,label,offset,0,bytes*8,primitive!.Type,endian,"msb0",1,0,"","C scalar",0));else foreach(var field in nested!.Fields)fields.Add(field with{Message=name,Name=label+"."+field.Name,ByteOffset=checked(offset+field.ByteOffset)});}
                    cursor=checked(cursor+bytes*count);
                }
                if(cursor>65535||fields.Count>10000)throw new ArgumentException("struct 크기/필드 수 제한 초과");
            }
            int size=Align(cursor,maxAlignment);if(size==0||size>65535)throw new ArgumentException("struct가 비어 있거나 너무 큽니다: "+name);active.Remove(name);var layout=new StructLayoutInfo(name,size,maxAlignment,fields);result.Add(name,layout);return layout;
        }
        foreach(var name in definitions.Keys)Compile(name,0);foreach(var alias in aliases.Keys){var actual=Resolve(alias);if(result.TryGetValue(actual,out var layout))result.TryAdd(alias,layout);}
        if(result.Count==0)throw new ArgumentException("struct 정의가 없습니다.");return result;
    }
}
