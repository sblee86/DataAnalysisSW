using System.Globalization;
using System.IO;
using System.Text;

namespace LanScope;
public sealed record IcdField(string Message,string Name,int ByteOffset,int BitOffset,int BitLength,string Type,string Endian,string BitOrder,decimal Scale,decimal Bias,string Unit,string Description,int SourceLine)
{
    public string Location=>$"{ByteOffset}:{BitOffset}";
}
public sealed record DecodedField(string Message,string Name,string Raw,string Value,string Unit,string Error);
public sealed class IcdSchema
{
    public List<IcdField> Fields {get;}=[];
    public List<string> Warnings {get;}=[];
    public string EncodingName {get;internal set;}="";
    public string[] Messages=>Fields.Select(f=>f.Message).Distinct().ToArray();
    public int RequiredBytes(string message)=>Fields.Where(f=>f.Message==message).Select(f=>f.ByteOffset+(f.BitOffset+f.BitLength+7)/8).DefaultIfEmpty(0).Max();
    public List<DecodedField> Decode(string message,ReadOnlySpan<byte> payload)
    {
        if(!Messages.Contains(message))throw new ArgumentException("메시지를 선택하세요.");
        var result=new List<DecodedField>();
        foreach(var f in Fields.Where(f=>f.Message==message)) {
            try {
                if(payload.Length<f.ByteOffset+(f.BitOffset+f.BitLength+7)/8)throw new ArgumentException("payload 길이 부족");
                if(f.Type=="bytes") {var value=Convert.ToHexString(payload.Slice(f.ByteOffset,f.BitLength/8));result.Add(new(message,f.Name,value,value,f.Unit,""));continue;}
                ulong raw=ExtractBits(payload,f);string rawText=raw.ToString(CultureInfo.InvariantCulture);string valueText;
                if(f.Type=="bool")valueText=raw==0?"false":"true";
                else if(f.Type is "float32" or "float64") {
                    double value=f.Type=="float32"?BitConverter.Int32BitsToSingle(unchecked((int)raw)):BitConverter.Int64BitsToDouble(unchecked((long)raw));
                    value=value*(double)f.Scale+(double)f.Bias;
                    if(!double.IsFinite(value))throw new ArgumentException("NaN/Infinity 또는 변환 범위 초과");
                    valueText=value.ToString("G17",CultureInfo.InvariantCulture);
                } else {
                    decimal value;
                    if(f.Type=="int") {
                        long signed=f.BitLength==64?unchecked((long)raw):(raw&(1UL<<(f.BitLength-1)))!=0?unchecked((long)(raw|(~0UL<<f.BitLength))):(long)raw;
                        rawText=signed.ToString(CultureInfo.InvariantCulture);value=signed;
                    }else value=raw;
                    valueText=checked(value*f.Scale+f.Bias).ToString(CultureInfo.InvariantCulture);
                }
                result.Add(new(message,f.Name,rawText,valueText,f.Unit,""));
            }catch(Exception e) when(e is ArgumentException or OverflowException){result.Add(new(message,f.Name,"—","—",f.Unit,e.Message));}
        }
        return result;
    }
    // Each byte slice retains its numeric value; slices concatenate in big-endian order.
    public static ulong ExtractBits(ReadOnlySpan<byte> payload,IcdField f)
    {
        ulong value=0;int left=f.BitLength,index=f.ByteOffset,position=f.BitOffset;
        if(left<1||left>64||position<0||position>7||index<0||payload.Length<index+(position+left+7)/8)throw new ArgumentException("잘못된 비트 범위");
        while(left>0) {
            int take=Math.Min(8-position,left),shift=f.BitOrder=="lsb0"?position:8-position-take;
            ulong chunk=(ulong)((payload[index]>>shift)&((1<<take)-1));
            value=(value<<take)|chunk;
            left-=take;index++;position=0;
        }
        return value;
    }
}
public static class IcdCsv
{
    private static readonly Dictionary<string,string[]> Aliases=new() {
        ["message"]=["message","messagename","메시지","메시지명"],
        ["name"]=["name","field","fieldname","signalname","필드명","항목명"],
        ["byte_offset"]=["byteoffset","startbyte","바이트오프셋"],
        ["bit_offset"]=["bitoffset","startbit","비트오프셋"],
        ["bit_length"]=["bitlength","bitwidth","bits","비트길이","비트수"],
        ["type"]=["type","datatype","자료형","타입"],
        ["endian"]=["endian","byteorder","엔디언"],
        ["bit_order"]=["bitorder","bitnumbering","비트순서"],
        ["scale"]=["scale","배율"], ["bias"]=["bias","valueoffset","보정값"],
        ["unit"]=["unit","단위"], ["description"]=["description","comment","설명"]
    };
    private static string Normalize(string s)=>new(s.Trim().ToLowerInvariant().Where(c=>c!='_'&&c!=' '&&c!='-').ToArray());
    public static IcdSchema Parse(byte[] bytes)
    {
        if(bytes.Length==0||bytes.Length>16*1024*1024)throw new ArgumentException("CSV 크기는 1 byte ~ 16 MB이어야 합니다.");
        string text,encoding;
        if(bytes.AsSpan().StartsWith(new byte[]{0xff,0xfe})){text=new UnicodeEncoding(false,true,true).GetString(bytes,2,bytes.Length-2);encoding="UTF-16 LE";}
        else if(bytes.AsSpan().StartsWith(new byte[]{0xfe,0xff})){text=new UnicodeEncoding(true,true,true).GetString(bytes,2,bytes.Length-2);encoding="UTF-16 BE";}
        else {
            try{text=new UTF8Encoding(false,true).GetString(bytes).TrimStart('\ufeff');encoding="UTF-8";}
            catch(DecoderFallbackException){Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);text=Encoding.GetEncoding(949,EncoderFallback.ExceptionFallback,DecoderFallback.ExceptionFallback).GetString(bytes);encoding="CP949";}
        }
        if(text.Contains('\0'))throw new ArgumentException("CSV에 NUL 문자가 있습니다. UTF-16 파일에는 BOM이 필요합니다.");
        var headerLine=text.Split(['\r','\n'])[0];
        char delimiter=new[]{',',';','\t'}.OrderByDescending(c=>CountDelimiters(headerLine,c)).First();
        var rows=ReadRows(text,delimiter);
        if(rows.Count<2)throw new ArgumentException("CSV 헤더와 필드 행이 필요합니다.");
        var headers=rows[0].Cells;var columns=new Dictionary<string,int>();var schema=new IcdSchema {EncodingName=encoding};
        for(int i=0;i<headers.Count;i++) {
            var key=Aliases.FirstOrDefault(p=>p.Value.Contains(Normalize(headers[i]))).Key;
            if(key==null){schema.Warnings.Add("미사용 열: "+headers[i]);continue;}
            if(!columns.TryAdd(key,i))throw new ArgumentException("중복 CSV 열: "+headers[i]);
        }
        foreach(var key in new[]{"name","byte_offset","bit_length","type"})if(!columns.ContainsKey(key))throw new ArgumentException("필수 CSV 열 누락: "+key);
        var usedNames=new HashSet<string>();var occupied=new Dictionary<string,System.Collections.BitArray>();
        foreach(var row in rows.Skip(1)) {
            try {
                if(row.Cells.Count!=headers.Count)throw new ArgumentException($"열 수가 헤더({headers.Count})와 다릅니다: {row.Cells.Count}");
                string Get(string key,string fallback=""){var value=columns.TryGetValue(key,out var i)?row.Cells[i].Trim():"";return value.Length==0?fallback:value;}
                foreach(var key in new[]{"name","byte_offset","bit_length","type"})if(Get(key).Length==0)throw new ArgumentException("필수 값 누락: "+key);
                int Number(string key,int fallback)=>int.TryParse(Get(key,fallback.ToString(CultureInfo.InvariantCulture)),NumberStyles.Integer,CultureInfo.InvariantCulture,out var n)?n:throw new ArgumentException(key+"는 정수여야 합니다.");
                decimal Decimal(string key,decimal fallback)=>decimal.TryParse(Get(key,fallback.ToString(CultureInfo.InvariantCulture)),NumberStyles.Float,CultureInfo.InvariantCulture,out var n)?n:throw new ArgumentException(key+"는 숫자여야 합니다.");
                var message=Get("message","Default");var name=Get("name");int start=Number("byte_offset",0),bit=Number("bit_offset",0),length=Number("bit_length",0);
                var type=Get("type").ToLowerInvariant();type=type switch {"unsigned" or "bitfield"=>"uint","signed"=>"int","boolean"=>"bool","float"=>"float32","double"=>"float64",_=>type};
                var endian=Get("endian","be").ToLowerInvariant();endian=endian switch {"little" or "littleendian"=>"le","big" or "bigendian" or "network"=>"be",_=>endian};
                var order=Get("bit_order","msb0").ToLowerInvariant();decimal scale=Decimal("scale",1),bias=Decimal("bias",0);
                if(name.Length==0||message.Length==0||name.Length>128||message.Length>128)throw new ArgumentException("메시지/필드 이름을 1~128자로 지정하세요.");
                if(!usedNames.Add(message+"\0"+name))throw new ArgumentException("같은 메시지에 중복 필드명: "+name);
                if(start<0||start>65534||bit<0||bit>7||length<1||length>524280||(long)start*8+bit+length>65535*8)throw new ArgumentException("잘못된 바이트/비트 범위 (최대 payload 65,535 bytes)");
                if(type is not ("uint" or "int" or "bool" or "float32" or "float64" or "bytes"))throw new ArgumentException("미지원 type: "+type);
                if(endian!="be")throw new ArgumentException("통신 ICD는 빅엔디언(be)만 지원합니다. 1바이트 값은 변환하지 않습니다.");
                if(order is not ("lsb0" or "msb0"))throw new ArgumentException("bit_order는 lsb0/msb0이어야 합니다.");
                if(type is "uint" or "int" && length>64)throw new ArgumentException("정수/비트 필드는 최대 64 bits입니다.");
                if(type=="bool"&&(length!=1||scale!=1||bias!=0))throw new ArgumentException("bool은 1 bit, scale=1, bias=0이어야 합니다.");
                if(type is "float32" or "float64" && (bit!=0||length!=(type=="float32"?32:64)))throw new ArgumentException("float 필드는 바이트 정렬된 32/64 bits이어야 합니다.");
                if(type=="bytes"&&(bit!=0||length%8!=0||scale!=1||bias!=0))throw new ArgumentException("bytes는 바이트 정렬/8배수 길이, scale=1, bias=0이어야 합니다.");
                if(!occupied.TryGetValue(message,out var locations)){if(occupied.Count>=256)throw new ArgumentException("메시지는 최대 256개입니다.");locations=new System.Collections.BitArray(65535*8);occupied.Add(message,locations);}
                for(int k=0;k<length;k++){int pos=bit+k;int physical=(start+pos/8)*8+(order=="lsb0"?pos%8:7-pos%8);if(locations[physical])throw new ArgumentException("같은 메시지의 필드 비트 범위가 겹칩니다: "+name);locations[physical]=true;}
                schema.Fields.Add(new(message,name,start,bit,length,type,endian,order,scale,bias,Get("unit"),Get("description"),row.Line));
            }catch(ArgumentException e){throw new ArgumentException($"CSV {row.Line}행: {e.Message}",e);}
        }
        return schema;
    }
    private static int CountDelimiters(string text,char delimiter){bool quote=false;int count=0;foreach(var c in text){if(c=='"')quote=!quote;else if(!quote&&c==delimiter)count++;}return count;}
    private sealed record Row(int Line,List<string> Cells);
    private static List<Row> ReadRows(string text,char delimiter)
    {
        var rows=new List<Row>();var cells=new List<string>();var value=new StringBuilder();bool quoted=false,closed=false;int line=1,start=1;
        void Cell(){cells.Add(value.ToString());value.Clear();closed=false;if(cells.Count>64)throw new ArgumentException($"CSV {start}행: 열은 최대 64개입니다.");}
        void Record(){Cell();if(cells.Any(c=>!string.IsNullOrWhiteSpace(c)))rows.Add(new(start,cells));cells=[];if(rows.Count>10001)throw new ArgumentException("CSV 필드는 최대 10,000개입니다.");}
        for(int i=0;i<text.Length;i++) {
            char c=text[i];
            if(quoted) {
                if(c=='"'){if(i+1<text.Length&&text[i+1]=='"'){value.Append('"');i++;}else{quoted=false;closed=true;}}
                else {value.Append(c);if(c=='\n'||(c=='\r'&&(i+1==text.Length||text[i+1]!='\n')))line++;}
                continue;
            }
            if(c==delimiter){Cell();continue;}
            if(c=='\r'||c=='\n'){if(c=='\r'&&i+1<text.Length&&text[i+1]=='\n')i++;Record();line++;start=line;continue;}
            if(closed){if(c==' '||c=='\t')continue;throw new ArgumentException($"CSV {line}행: 닫는 따옴표 뒤에 문자가 있습니다.");}
            if(c=='"'){if(value.Length!=0)throw new ArgumentException($"CSV {line}행: 잘못된 따옴표 위치");quoted=true;}
            else value.Append(c);
        }
        if(quoted)throw new ArgumentException($"CSV {start}행: 닫히지 않은 따옴표");
        if(value.Length>0||cells.Count>0||closed)Record();
        return rows;
    }
}
