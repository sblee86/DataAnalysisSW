using System.Globalization;
using System.IO;
using System.Text;

namespace LanScope;
public sealed record IcdField(string Message,string Name,int ByteOffset,int BitOffset,int BitLength,string Type,string Endian,string BitOrder,decimal Scale,decimal Bias,string Unit,string Description,int SourceLine,int StorageBits=0,int StorageBitOffset=0,decimal? Minimum=null,decimal? Maximum=null)
{
    public int EndByte=>ByteOffset+(StorageBits>0?StorageBits/8:(BitOffset+BitLength+7)/8);
    public string Location=>StorageBits>0?$"{ByteOffset}:u{StorageBits}/{StorageBitOffset}":$"{ByteOffset}:{BitOffset}";
}
public sealed record DecodedField(string Message,string Name,string Raw,string Value,string Unit,string Error,string RangeError="");
public sealed class IcdSchema
{
    public List<IcdField> Fields {get;}=[];
    public List<string> Warnings {get;}=[];
    public string EncodingName {get;internal set;}="";
    public string[] Messages=>Fields.Select(f=>f.Message).Distinct().ToArray();
    public Dictionary<string,int> MessageSizes {get;}=[];
    public int RequiredBytes(string message)=>Math.Max(MessageSizes.GetValueOrDefault(message),Fields.Where(f=>f.Message==message).Select(f=>f.EndByte).DefaultIfEmpty(0).Max());
    public List<DecodedField> Decode(string message,ReadOnlySpan<byte> payload)
    {
        if(!Messages.Contains(message))throw new ArgumentException("메시지를 선택하세요.");
        var result=new List<DecodedField>();
        foreach(var f in Fields.Where(f=>f.Message==message)) {
            try {
                if(payload.Length<f.EndByte)throw new ArgumentException("payload 길이 부족");
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
                string rangeError="";
                if(f.Minimum.HasValue||f.Maximum.HasValue){
                    bool outside=f.Type is "float32" or "float64"
                        ? (f.Minimum.HasValue&&double.Parse(valueText,CultureInfo.InvariantCulture)<(double)f.Minimum.Value)||(f.Maximum.HasValue&&double.Parse(valueText,CultureInfo.InvariantCulture)>(double)f.Maximum.Value)
                        : (f.Minimum.HasValue&&decimal.Parse(valueText,CultureInfo.InvariantCulture)<f.Minimum.Value)||(f.Maximum.HasValue&&decimal.Parse(valueText,CultureInfo.InvariantCulture)>f.Maximum.Value);
                    if(outside)rangeError=$"범위 이탈: {valueText} (min={f.Minimum?.ToString(CultureInfo.InvariantCulture)??"없음"}, max={f.Maximum?.ToString(CultureInfo.InvariantCulture)??"없음"})";
                }
                result.Add(new(message,f.Name,rawText,valueText,f.Unit,"",rangeError));
            }catch(Exception e) when(e is ArgumentException or OverflowException){result.Add(new(message,f.Name,"—","—",f.Unit,e.Message));}
        }
        return result;
    }
    public void WriteValue(string message,string fieldName,string value,Span<byte> payload,bool rawValue=false)
    {
        var f=Fields.SingleOrDefault(f=>f.Message==message&&f.Name==fieldName)??throw new ArgumentException("메시지/필드를 선택하세요.");
        if(payload.Length<f.EndByte)throw new ArgumentException("쓰기 대상 payload 길이가 부족합니다.");
        if(f.Type=="bytes") {
            var text=new string(value.Where(c=>!char.IsWhiteSpace(c)).ToArray());var bytes=Convert.FromHexString(text);
            if(bytes.Length!=f.BitLength/8)throw new ArgumentException("bytes 값은 정의된 길이와 같아야 합니다.");bytes.CopyTo(payload.Slice(f.ByteOffset));return;
        }
        ulong raw;
        if(f.Type=="bool")raw=value.Trim().ToLowerInvariant() switch {"true" or "1"=>1,"false" or "0"=>0,_=>throw new ArgumentException("bool 값은 true/false 또는 1/0입니다.")};
        else if(f.Type is "float32" or "float64") {
            if(rawValue){if(!ulong.TryParse(value,NumberStyles.Integer,CultureInfo.InvariantCulture,out raw)||(f.Type=="float32"&&raw>uint.MaxValue))throw new ArgumentException("raw float는 IEEE754 비트 패턴의 부호 없는 정수입니다.");}
            else {
                if(!double.TryParse(value,NumberStyles.Float,CultureInfo.InvariantCulture,out var number)||!double.IsFinite(number))throw new ArgumentException("유한한 실수를 입력하세요.");
                if(f.Scale==0)throw new ArgumentException("scale=0인 필드는 실제값을 역변환할 수 없습니다. raw 모드를 사용하세요.");number=(number-(double)f.Bias)/(double)f.Scale;
                if(!double.IsFinite(number))throw new ArgumentException("실수 범위 초과");
                if(f.Type=="float32"){var single=(float)number;if(!float.IsFinite(single))throw new ArgumentException("float32 범위 초과");raw=unchecked((uint)BitConverter.SingleToInt32Bits(single));}else raw=unchecked((ulong)BitConverter.DoubleToInt64Bits(number));
            }
        }else {
            if(!decimal.TryParse(value,NumberStyles.Float,CultureInfo.InvariantCulture,out var number))throw new ArgumentException("정수/실제값을 입력하세요.");
            if(!rawValue){if(f.Scale==0)throw new ArgumentException("scale=0인 필드는 실제값을 역변환할 수 없습니다. raw 모드를 사용하세요.");number=checked((number-f.Bias)/f.Scale);}
            if(decimal.Truncate(number)!=number)throw new ArgumentException("비트 필드 정수로 정확히 표현할 수 없는 값입니다.");
            if(f.Type=="int") {
                decimal minimum=f.BitLength==64?long.MinValue:-(1L<<(f.BitLength-1)),maximum=f.BitLength==64?long.MaxValue:(1L<<(f.BitLength-1))-1;
                if(number<minimum||number>maximum)throw new ArgumentException("부호 있는 비트 필드 범위 초과");raw=unchecked((ulong)(long)number);if(f.BitLength<64)raw&=(1UL<<f.BitLength)-1;
            }else{decimal maximum=f.BitLength==64?ulong.MaxValue:(1UL<<f.BitLength)-1;if(number<0||number>maximum)throw new ArgumentException("부호 없는 비트 필드 범위 초과");raw=(ulong)number;}
        }
        // Validate first; only the selected physical bit range is changed below.
        if(f.StorageBits>0) {
            ulong container=ReadStorage(payload,f),mask=f.BitLength==64?ulong.MaxValue:(1UL<<f.BitLength)-1;int shift=f.BitOrder=="lsb0"?f.StorageBitOffset:f.StorageBits-f.StorageBitOffset-f.BitLength;
            container=(container&~(mask<<shift))|((raw&mask)<<shift);for(int i=0;i<f.StorageBits/8;i++)payload[f.ByteOffset+i]=(byte)(container>>(8*(f.Endian=="le"?i:f.StorageBits/8-1-i)));return;
        }
        int left=f.BitLength,index=f.ByteOffset,position=f.BitOffset;
        while(left>0){int take=Math.Min(8-position,left),shift=f.BitOrder=="lsb0"?position:8-position-take,mask=((1<<take)-1)<<shift;int sourceShift=f.Endian=="le"?f.BitLength-left:left-take;int chunk=(int)((raw>>sourceShift)&(ulong)((1<<take)-1));payload[index]=(byte)((payload[index]&~mask)|(chunk<<shift));left-=take;index++;position=0;}

    }
    public byte[] Encode(string message,IReadOnlyDictionary<string,string> values,byte[]? initial=null,bool rawValue=false)
    {
        if(!Messages.Contains(message))throw new ArgumentException("메시지를 선택하세요.");var bytes=initial?.ToArray()??new byte[RequiredBytes(message)];foreach(var item in values)WriteValue(message,item.Key,item.Value,bytes,rawValue);return bytes;
    }
    private static ulong ReadStorage(ReadOnlySpan<byte> payload,IcdField f)
    {
        ulong value=0;for(int i=0;i<f.StorageBits/8;i++)if(f.Endian=="le")value|=(ulong)payload[f.ByteOffset+i]<<(i*8);else value=(value<<8)|payload[f.ByteOffset+i];return value;
    }
    public static IEnumerable<int> PhysicalBits(IcdField f)
    {
        if(f.StorageBits>0){int first=f.BitOrder=="lsb0"?f.StorageBitOffset:f.StorageBits-f.StorageBitOffset-f.BitLength;for(int k=0;k<f.BitLength;k++){int bit=first+k,byteIndex=f.Endian=="le"?bit/8:f.StorageBits/8-1-bit/8;yield return(f.ByteOffset+byteIndex)*8+bit%8;}}
        else for(int k=0;k<f.BitLength;k++){int pos=f.BitOffset+k;yield return(f.ByteOffset+pos/8)*8+(f.BitOrder=="lsb0"?pos%8:7-pos%8);}
    }
    public static ulong ExtractBits(ReadOnlySpan<byte> payload,IcdField f)
    {
        if(f.BitLength<1||f.BitLength>64||f.BitOffset<0||f.BitOffset>7||f.ByteOffset<0||payload.Length<f.EndByte)throw new ArgumentException("잘못된 비트 범위");
        if(f.StorageBits>0){var container=ReadStorage(payload,f);int shift=f.BitOrder=="lsb0"?f.StorageBitOffset:f.StorageBits-f.StorageBitOffset-f.BitLength;return(container>>shift)&(f.BitLength==64?ulong.MaxValue:(1UL<<f.BitLength)-1);}
        ulong value=0;int left=f.BitLength,index=f.ByteOffset,position=f.BitOffset,collected=0;
        while(left>0){int take=Math.Min(8-position,left),shift=f.BitOrder=="lsb0"?position:8-position-take;ulong chunk=(ulong)((payload[index]>>shift)&((1<<take)-1));if(f.Endian=="le")value|=chunk<<collected;else value=(value<<take)|chunk;collected+=take;left-=take;index++;position=0;}return value;
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
        ["minimum"]=["min","minimum","최소","최소값"], ["maximum"]=["max","maximum","최대","최대값"],
        ["scale"]=["scale","배율"], ["bias"]=["bias","valueoffset","보정값"],
        ["unit"]=["unit","단위"], ["description"]=["description","comment","설명"], ["storage_bits"]=["storagebits"], ["storage_bit_offset"]=["storagebitoffset"], ["message_size"]=["messagesize"], ["struct_name"]=["structname","struct","구조체"]
    };
    private static string Normalize(string s)=>new(s.Trim().ToLowerInvariant().Where(c=>c!='_'&&c!=' '&&c!='-').ToArray());
    public static (string Text,string Encoding) DecodeText(byte[] bytes)
    {
        if(bytes.Length==0||bytes.Length>16*1024*1024)throw new ArgumentException("CSV 크기는 1 byte ~ 16 MB이어야 합니다.");
        string text,encoding;
        if(bytes.AsSpan().StartsWith(new byte[]{0xff,0xfe})){text=new UnicodeEncoding(false,true,true).GetString(bytes,2,bytes.Length-2);encoding="UTF-16 LE";}
        else if(bytes.AsSpan().StartsWith(new byte[]{0xfe,0xff})){text=new UnicodeEncoding(true,true,true).GetString(bytes,2,bytes.Length-2);encoding="UTF-16 BE";}
        else {
            try{text=new UTF8Encoding(false,true).GetString(bytes).TrimStart('\ufeff');encoding="UTF-8";}
            catch(DecoderFallbackException){Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);text=Encoding.GetEncoding(949,EncoderFallback.ExceptionFallback,DecoderFallback.ExceptionFallback).GetString(bytes);encoding="CP949";}
        }
        return(text,encoding);
    }
    public static IcdSchema Parse(byte[] bytes,string byteOrder="csv",IReadOnlyList<StructSource>? structs=null,int structPack=1,string structBitOrder="lsb0")
    {
        if(byteOrder is not ("csv" or "be" or "le"))throw new ArgumentException("엔디언은 csv/be/le입니다.");var decoded=DecodeText(bytes);string text=decoded.Text,encoding=decoded.Encoding;
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
        foreach(var key in new[]{"name","byte_offset","type"})if(!columns.ContainsKey(key))throw new ArgumentException("필수 CSV 열 누락: "+key);
        var usedNames=new HashSet<string>();var occupied=new Dictionary<string,System.Collections.BitArray>();var layouts=new Dictionary<string,Dictionary<string,StructLayoutInfo>>();
        void Add(IcdField field) {
            if(schema.Fields.Count>=10000||field.ByteOffset<0||field.EndByte>65535)throw new ArgumentException("ICD 크기/필드 수 제한 초과");
            if(!usedNames.Add(field.Message+"\0"+field.Name))throw new ArgumentException("같은 메시지에 중복 필드명: "+field.Name);
            if(!occupied.TryGetValue(field.Message,out var locations)){if(occupied.Count>=256)throw new ArgumentException("메시지는 최대 256개입니다.");locations=new System.Collections.BitArray(65535*8);occupied.Add(field.Message,locations);}
            foreach(int physical in IcdSchema.PhysicalBits(field)){if(locations[physical])throw new ArgumentException("같은 메시지의 필드 비트 범위가 겹칩니다: "+field.Name);locations[physical]=true;}schema.Fields.Add(field);
        }
        foreach(var row in rows.Skip(1)) {
            try {
                if(row.Cells.Count!=headers.Count)throw new ArgumentException($"열 수가 헤더({headers.Count})와 다릅니다: {row.Cells.Count}");
                string Get(string key,string fallback=""){var value=columns.TryGetValue(key,out var i)?row.Cells[i].Trim():"";return value.Length==0?fallback:value;}
                foreach(var key in new[]{"name","byte_offset","type"})if(Get(key).Length==0)throw new ArgumentException("필수 값 누락: "+key);
                int Number(string key,int fallback)=>int.TryParse(Get(key,fallback.ToString(CultureInfo.InvariantCulture)),NumberStyles.Integer,CultureInfo.InvariantCulture,out var n)?n:throw new ArgumentException(key+"는 정수여야 합니다.");
                decimal Decimal(string key,decimal fallback)=>decimal.TryParse(Get(key,fallback.ToString(CultureInfo.InvariantCulture)),NumberStyles.Float,CultureInfo.InvariantCulture,out var n)?n:throw new ArgumentException(key+"는 숫자여야 합니다.");
                var message=Get("message","Default");var name=Get("name");int start=Number("byte_offset",0),bit=Number("bit_offset",0),length=Number("bit_length",0);
                int storage=Number("storage_bits",0),storageOffset=Number("storage_bit_offset",0),messageSize=Number("message_size",0);
                if(messageSize<0||messageSize>65535)throw new ArgumentException("message_size 범위 오류");
                if(messageSize>0){if(schema.MessageSizes.TryGetValue(message,out var previous)&&previous!=messageSize)throw new ArgumentException("동일 메시지의 message_size 불일치");schema.MessageSizes[message]=messageSize;}
                var originalType=Get("type");var structName=Get("struct_name");if(originalType.StartsWith("struct:",StringComparison.OrdinalIgnoreCase))structName=originalType[7..].Trim();
                var type=originalType.ToLowerInvariant();type=type switch {"unsigned" or "bitfield"=>"uint","signed"=>"int","boolean"=>"bool","float"=>"float32","double"=>"float64",_=>type};
                var endian=(byteOrder=="csv"?Get("endian","be"):byteOrder).ToLowerInvariant();endian=endian switch {"little" or "littleendian"=>"le","big" or "bigendian" or "network"=>"be",_=>endian};
                var order=Get("bit_order","msb0").ToLowerInvariant();decimal scale=Decimal("scale",1),bias=Decimal("bias",0);
                if(name.Length==0||message.Length==0||name.Length>128||message.Length>128)throw new ArgumentException("메시지/필드 이름을 1~128자로 지정하세요.");
                if(structName.Length>0||type=="struct") {
                    if(Get("minimum").Length>0||Get("maximum").Length>0)throw new ArgumentException("struct 전체 범위는 지원하지 않습니다. 가져온 뒤 숫자 멤버별로 설정하세요.");
                    if(bit!=0||structName.Length==0)throw new ArgumentException("struct 이름과 바이트 정렬이 필요합니다.");if(structs==null||structs.Count==0)throw new ArgumentException("외부 C/C++ struct 파일을 함께 선택하세요.");
                    if(endian is not ("be" or "le"))throw new ArgumentException("엔디언은 be/le입니다.");var key=endian+":"+structBitOrder+":"+structPack;
                    if(!layouts.TryGetValue(key,out var library)){library=CStructParser.Parse(structs,structPack,endian,structBitOrder);layouts.Add(key,library);}
                    if(!library.TryGetValue(structName,out var layout))throw new ArgumentException("외부 struct를 찾을 수 없습니다: "+structName);
                    foreach(var field in layout.Fields)Add(field with{Message=message,Name=name+"."+field.Name,ByteOffset=checked(start+field.ByteOffset),SourceLine=row.Line});schema.MessageSizes[message]=Math.Max(schema.MessageSizes.GetValueOrDefault(message),checked(start+layout.Size));if(schema.MessageSizes[message]>65535)throw new ArgumentException("메시지 크기 초과");continue;
                }
                if(Get("bit_length").Length==0)throw new ArgumentException("필수 값 누락: bit_length");
                if(start<0||start>65534||bit<0||bit>7||length<1||length>524280||(long)start*8+bit+length>65535*8)throw new ArgumentException("잘못된 바이트/비트 범위 (최대 payload 65,535 bytes)");
                if(type is not ("uint" or "int" or "bool" or "float32" or "float64" or "bytes"))throw new ArgumentException("미지원 type: "+type);
                if(endian is not ("be" or "le"))throw new ArgumentException("엔디언은 be/le입니다.");
                if(order is not ("lsb0" or "msb0"))throw new ArgumentException("bit_order는 lsb0/msb0이어야 합니다.");
                if(type is "uint" or "int" && length>64)throw new ArgumentException("정수/비트 필드는 최대 64 bits입니다.");
                if(storage!=0&&(storage is not (8 or 16 or 32 or 64)||storageOffset<0||length>storage||storageOffset>storage-length||bit!=storageOffset%8||type is not ("uint" or "int" or "bool")))throw new ArgumentException("storage_bits/storage_bit_offset 범위 또는 타입 오류");
                if(storage==0&&storageOffset!=0)throw new ArgumentException("저장 단위 없는 storage_bit_offset");
                if(type=="bool"&&((length!=1&&!(length==8&&bit==0&&storageOffset==0))||scale!=1||bias!=0))throw new ArgumentException("bool은 1 bit 또는 정렬된 C bool 8 bits, scale=1, bias=0이어야 합니다.");
                if(type is "float32" or "float64" && (bit!=0||length!=(type=="float32"?32:64)))throw new ArgumentException("float 필드는 바이트 정렬된 32/64 bits이어야 합니다.");
                if(type=="bytes"&&(bit!=0||length%8!=0||scale!=1||bias!=0))throw new ArgumentException("bytes는 바이트 정렬/8배수 길이, scale=1, bias=0이어야 합니다.");
                decimal? minimum=Get("minimum").Length==0?null:Decimal("minimum",0),maximum=Get("maximum").Length==0?null:Decimal("maximum",0);
                if((minimum.HasValue||maximum.HasValue)&&type is "bytes" or "bool")throw new ArgumentException("최소/최대값은 숫자 필드에만 설정합니다.");
                if(minimum>maximum)throw new ArgumentException("최소값은 최대값보다 클 수 없습니다.");
                Add(new(message,name,start,bit,length,type,endian,order,scale,bias,Get("unit"),Get("description"),row.Line,storage,storageOffset,minimum,maximum));
            }catch(ArgumentException e){throw new ArgumentException($"CSV {row.Line}행: {e.Message}",e);}
        }
        foreach(var field in schema.Fields)if(schema.MessageSizes.TryGetValue(field.Message,out var size)&&size<field.EndByte)throw new ArgumentException("message_size가 필드보다 작습니다.");
        if(schema.Fields.Count==0)throw new ArgumentException("해석 가능한 이름 있는 필드가 없습니다.");
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
