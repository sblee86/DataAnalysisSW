using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
namespace LanScope;
public sealed record CaptureMessageRule(string Message,string Id,int BodyBytes=0);
public sealed class CapturePolicy
{
    public bool RequireHeaderLayout {get;set;}
    public bool MatchByStructure {get;set;}
    public string Transport {get;set;}="UDP";
    public string Checksum {get;set;}="none";
    public IcdField? IdField {get;set;}
    public IcdField? LengthField {get;set;}
    public List<IcdField> HeaderFields {get;set;}=[];
    public List<StructSource> HeaderSources {get;set;}=[];
    public string HeaderName {get;set;}="";
    public int ExternalPack {get;set;}=1;
    public string ExternalEndian {get;set;}="be";
    public string ExternalBitOrder {get;set;}="lsb0";
    public bool SeparateHeader {get;set;}
    public bool IcdIncludesHeader {get;set;}=true;
    public int HeaderBytes {get;set;}
    public bool LengthIncludesHeader {get;set;}=true;
    public List<CaptureMessageRule> Messages {get;set;}=[];
    public int DecodeOffset=>IcdIncludesHeader?0:HeaderBytes;
    public int LengthAdjustment=>LengthIncludesHeader?0:HeaderBytes;
    public static ulong ParseId(string value)=>value.Trim().StartsWith("0x",StringComparison.OrdinalIgnoreCase)?ulong.Parse(value.Trim()[2..],NumberStyles.AllowHexSpecifier,CultureInfo.InvariantCulture):ulong.Parse(value.Trim(),NumberStyles.None,CultureInfo.InvariantCulture);
    private static bool SameLayout(IcdField a,IcdField b)=>a.Type==b.Type&&a.BitLength==b.BitLength&&IcdExport.NumericPhysicalBits(a).SequenceEqual(IcdExport.NumericPhysicalBits(b));
    public string HeaderError(IcdSchema schema,string message)
    {
        if(!IcdIncludesHeader)return "";
        if(schema.RequiredBytes(message)<HeaderBytes)return $"{message}: 메시지 크기 {schema.RequiredBytes(message)} bytes가 지정 헤더 {HeaderBytes} bytes보다 작습니다.";
        foreach(var header in new[]{IdField!,LengthField!}){
            var expected=IcdExport.NumericPhysicalBits(header);var matches=schema.Fields.Where(f=>f.Message==message&&f.Type is "uint" or "int"&&f.Scale==1&&f.Bias==0&&f.BitLength==header.BitLength&&IcdExport.NumericPhysicalBits(f).SequenceEqual(expected)).ToList();
            if(matches.Count!=1)return $"{message}: 선택한 {header.Name} 위치(byte {header.ByteOffset}, bit {header.BitOffset})에 {header.BitLength} bits 정수 필드가 없습니다. 비트 폭·위치·엔디언을 확인하세요. 필드 이름은 같을 필요가 없습니다.";
        }return "";
    }
    public void ValidateHeaderDefinition()
    {
        if(IdField==null||LengthField==null||HeaderBytes is <1 or >65535||HeaderSources.Sum(s=>(long)s.Content.Length)>16*1024*1024)throw new ArgumentException("공통헤더 ID·Length와 전체 크기를 지정하세요.");
        PacketHeaderMatcher.ValidateHeaderField(IdField);PacketHeaderMatcher.ValidateHeaderField(LengthField);
        if(HeaderBytes<Math.Max(IdField.EndByte,LengthField.EndByte)||IcdSchema.PhysicalBits(IdField).Intersect(IcdSchema.PhysicalBits(LengthField)).Any())throw new ArgumentException("ID·Length가 겹치거나 헤더 크기를 넘습니다.");
        if(!HeaderFields.Any(f=>SameLayout(f,IdField))||!HeaderFields.Any(f=>SameLayout(f,LengthField)))throw new ArgumentException("선택 ID·Length가 헤더 정의에 없습니다.");
    }
    public void Prepare(IcdSchema schema)
    {
        if(RequireHeaderLayout){ValidateHeaderDefinition();var errors=schema.Messages.Select(m=>HeaderError(schema,m)).Where(e=>e.Length>0).ToList();if(errors.Count>0)throw new ArgumentException(string.Join("\n",errors));}
        if(MatchByStructure){if(IdField==null||LengthField==null)throw new ArgumentException("ID·Length 필드를 선택하세요.");Messages=schema.Messages.Where(m=>!IcdIncludesHeader||RequireHeaderLayout||new[]{IdField!,LengthField!}.All(field=>schema.Fields.Any(f=>f.Message==m&&SameLayout(f,field)))).Where(m=>schema.RequiredBytes(m)+DecodeOffset>=HeaderBytes).Select(m=>new CaptureMessageRule(m,"",schema.RequiredBytes(m))).ToList();}
        Validate();if(!SeparateHeader&&!IcdIncludesHeader)throw new ArgumentException("ICD가 본문만 포함하면 별도 헤더를 선택하세요.");
        if(HeaderFields.Count==0)throw new ArgumentException("헤더 필드가 없습니다.");
        if(!HeaderFields.Any(f=>SameLayout(f,IdField!))||!HeaderFields.Any(f=>SameLayout(f,LengthField!)))throw new ArgumentException("선택한 ID/Length가 헤더에 포함되어 있지 않습니다.");
        var updated=new List<CaptureMessageRule>();
        foreach(var rule in Messages){if(!schema.Messages.Contains(rule.Message))throw new ArgumentException("ICD 메시지를 찾을 수 없습니다: "+rule.Message);
            if(IcdIncludesHeader&&!RequireHeaderLayout)foreach(var field in (MatchByStructure?new[]{IdField!,LengthField!}.AsEnumerable():HeaderFields))if(!schema.Fields.Any(f=>f.Message==rule.Message&&SameLayout(f,field)))throw new ArgumentException($"{rule.Message}: 헤더 필드 {field.Name}의 위치·타입·길이·엔디언이 ICD와 다릅니다.");
            if(HeaderBytes>(long)schema.RequiredBytes(rule.Message)+DecodeOffset)throw new ArgumentException("헤더가 전체 ICD 패킷보다 큽니다.");
            updated.Add(rule with{BodyBytes=schema.RequiredBytes(rule.Message)});
        }
        Messages=updated;_ = CreateMatcher(new RecordProfile{Name="검증",SenderIps=["192.0.2.1"],ReceiverIps=["192.0.2.2"]});
    }
    public void PrepareForConversion(IcdSchema schema){foreach(var rule in Messages)if(!schema.Messages.Contains(rule.Message)||schema.RequiredBytes(rule.Message)!=rule.BodyBytes)throw new ArgumentException("ICD 크기와 저장된 헤더 규칙이 다릅니다.");}
    public void Validate()
    {
        if(Transport!="UDP")throw new ArgumentException("현재 완전한 UDP 데이터그램만 지원합니다. TCP는 스트림 재조립 규칙이 필요합니다.");
        if(Checksum!="none")throw new ArgumentException("체크섬은 없음 모드만 지원합니다. 알고리즘을 추측하지 않습니다.");
        if(IdField==null||LengthField==null||HeaderBytes is <1 or >65535||Messages.Count is <1 or >256||HeaderFields.Count>256||HeaderSources.Sum(s=>(long)s.Content.Length)>16*1024*1024)throw new ArgumentException("ID·Length·헤더 크기·메시지 매핑을 지정하세요.");
        if(HeaderBytes<Math.Max(IdField.EndByte,LengthField.EndByte)||(!RequireHeaderLayout&&HeaderFields.Any(f=>f.EndByte>HeaderBytes)))throw new ArgumentException("선택한 필드가 지정한 헤더 크기를 넘습니다.");
    }
    public PacketHeaderMatcher CreateMatcher(RecordProfile profile)
    {
        Validate();var schema=new IcdSchema();foreach(var r in Messages){if(r.BodyBytes is <1 or >65535)throw new ArgumentException("ICD 메시지 크기를 먼저 검증·저장하세요.");schema.Fields.Add(new(r.Message,"_payload",0,0,r.BodyBytes*8,"bytes","be","msb0",1,0,"","",0));}
        return new PacketHeaderMatcher(profile,schema,IdField!,LengthField!,Messages.Select(r=>new HeaderMessageId(MatchByStructure?0:ParseId(r.Id),r.Message)),LengthAdjustment,DecodeOffset,MatchByStructure);
    }
    internal bool CanOverlap(CapturePolicy other)
    {
        foreach(var a in Messages)foreach(var b in other.Messages){int total=a.BodyBytes+DecodeOffset;if(total!=b.BodyBytes+other.DecodeOffset)continue;var assignments=new Dictionary<int,bool>();
            bool Add(IcdField field,ulong value){var bits=IcdExport.NumericPhysicalBits(field);for(int k=0;k<bits.Length;k++){bool bit=((value>>k)&1)!=0;if(assignments.TryGetValue(bits[k],out var old)&&old!=bit)return false;assignments[bits[k]]=bit;}return true;}
            if((MatchByStructure||Add(IdField!,ParseId(a.Id)))&&Add(LengthField!,(ulong)(total-LengthAdjustment))&&(other.MatchByStructure||Add(other.IdField!,ParseId(b.Id)))&&Add(other.LengthField!,(ulong)(total-other.LengthAdjustment)))return true;
        }return false;
    }
    public CapturePolicy Clone()=>JsonSerializer.Deserialize<CapturePolicy>(JsonSerializer.Serialize(this))!;
    public CapturePolicy Minimal()=>new(){RequireHeaderLayout=RequireHeaderLayout,MatchByStructure=MatchByStructure,Transport=Transport,Checksum=Checksum,IdField=IdField,LengthField=LengthField,HeaderFields=[IdField!,LengthField!],SeparateHeader=SeparateHeader,IcdIncludesHeader=IcdIncludesHeader,HeaderBytes=HeaderBytes,LengthIncludesHeader=LengthIncludesHeader,Messages=[..Messages],ExternalPack=ExternalPack,ExternalEndian=ExternalEndian,ExternalBitOrder=ExternalBitOrder};
    public void Clear(){foreach(var s in HeaderSources)CryptographicOperations.ZeroMemory(s.Content);HeaderSources=[];HeaderFields=[];IdField=LengthField=null;Messages=[];HeaderName="";}
}
