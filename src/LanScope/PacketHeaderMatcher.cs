using System.Net;
namespace LanScope;

public enum PacketMatchFailure { None, ConfigurationMissing, EndpointMismatch, TruncatedHeader, UnknownMessageId, LengthMismatch, IcdSizeMismatch, AmbiguousMessage }
public readonly record struct PacketMatchResult(PacketMatchFailure Failure,string Message="",int DecodeOffset=0)
{
    public bool Accepted=>Failure==PacketMatchFailure.None;
}
public sealed record HeaderMessageId(ulong Id,string Message);

/// <summary>
/// Checks a complete application PDU, after transport framing/reassembly.
/// Layout is explicit: no field-name/byte-offset guessing and no accept-all fallback.
/// The caller must not save or decode a PDU unless Accepted is true.
/// </summary>
public sealed class PacketHeaderMatcher
{
    private readonly HashSet<IPAddress> senders,receivers;private readonly bool enabled,bothDirections;
    private readonly Dictionary<string,int> messageSizes;
    private readonly IcdField idField,lengthField;
    private readonly Dictionary<ulong,string> messages;
    private readonly int declaredLengthAdjustment,decodeOffset;private readonly bool structureOnly;
    public PacketHeaderMatcher(RecordProfile profile,IcdSchema schema,IcdField idField,IcdField lengthField,IEnumerable<HeaderMessageId> messages,int declaredLengthAdjustment,int decodeOffset,bool structureOnly=false)
    {
        ValidateHeaderField(idField);ValidateHeaderField(lengthField);
        if(IcdSchema.PhysicalBits(idField).Intersect(IcdSchema.PhysicalBits(lengthField)).Any())throw new ArgumentException("공통헤더 ID와 길이 필드가 겹칩니다.");
        if(decodeOffset<0||decodeOffset>65535||declaredLengthAdjustment is <-65535 or >65535)throw new ArgumentException("헤더/ICD 기준 오프셋 오류");
        this.structureOnly=structureOnly;this.messages=[];
        foreach(var entry in messages){if(!schema.Messages.Contains(entry.Message)||!this.messages.TryAdd(structureOnly?(ulong)this.messages.Count:entry.Id,entry.Message))throw new ArgumentException("메시지 ID와 ICD 메시지명 매핑이 누락되거나 중복되었습니다.");if(!structureOnly&&idField.BitLength<64&&entry.Id>=(1UL<<idField.BitLength))throw new ArgumentException("메시지 ID가 헤더 비트 폭을 넘습니다.");int expected=checked(schema.RequiredBytes(entry.Message)+decodeOffset);long declared=(long)expected-declaredLengthAdjustment;if(declared<0||(lengthField.BitLength<64&&(ulong)declared>=(1UL<<lengthField.BitLength)))throw new ArgumentException("기대 길이를 Length 필드로 표현할 수 없습니다.");if(expected>65535||expected<Math.Max(idField.EndByte,lengthField.EndByte))throw new ArgumentException("ICD 크기와 공통헤더 범위가 맞지 않습니다.");}
        if(this.messages.Count==0)throw new ArgumentException("메시지 ID 매핑이 필요합니다.");
        profile.ValidateEndpoints();senders=profile.SenderIps.Select(IPAddress.Parse).ToHashSet();receivers=profile.ReceiverIps.Select(IPAddress.Parse).ToHashSet();enabled=profile.Enabled;bothDirections=profile.BothDirections;
        this.messageSizes=this.messages.Values.Distinct().ToDictionary(m=>m,schema.RequiredBytes);this.idField=idField;this.lengthField=lengthField;this.declaredLengthAdjustment=declaredLengthAdjustment;this.decodeOffset=decodeOffset;
    }
    private static void ValidateHeaderField(IcdField f)
    {
        if(f.Type is not ("uint" or "int")||f.Scale!=1||f.Bias!=0||f.ByteOffset is <0 or >65534||f.BitOffset is <0 or >7||f.BitLength is <1 or >64||f.EndByte>65535||f.Endian is not ("be" or "le")||f.BitOrder is not ("msb0" or "lsb0"))throw new ArgumentException("공통헤더 ID/길이는 위치·순서가 명시된 raw integer 필드여야 합니다.");
        if(f.StorageBits!=0&&(f.StorageBits is not (8 or 16 or 32 or 64)||f.StorageBitOffset<0||f.StorageBitOffset>f.StorageBits-f.BitLength||f.BitOffset!=f.StorageBitOffset%8))throw new ArgumentException("공통헤더 저장 단위 오류");
        if(f.StorageBits==0&&f.StorageBitOffset!=0)throw new ArgumentException("공통헤더 저장 단위 오프셋 오류");
    }
    public PacketMatchResult Match(IPAddress source,IPAddress destination,ReadOnlySpan<byte> completePdu)
    {
        if(!enabled||!((senders.Contains(source)&&receivers.Contains(destination))||(bothDirections&&senders.Contains(destination)&&receivers.Contains(source))))return new(PacketMatchFailure.EndpointMismatch);
        if(completePdu.Length<Math.Max(idField.EndByte,lengthField.EndByte))return new(PacketMatchFailure.TruncatedHeader);
        ulong id=IcdSchema.ExtractBits(completePdu,idField);string? message=null;if(!structureOnly&&!messages.TryGetValue(id,out message))return new(PacketMatchFailure.UnknownMessageId);
        // adjustment=0 means the declared length includes the whole PDU.
        // adjustment=header bytes means the declared length excludes that header.
        long expectedDeclaration=(long)completePdu.Length-declaredLengthAdjustment;
        if(expectedDeclaration<0||IcdSchema.ExtractBits(completePdu,lengthField)!=(ulong)expectedDeclaration)return new(PacketMatchFailure.LengthMismatch);
        if(structureOnly){var payloadBytes=completePdu.Length;var candidates=messageSizes.Where(p=>(long)p.Value+decodeOffset==payloadBytes).Select(p=>p.Key).Take(2).ToArray();if(candidates.Length==0)return new(PacketMatchFailure.IcdSizeMismatch);if(candidates.Length>1)return new(PacketMatchFailure.AmbiguousMessage);message=candidates[0];}
        if(completePdu.Length!=(long)messageSizes[message!]+decodeOffset)return new(PacketMatchFailure.IcdSizeMismatch);
        return new(PacketMatchFailure.None,message!,decodeOffset);
    }
}
