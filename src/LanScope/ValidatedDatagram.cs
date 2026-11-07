using PacketDotNet;
using SharpPcap;
namespace LanScope;
internal sealed record ValidatedDatagram(System.Net.IPAddress Source,System.Net.IPAddress Destination,int SourcePort,int DestinationPort,byte[] Payload)
{
    internal static ValidatedDatagram? Read(RawCapture raw)=>Read(raw,out _);
    private static ValidatedDatagram? Invalid(out string reason,string detail){reason=detail;return null;}
    internal static ValidatedDatagram? Read(RawCapture raw,out string reason)
    {
        reason="";
        try {
            var ip=Packet.ParsePacket(raw.LinkLayerType,raw.Data).Extract<IPPacket>();if(ip==null)return Invalid(out reason,"NonIp: IP 패킷이 아닙니다.");var b=ip.Bytes;int start,total;
            if(b.Length>=20&&(b[0]>>4)==4){start=(b[0]&15)*4;total=(b[2]<<8)|b[3];int fragment=(b[6]<<8)|b[7];if(start<20)return Invalid(out reason,$"InvalidIpv4Header: IHL={start}");if(total<start+8||total>b.Length)return Invalid(out reason,$"InvalidIpv4Length: declared={total}, available={b.Length}, header={start}");if((fragment&0x3FFF)!=0)return Invalid(out reason,$"Ipv4Fragment: flags/offset=0x{fragment:X4}, 재조립 미지원");if(b[9]!=17)return Invalid(out reason,$"NonUdp: IP protocol={b[9]}");}
            else if(b.Length>=40&&(b[0]>>4)==6){start=40;total=40+((b[4]<<8)|b[5]);if(b[6]!=17)return Invalid(out reason,$"Ipv6ExtensionOrNonUdp: nextHeader={b[6]}, 확장/조각 재조립 미지원");if(total<48||total>b.Length)return Invalid(out reason,$"InvalidIpv6Length: declared={total}, available={b.Length}");}
            else return Invalid(out reason,$"InvalidIpHeader: available={b.Length}");
            int length=(b[start+4]<<8)|b[start+5];if(length<8||start+length!=total)return Invalid(out reason,$"InvalidUdpLength: UDP declared={length}, IP payload={total-start}");
            return new(ip.SourceAddress,ip.DestinationAddress,(b[start]<<8)|b[start+1],(b[start+2]<<8)|b[start+3],b.AsSpan(start+8,length-8).ToArray());
        }catch(Exception e){return Invalid(out reason,"PacketParseFailure: "+e.GetType().Name+": "+e.Message);}
    }
}
