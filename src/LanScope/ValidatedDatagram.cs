using PacketDotNet;
using SharpPcap;
namespace LanScope;
internal sealed record ValidatedDatagram(System.Net.IPAddress Source,System.Net.IPAddress Destination,int SourcePort,int DestinationPort,byte[] Payload)
{
    internal static ValidatedDatagram? Read(RawCapture raw)
    {
        try {
            var ip=Packet.ParsePacket(raw.LinkLayerType,raw.Data).Extract<IPPacket>();if(ip==null)return null;var b=ip.Bytes;int start,total;
            if(b.Length>=20&&(b[0]>>4)==4){start=(b[0]&15)*4;total=(b[2]<<8)|b[3];int fragment=(b[6]<<8)|b[7];if(start<20||total<start+8||total>b.Length||(fragment&0x3FFF)!=0||b[9]!=17)return null;}
            else if(b.Length>=40&&(b[0]>>4)==6){start=40;total=40+((b[4]<<8)|b[5]);if(b[6]!=17||total<48||total>b.Length)return null;} // No fragment/extension reassembly.
            else return null;
            int length=(b[start+4]<<8)|b[start+5];if(length<8||start+length!=total)return null;
            return new(ip.SourceAddress,ip.DestinationAddress,(b[start]<<8)|b[start+1],(b[start+2]<<8)|b[start+3],b.AsSpan(start+8,length-8).ToArray());
        }catch{return null;}
    }
}
