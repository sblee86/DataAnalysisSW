using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace LanScope;
public sealed record CsvConversionResult(long Frames,long Rows,long Skipped,long RowsWithErrors);
public static class PcapCsvConverter
{
    private static RecordProfile Authorize(LoginSession session,WorkspaceSettings settings,string profileId)
    {
        _=session.SessionKey;var profile=settings.Profiles.SingleOrDefault(p=>p.Id==profileId)??throw new ArgumentException("인터페이스를 선택하세요.");
        if(session.Role==UserRole.Guest) {
            if(!settings.GuestIcdAllowList.Contains(profile.IcdId))throw new UnauthorizedAccessException("이 인터페이스의 CSV 변환 권한이 없습니다. PCAP 기록은 가능합니다.");
            if(settings.HasGuestConversionConflict(profileId))throw new UnauthorizedAccessException("동일 IP의 제한 ICD를 구별할 수 없어 CSV 변환을 차단합니다. PCAP 기록은 가능합니다.");
            if(profile.GuestConversionIcd.Length==0)throw new UnauthorizedAccessException("관리자가 CSV 변환 허용 설정을 다시 저장해야 합니다.");
        }
        return profile;
    }
    private static IcdSchema Schema(LoginSession session,RecordProfile profile)
    {
        if(session.Role==UserRole.Guest){var bytes=GuestIcdAccess.Open(session,profile);try{return IcdCsv.Parse(bytes);}finally{CryptographicOperations.ZeroMemory(bytes);}}
        session.RequireAdmin();var temporary=new RecordProfile{Id=profile.Id,IcdId=profile.IcdId,EncryptedIcd=profile.EncryptedIcd};
        try{IcdProtection.Open(session,temporary);return IcdCsv.Parse(temporary.IcdContent);}finally{temporary.ClearPlaintext();}
    }
    public static string[] Messages(LoginSession session,WorkspaceSettings settings,string profileId)=>Schema(session,Authorize(session,settings,profileId)).Messages;
    public static CsvConversionResult Convert(LoginSession session,WorkspaceSettings settings,string profileId,string message,string input,string output,CancellationToken cancellation=default)
    {
        var profile=Authorize(session,settings,profileId);var schema=Schema(session,profile);
        if(!schema.Messages.Contains(message))throw new ArgumentException("CSV 메시지를 선택하세요.");
        input=Path.GetFullPath(input);output=Path.GetFullPath(output);if(string.Equals(input,output,StringComparison.OrdinalIgnoreCase))throw new ArgumentException("PCAP 원본과 CSV 출력 경로는 달라야 합니다.");
        string temp=output+"."+Guid.NewGuid().ToString("N")+".tmp";long frames=0,rows=0,skipped=0,errors=0;
        string Escape(string value)=>"\""+value.Replace("\"","\"\"")+"\"";
        string SafeHeader(string value)=>value.Length>0&&"=+-@".Contains(value[0])?"'"+value:value;
        try {
            using var reader=new CaptureFileReaderDevice(input);reader.Open();
            using(var writer=new StreamWriter(new FileStream(temp,FileMode.CreateNew,FileAccess.Write),new UTF8Encoding(true))) {
                var header=new[]{"PacketIndex","UtcTimestamp","SourceIP","DestinationIP","SourcePort","DestinationPort"}.Concat(schema.Fields.Where(f=>f.Message==message).Select(f=>SafeHeader(f.Name))).Append("DecodeError");writer.WriteLine(string.Join(",",header.Select(Escape)));
                while(true) {
                    cancellation.ThrowIfCancellationRequested();var status=reader.GetNextPacket(out var capture);if(status==GetPacketStatus.NoRemainingPackets)break;if(status!=GetPacketStatus.PacketRead)throw new IOException("PCAP 읽기 실패: "+status);
                    frames++;var raw=capture.GetPacket();IPPacket? ip;UdpPacket? udp;
                    try {var packet=Packet.ParsePacket(raw.LinkLayerType,raw.Data);ip=packet.Extract<IPPacket>();udp=packet.Extract<UdpPacket>();}
                    catch {skipped++;continue;}
                    if(ip==null||udp==null||!profile.Matches(ip.SourceAddress,ip.DestinationAddress)||ip is IPv4Packet ipv4&&(ipv4.FragmentOffset!=0||(ipv4.FragmentFlags&1)!=0)||udp.Length!=udp.PayloadData.Length+8){skipped++;continue;}
                    var decoded=schema.Decode(message,udp.PayloadData);string error=string.Join("; ",decoded.Where(f=>f.Error.Length>0).Select(f=>f.Name+": "+f.Error));if(error.Length>0)errors++;
                    var values=new[]{frames.ToString(CultureInfo.InvariantCulture),raw.Timeval.Date.ToUniversalTime().ToString("O"),ip.SourceAddress.ToString(),ip.DestinationAddress.ToString(),udp.SourcePort.ToString(CultureInfo.InvariantCulture),udp.DestinationPort.ToString(CultureInfo.InvariantCulture)}.Concat(decoded.Select(f=>f.Error.Length>0?"":f.Value)).Append(error);
                    writer.WriteLine(string.Join(",",values.Select(Escape)));rows++;
                }
            }
            cancellation.ThrowIfCancellationRequested();File.Move(temp,output,true);return new(frames,rows,skipped,errors);
        }finally{if(File.Exists(temp))File.Delete(temp);}
    }
}
