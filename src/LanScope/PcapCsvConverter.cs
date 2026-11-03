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
        if(!profile.Enabled)throw new UnauthorizedAccessException("비활성 ICD는 CSV로 변환할 수 없습니다. PCAP 기록은 가능합니다.");
        if(session.Role==UserRole.Guest) {
            if(!settings.GuestIcdAllowList.Contains(profile.IcdId))throw new UnauthorizedAccessException("이 인터페이스의 CSV 변환 권한이 없습니다. PCAP 기록은 가능합니다.");

            if(profile.GuestConversionIcd.Length==0)throw new UnauthorizedAccessException("관리자가 CSV 변환 허용 설정을 다시 저장해야 합니다.");
        }
        if(profile.CapturePolicy==null)throw new ArgumentException("공통헤더 ID·Length 및 메시지 ID 규칙을 설정하세요.");
        return profile;
    }
    private static IcdSchema Schema(LoginSession session,RecordProfile profile)
    {
        var temporary=new RecordProfile{Id=profile.Id,IcdId=profile.IcdId,EncryptedIcd=profile.EncryptedIcd,ByteOrder=profile.ByteOrder,StructPack=profile.StructPack,StructBitOrder=profile.StructBitOrder};
        try {
            if(session.Role==UserRole.Guest){var bytes=GuestIcdAccess.Open(session,profile);try{IcdBundle.Unpack(bytes,temporary);}finally{CryptographicOperations.ZeroMemory(bytes);}}
            else IcdProtection.Open(session,temporary);
            return temporary.ParseSchema();
        }finally{temporary.ClearPlaintext();}
    }
    public static string[] Messages(LoginSession session,WorkspaceSettings settings,string profileId){var p=Authorize(session,settings,profileId);var schema=Schema(session,p);p.CapturePolicy!.PrepareForConversion(schema);return p.CapturePolicy.Messages.Select(r=>r.Message).Distinct().ToArray();}
    public static CsvConversionResult Convert(LoginSession session,WorkspaceSettings settings,string profileId,string message,string input,string output,CancellationToken cancellation=default)
    {
        var profile=Authorize(session,settings,profileId);var schema=Schema(session,profile);profile.CapturePolicy!.PrepareForConversion(schema);var matcher=profile.CapturePolicy.CreateMatcher(profile);var otherMatchers=settings.Profiles.Where(other=>other.Id!=profile.Id&&other.Enabled&&other.CapturePolicy!=null).Select(other=>other.CapturePolicy!.CreateMatcher(other)).ToArray();
        if(!schema.Messages.Contains(message)||!profile.CapturePolicy.Messages.Any(r=>r.Message==message))throw new ArgumentException("CSV 메시지를 선택하세요.");
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
                    frames++;var raw=capture.GetPacket();var datagram=ValidatedDatagram.Read(raw);
                    if(datagram==null){skipped++;continue;}
                    var match=matcher.Match(datagram.Source,datagram.Destination,datagram.Payload);
                    bool ambiguous=otherMatchers.Any(other=>other.Match(datagram.Source,datagram.Destination,datagram.Payload).Accepted);
                    if(!match.Accepted||match.Message!=message||ambiguous){skipped++;continue;}
                    var decoded=schema.Decode(message,datagram.Payload.AsSpan(match.DecodeOffset));string error=string.Join("; ",decoded.Where(f=>f.Error.Length>0).Select(f=>f.Name+": "+f.Error));if(error.Length>0)errors++;
                    var values=new[]{frames.ToString(CultureInfo.InvariantCulture),raw.Timeval.Date.ToUniversalTime().ToString("O"),datagram.Source.ToString(),datagram.Destination.ToString(),datagram.SourcePort.ToString(CultureInfo.InvariantCulture),datagram.DestinationPort.ToString(CultureInfo.InvariantCulture)}.Concat(decoded.Select(f=>f.Error.Length>0?"":f.Value)).Append(error);
                    writer.WriteLine(string.Join(",",values.Select(Escape)));rows++;
                }
            }
            cancellation.ThrowIfCancellationRequested();File.Move(temp,output,true);return new(frames,rows,skipped,errors);
        }finally{if(File.Exists(temp))File.Delete(temp);}
    }
}
