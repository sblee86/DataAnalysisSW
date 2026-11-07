using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Encodings.Web;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace LanScope;
public sealed record CsvConversionResult(long Frames,long Rows,long Skipped,long RowsWithErrors,long RowsOutsideRange=0,string LogFile="",string LogWarning="");
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
    private static readonly JsonSerializerOptions LogJson=new(){Encoder=JavaScriptEncoder.UnsafeRelaxedJsonEscaping};
    public static CsvConversionResult Convert(LoginSession session,WorkspaceSettings settings,string profileId,string message,string input,string output,CancellationToken cancellation=default,bool overwrite=true)
    {
        var profile=Authorize(session,settings,profileId);
        input=Path.GetFullPath(input);output=Path.GetFullPath(output);if(string.Equals(input,output,StringComparison.OrdinalIgnoreCase))throw new ArgumentException("PCAP 원본과 CSV 출력 경로는 달라야 합니다.");
        // Create a distinct log for every attempt; never replace an older log or source file.
        string logBase=ConversionOutput.LogPath(output),logPath=logBase;FileStream? logStream=null;
        for(int i=0;logStream==null;i++){logPath=i==0?logBase:Path.Combine(Path.GetDirectoryName(logBase)!,Path.GetFileNameWithoutExtension(logBase)+"_"+i.ToString("D3",CultureInfo.InvariantCulture)+".txt");try{logStream=new FileStream(logPath,FileMode.CreateNew,FileAccess.Write,FileShare.Read);}catch(IOException) when(File.Exists(logPath)){if(i>=9999)throw new IOException("변환 로그 파일명 충돌 한도를 넘었습니다.");}}
        var log=new StreamWriter(logStream,new UTF8Encoding(true)){AutoFlush=true};
        void Log(string level,string code,object detail)=>log.WriteLine($"{DateTimeOffset.UtcNow:O}\t{level}\t{code}\t{JsonSerializer.Serialize(detail,LogJson)}");
        string temp=output+"."+Guid.NewGuid().ToString("N")+".tmp";long frames=0,rows=0,skipped=0,errors=0,rangeErrors=0;var reasons=new Dictionary<string,long>();
        void Count(string reason)=>reasons[reason]=reasons.GetValueOrDefault(reason)+1;
        string Escape(string value)=>"\""+value.Replace("\"","\"\"")+"\"";
        string SafeHeader(string value)=>value.Length>0&&"=+-@".Contains(value[0])?"'"+value:value;
        try {
            Log("INFO","Start",new{LocalStart=DateTimeOffset.Now,Interface=profile.Name,Message=message,Input=input,Output=output,Log=logPath});
            var schema=Schema(session,profile);profile.CapturePolicy!.PrepareForConversion(schema);var policy=profile.CapturePolicy;var matcher=policy.CreateMatcher(profile);var otherMatchers=settings.Profiles.Where(other=>other.Id!=profile.Id&&other.Enabled&&other.CapturePolicy!=null).Select(other=>other.CapturePolicy!.CreateMatcher(other)).ToArray();
            if(!schema.Messages.Contains(message)||!policy.Messages.Any(r=>r.Message==message))throw new ArgumentException("CSV 메시지를 선택하세요.");
            var definitions=schema.Fields.Where(f=>f.Message==message).ToDictionary(f=>f.Name);
            Log("INFO","Rules",new{HeaderBytes=policy.HeaderBytes,policy.LengthIncludesHeader,policy.MatchByStructure,DecodeOffset=policy.DecodeOffset,ExpectedPayloadBytes=schema.RequiredBytes(message)+policy.DecodeOffset,FieldCount=definitions.Count,profile.SenderIps,profile.ReceiverIps,profile.BothDirections,IdField=new{policy.IdField!.ByteOffset,policy.IdField.BitOffset,policy.IdField.BitLength,policy.IdField.Endian,policy.IdField.BitOrder},LengthField=new{policy.LengthField!.ByteOffset,policy.LengthField.BitOffset,policy.LengthField.BitLength,policy.LengthField.Endian,policy.LengthField.BitOrder},CandidatePayloadSizes=policy.Messages.Select(r=>r.BodyBytes+policy.DecodeOffset).Distinct().ToArray()});
            using var reader=new CaptureFileReaderDevice(input);reader.Open();
            using(var writer=new StreamWriter(new FileStream(temp,FileMode.CreateNew,FileAccess.Write),new UTF8Encoding(true))) {
                var header=new[]{"PacketIndex","UtcTimestamp","SourceIP","DestinationIP","SourcePort","DestinationPort"}.Concat(schema.Fields.Where(f=>f.Message==message).Select(f=>SafeHeader(f.Name))).Concat(new[]{"DecodeError","RangeError"});writer.WriteLine(string.Join(",",header.Select(Escape)));
                while(true) {
                    cancellation.ThrowIfCancellationRequested();var status=reader.GetNextPacket(out var capture);if(status==GetPacketStatus.NoRemainingPackets)break;if(status!=GetPacketStatus.PacketRead)throw new IOException("PCAP 읽기 실패: "+status);
                    frames++;var raw=capture.GetPacket();var timestamp=raw.Timeval.Date.ToUniversalTime().ToString("O");var datagram=ValidatedDatagram.Read(raw,out var invalidReason);
                    if(datagram==null){skipped++;Count("InvalidDatagram");Log("SKIP","InvalidDatagram",new{Packet=frames,UtcTimestamp=timestamp,FrameBytes=raw.Data.Length,LinkLayer=raw.LinkLayerType.ToString(),Reason=invalidReason});continue;}
                    var match=matcher.Match(datagram.Source,datagram.Destination,datagram.Payload);
                    bool ambiguous=otherMatchers.Any(other=>other.Match(datagram.Source,datagram.Destination,datagram.Payload).Accepted);
                    if(!match.Accepted||match.Message!=message||ambiguous){skipped++;string reason=!match.Accepted?match.Failure.ToString():ambiguous?"AmbiguousInterface":"OtherMessage";Count(reason);
                        string? Read(IcdField? field)=>field!=null&&datagram.Payload.Length>=field.EndByte?IcdSchema.ExtractBits(datagram.Payload,field).ToString(CultureInfo.InvariantCulture):null;
                        Log("SKIP",reason,new{Packet=frames,UtcTimestamp=timestamp,Source=datagram.Source.ToString(),Destination=datagram.Destination.ToString(),datagram.SourcePort,datagram.DestinationPort,PayloadBytes=datagram.Payload.Length,ObservedId=Read(policy.IdField),DeclaredLength=Read(policy.LengthField),ExpectedDeclaredLength=datagram.Payload.Length-policy.LengthAdjustment,ExpectedSelectedPayload=schema.RequiredBytes(message)+policy.DecodeOffset,RequiredHeaderBytes=policy.HeaderBytes,MatchedMessage=match.Accepted?match.Message:null});continue;}
                    var decoded=schema.Decode(message,datagram.Payload.AsSpan(match.DecodeOffset));string error=string.Join("; ",decoded.Where(f=>f.Error.Length>0).Select(f=>f.Name+": "+f.Error));if(error.Length>0)errors++;string rangeError=string.Join("; ",decoded.Where(f=>f.RangeError.Length>0).Select(f=>f.Name+": "+f.RangeError));if(rangeError.Length>0)rangeErrors++;
                    foreach(var field in decoded.Where(f=>f.Error.Length>0||f.RangeError.Length>0)){var definition=definitions[field.Name];string? rawBits=definition.Type!="bytes"&&definition.BitLength<=64&&datagram.Payload.Length-match.DecodeOffset>=definition.EndByte?IcdSchema.ExtractBits(datagram.Payload.AsSpan(match.DecodeOffset),definition).ToString("X",CultureInfo.InvariantCulture):null;Log("ERROR",field.Error.Length>0?"FieldDecodeError":"FieldRangeError",new{Packet=frames,UtcTimestamp=timestamp,Source=datagram.Source.ToString(),Destination=datagram.Destination.ToString(),datagram.SourcePort,datagram.DestinationPort,Field=field.Name,definition.ByteOffset,PayloadByteOffset=definition.ByteOffset+match.DecodeOffset,definition.BitOffset,definition.BitLength,definition.Type,definition.Endian,RawBitsHex=rawBits,Raw=field.Raw,Value=field.Value,Minimum=definition.Minimum,Maximum=definition.Maximum,Reason=field.Error.Length>0?field.Error:field.RangeError});}
                    var values=new[]{frames.ToString(CultureInfo.InvariantCulture),timestamp,datagram.Source.ToString(),datagram.Destination.ToString(),datagram.SourcePort.ToString(CultureInfo.InvariantCulture),datagram.DestinationPort.ToString(CultureInfo.InvariantCulture)}.Concat(decoded.Select(f=>f.Error.Length>0?"":f.Value)).Concat(new[]{error,rangeError});writer.WriteLine(string.Join(",",values.Select(Escape)));rows++;
                }
            }
            cancellation.ThrowIfCancellationRequested();File.Move(temp,output,overwrite);
            string warning="";try{Log("INFO","Completed",new{Frames=frames,Rows=rows,Skipped=skipped,DecodeErrorRows=errors,RangeErrorRows=rangeErrors,SkipReasons=reasons});}catch(Exception logError) when(logError is IOException or UnauthorizedAccessException){warning="CSV는 저장됐으나 완료 로그 기록에 실패했습니다: "+logError.Message;}return new(frames,rows,skipped,errors,rangeErrors,logPath,warning);
        }catch(Exception error){error.Data["ConversionLogPath"]=logPath;try{Log(error is OperationCanceledException?"WARN":"FATAL",error is OperationCanceledException?"Cancelled":"Failed",new{Exception=error.GetType().FullName,error.Message,error.HResult,error.StackTrace,LastPacket=frames,Rows=rows,Skipped=skipped,DecodeErrorRows=errors,RangeErrorRows=rangeErrors,SkipReasons=reasons});}catch(Exception loggingError) when(loggingError is IOException or UnauthorizedAccessException){}throw;}
        finally{try{log.Dispose();}catch(Exception logError) when(logError is IOException or UnauthorizedAccessException){}if(File.Exists(temp))File.Delete(temp);}
    }
}
