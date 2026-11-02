using System.IO;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;

namespace LanScope;
public record PacketRow(int Number, string Time, string Source, string Destination, string Protocol, int Length, string Info);
public partial class MainWindow : Window
{
    private readonly List<PacketRow> packets = [
        new(1,"0.000000","192.168.0.12","93.184.216.34","TCP",74,"52104 → 443 [SYN]"),
        new(2,"0.001204","93.184.216.34","192.168.0.12","TCP",74,"443 → 52104 [SYN, ACK]"),
        new(3,"0.001318","192.168.0.12","93.184.216.34","TCP",66,"52104 → 443 [ACK]"),
        new(4,"0.004821","192.168.0.12","93.184.216.34","TCP",1514,"Application data · segment 1"),
        new(5,"0.005103","93.184.216.34","192.168.0.12","TCP",1514,"Application data · segment 2"),
        new(6,"0.010411","192.168.0.12","192.168.0.1","UDP",1514,"5353 → 5353 · Multicast query"),
        new(7,"0.012084","192.168.0.12","8.8.8.8","DNS",1420,"Standard query · example.com"),
        new(8,"0.014205","192.168.0.1","Broadcast","ARP",64,"Who has 192.168.0.12?")
    ];
    public MainWindow() { InitializeComponent(); Refresh(); }
    private void Refresh()
    {
        if(PacketGrid is null) return;
        var query = SearchBox.Text.Trim();
        var visible = packets.Where(p => $"{p.Source} {p.Destination} {p.Protocol} {p.Info}".Contains(query,StringComparison.OrdinalIgnoreCase)).ToList();
        PacketGrid.ItemsSource = visible;
        CountText.Text = $"{visible.Count} / {packets.Count} packets";
        PacketGrid.SelectedIndex = visible.Count > 0 ? 0 : -1;
        if(visible.Count == 0) { DetailText.Text="검색 결과가 없습니다."; HexText.Text="—"; }
    }
    private void SearchChanged(object sender, TextChangedEventArgs e) => Refresh();
    private void ResetClick(object sender, RoutedEventArgs e) { SearchBox.Clear(); Refresh(); StatusText.Text="샘플 데이터 다시 불러옴 · 실제 수집 아님"; }
    private void SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if(PacketGrid.SelectedItem is not PacketRow p || DetailText is null) return;
        DetailText.Text=$"Frame #{p.Number} · {p.Length} bytes\n{p.Source} → {p.Destination}\n{p.Protocol}   ·   {p.Info}\n목록·상세는 디자인 검토용 예시입니다.";
        HexText.Text="0000  00 11 22 33 44 55 66 77 88 99 aa bb 08 00\n000e  45 00 00 20 00 00 00 00 40 11 00 00 c0 00\n001c  02 01 c6 33 64 02 30 39 00 35 00 0c 00 00\n002a  54 45 53 54                              TEST";
    }
    private void SaveClick(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Filter="PCAP files (*.pcap)|*.pcap", FileName="lanscope-synthetic-udp.pcap" };
        if(dialog.ShowDialog()!=true) return;
        try {
            using var writer = new BinaryWriter(File.Create(dialog.FileName));
            var frame = Convert.FromHexString("00112233445566778899AABB0800450000200000000040110000C0000201C633640230390035000C000054455354");
            writer.Write(0xa1b2c3d4u); writer.Write((ushort)2); writer.Write((ushort)4);
            writer.Write(0); writer.Write(0u); writer.Write(65535u); writer.Write(1u);
            writer.Write(1700000000u); writer.Write(123456u); writer.Write((uint)frame.Length); writer.Write((uint)frame.Length); writer.Write(frame);
            StatusText.Text="별도 합성 UDP 프레임 1개 저장 완료 · 목록 8개를 내보낸 파일이 아닙니다.";
        } catch(Exception ex) when(ex is IOException or UnauthorizedAccessException) { MessageBox.Show(this,ex.Message,"파일 저장 실패",MessageBoxButton.OK,MessageBoxImage.Error); }
    }
}
