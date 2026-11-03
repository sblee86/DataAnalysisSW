using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using Microsoft.Win32;
namespace LanScope;
public sealed class HeaderMatchSettingsWindow : Window
{
    private sealed class RuleRow {public bool Enabled {get;set;}public string Message {get;set;}="";public string Id {get;set;}="";public int Bytes {get;set;}}
    public CapturePolicy? Result {get;private set;}
    public HeaderMatchSettingsWindow(IcdSchema schema,CapturePolicy? existing)
    {
        Title="공통헤더 · 메시지 식별 규칙";Width=900;Height=850;MinWidth=750;MinHeight=600;Background=new SolidColorBrush(Color.FromRgb(243,246,250));FontSize=13;
        var panel=new StackPanel{Margin=new Thickness(24)};Content=new ScrollViewer{Content=panel,VerticalScrollBarVisibility=ScrollBarVisibility.Auto};
        panel.Children.Add(new TextBlock{Text="IP → ID → Length → ICD 크기가 모두 일치하는 패킷만 기록",FontSize=20,FontWeight=FontWeights.SemiBold,TextWrapping=TextWrapping.Wrap});
        panel.Children.Add(new TextBlock{Text="ID와 Length는 직접 선택합니다. 현재 완전한 UDP 데이터그램만 지원하며 TCP 재조립은 하지 않습니다. 체크섬은 없음 모드입니다.",TextWrapping=TextWrapping.Wrap,Foreground=Brushes.SlateGray,Margin=new Thickness(0,12,0,18)});
        void Label(string text)=>panel.Children.Add(new TextBlock{Text=text,FontWeight=FontWeights.SemiBold,Margin=new Thickness(0,18,0,9)});
        var sourceMode=new ComboBox{ItemsSource=new[]{"현재 ICD에서 헤더 필드 선택","별도 헤더 CSV / C++ 구조체 선택"},SelectedIndex=existing?.SeparateHeader==true?1:0,Padding=new Thickness(10)};Label("1. 헤더 원본");panel.Children.Add(sourceMode);
        var sourceMessage=new ComboBox{Padding=new Thickness(10),Margin=new Thickness(0,10,0,10)};panel.Children.Add(sourceMessage);
        var choose=new Button{Content="별도 헤더 파일 선택 (.csv / .h / .hpp)",Padding=new Thickness(12),ToolTip="CSV 헤더 메시지 또는 C/C++ 헤더 구조체를 선택합니다. includes를 실행하지 않으며 필요한 헤더를 모두 선택하세요."};panel.Children.Add(choose);
        var sourceLabel=new TextBlock{TextWrapping=TextWrapping.Wrap,Foreground=Brushes.SlateGray,Margin=new Thickness(0,8,0,0)};panel.Children.Add(sourceLabel);
        var endian=new ComboBox{ItemsSource=new[]{"be","le"},SelectedItem=existing?.ExternalEndian??"be",Width=90};var pack=new ComboBox{ItemsSource=new[]{1,2,4,8},SelectedItem=existing?.ExternalPack??1,Width=70};var bits=new ComboBox{ItemsSource=new[]{"lsb0","msb0"},SelectedItem=existing?.ExternalBitOrder??"lsb0",Width=90};var options=new WrapPanel{Margin=new Thickness(0,12,0,12)};options.Children.Add(new TextBlock{Text="별도 C++: endian / pack / bit order  ",VerticalAlignment=VerticalAlignment.Center});options.Children.Add(endian);options.Children.Add(pack);options.Children.Add(bits);panel.Children.Add(options);
        var external=new Dictionary<string,StructLayoutInfo>();var sources=existing?.HeaderSources.Select(s=>new StructSource(s.Name,[..s.Content])).ToList()??[];
        ComboBox idBox=new ComboBox{DisplayMemberPath="Name",Padding=new Thickness(10)},lengthBox=new ComboBox{DisplayMemberPath="Name",Padding=new Thickness(10)};
        Label("2. header.ID 필드 (raw integer)");panel.Children.Add(idBox);Label("header.Length 필드 (raw integer)");panel.Children.Add(lengthBox);
        Label("헤더 전체 크기 (bytes) / 별도 C++ 구조체는 자동 계산");var headerBytes=new TextBox{Text=(existing?.HeaderBytes??0).ToString(),Padding=new Thickness(10)};panel.Children.Add(headerBytes);
        var includes=new CheckBox{Content="대상 ICD 안에 공통헤더가 포함됨 (해제하면 ICD는 본문만)",IsChecked=existing?.IcdIncludesHeader??true,Margin=new Thickness(0,18,0,8)};panel.Children.Add(includes);
        var lengthIncludes=new CheckBox{Content="header.Length 값이 공통헤더를 포함한 전체 UDP payload 크기",IsChecked=existing?.LengthIncludesHeader??true,Margin=new Thickness(0,8,0,8)};panel.Children.Add(lengthIncludes);
        panel.Children.Add(new TextBlock{Text="해제하면 Length + 헤더 크기 = 실제 UDP payload 크기를 검사합니다. ICD에 헤더가 포함된 경우 선택한 헤더 필드의 위치·타입·길이·엔디언이 모든 대상 메시지에 포함되어야 합니다.",TextWrapping=TextWrapping.Wrap,Foreground=Brushes.SlateGray});
        Label("3. 메시지 ID ↔ ICD 메시지명 (10진수 또는 0x HEX)");var rows=schema.Messages.Select(m=>new RuleRow{Message=m,Bytes=schema.RequiredBytes(m),Enabled=existing?.Messages.Any(r=>r.Message==m)??false,Id=existing?.Messages.FirstOrDefault(r=>r.Message==m)?.Id??""}).ToList();
        var grid=new DataGrid{ItemsSource=rows,AutoGenerateColumns=false,CanUserAddRows=false,MinHeight=130,MaxHeight=240,Margin=new Thickness(0,0,0,12)};
        grid.Columns.Add(new DataGridCheckBoxColumn{Header="사용",Binding=new Binding("Enabled")});grid.Columns.Add(new DataGridTextColumn{Header="ICD 메시지",Binding=new Binding("Message"),IsReadOnly=true,Width=new DataGridLength(1,DataGridLengthUnitType.Star)});grid.Columns.Add(new DataGridTextColumn{Header="기대 ID",Binding=new Binding("Id"),Width=160});grid.Columns.Add(new DataGridTextColumn{Header="ICD bytes",Binding=new Binding("Bytes"),IsReadOnly=true,Width=110});panel.Children.Add(grid);
        var status=new TextBlock{TextWrapping=TextWrapping.Wrap,Foreground=Brushes.DarkRed,Margin=new Thickness(0,10,0,12)};panel.Children.Add(status);
        var save=new Button{Content="헤더 포함 여부·크기 검사 후 적용",Padding=new Thickness(14),ToolTip="헤더 필드와 대상 ICD를 대조하고 ID 중복·길이·엔디언을 검증합니다. 프로파일 저장을 눌러야 암호화 저장소에 반영됩니다."};panel.Children.Add(save);
        void LoadExternal(){external.Clear();if(sources.Count==0)return;if(sources.Count==1&&sources[0].Name.EndsWith(".csv",StringComparison.OrdinalIgnoreCase)){var hs=IcdCsv.Parse(sources[0].Content);foreach(var m in hs.Messages)external[m]=new(m,hs.RequiredBytes(m),1,hs.Fields.Where(f=>f.Message==m).ToArray());}else foreach(var pair in CStructParser.Parse(sources,(int)pack.SelectedItem,(string)endian.SelectedItem,(string)bits.SelectedItem))external[pair.Key]=pair.Value;}
        IReadOnlyList<IcdField> Fields(){if(sourceMessage.SelectedItem is not string m)return [];return sourceMode.SelectedIndex==1?external.GetValueOrDefault(m)?.Fields??[]:schema.Fields.Where(f=>f.Message==m).ToArray();}
        void UpdateFields(){var fields=Fields().Where(f=>f.Type is "uint" or "int" &&f.Scale==1&&f.Bias==0&&f.BitLength<=64).ToList();idBox.ItemsSource=fields;lengthBox.ItemsSource=fields;idBox.SelectedItem=fields.FirstOrDefault(f=>existing?.IdField?.Name==f.Name);lengthBox.SelectedItem=fields.FirstOrDefault(f=>existing?.LengthField?.Name==f.Name);if(sourceMode.SelectedIndex==1&&sourceMessage.SelectedItem is string m&&external.TryGetValue(m,out var layout))headerBytes.Text=layout.Size.ToString();}
        void UpdateSource(){headerBytes.IsReadOnly=sourceMode.SelectedIndex==1;options.IsEnabled=sourceMode.SelectedIndex==1;choose.IsEnabled=sourceMode.SelectedIndex==1;sourceLabel.Text=sourceMode.SelectedIndex==1?string.Join(", ",sources.Select(s=>s.Name)):"현재 ICD의 메시지에서 ID·Length를 선택하세요.";sourceMessage.ItemsSource=sourceMode.SelectedIndex==1?external.Keys.ToArray():schema.Messages;sourceMessage.SelectedItem=existing?.HeaderName;if(sourceMessage.SelectedItem==null)sourceMessage.SelectedIndex=0;UpdateFields();}
        choose.Click+=(_,_)=>{var d=new OpenFileDialog{Filter="헤더 CSV/C++|*.csv;*.h;*.hpp",Multiselect=true};if(d.ShowDialog(this)!=true)return;try{if(d.FileNames.Length>128||d.FileNames.Sum(f=>new FileInfo(f).Length)>16*1024*1024)throw new ArgumentException("헤더 합계 최대 16 MB / 128개입니다.");sources=d.FileNames.Select(f=>new StructSource(Path.GetFileName(f),File.ReadAllBytes(f))).ToList();LoadExternal();UpdateSource();}catch(Exception e){status.Text=e.Message;}};
        foreach(var box in new[]{endian,pack,bits})box.SelectionChanged+=(_,_)=>{try{LoadExternal();UpdateSource();}catch(Exception e){status.Text=e.Message;}};
        sourceMode.SelectionChanged+=(_,_)=>UpdateSource();sourceMessage.SelectionChanged+=(_,_)=>UpdateFields();
        save.Click+=(_,_)=>{try{grid.CommitEdit(DataGridEditingUnit.Cell,true);grid.CommitEdit(DataGridEditingUnit.Row,true);if(idBox.SelectedItem is not IcdField id||lengthBox.SelectedItem is not IcdField length)throw new ArgumentException("ID와 Length 필드를 각각 선택하세요.");var policy=new CapturePolicy{IdField=id,LengthField=length,HeaderName=sourceMessage.SelectedItem as string??"",SeparateHeader=sourceMode.SelectedIndex==1,HeaderSources=sourceMode.SelectedIndex==1?sources:[],IcdIncludesHeader=includes.IsChecked==true,LengthIncludesHeader=lengthIncludes.IsChecked==true,HeaderBytes=int.Parse(headerBytes.Text),ExternalPack=(int)pack.SelectedItem,ExternalEndian=(string)endian.SelectedItem,ExternalBitOrder=(string)bits.SelectedItem,HeaderFields=sourceMode.SelectedIndex==1?Fields().Select(f=>f with{Description="",Unit="",SourceLine=0}).ToList():[id,length],Messages=rows.Where(r=>r.Enabled).Select(r=>new CaptureMessageRule(r.Message,r.Id)).ToList()};policy.Prepare(schema);Result=policy;DialogResult=true;}catch(Exception e){status.Text=e.Message;}};
        try{LoadExternal();UpdateSource();}catch(Exception e){status.Text=e.Message;}
    }
}
