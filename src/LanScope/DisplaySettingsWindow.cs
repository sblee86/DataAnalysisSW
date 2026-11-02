using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
namespace LanScope;
public sealed class DisplaySettingsWindow : Window
{
    public DisplaySettingsWindow(UiLayoutOptions initial,Action<UiLayoutOptions> changed)
    {
        Title="DRAS · 화면 설정";Width=470;Height=650;MinWidth=370;MinHeight=420;ResizeMode=ResizeMode.CanResizeWithGrip;Background=new SolidColorBrush(Color.FromRgb(243,246,250));FontSize=13;
        var panel=new StackPanel{Margin=new Thickness(24)};Content=new ScrollViewer{Content=panel,VerticalScrollBarVisibility=ScrollBarVisibility.Auto};var value=initial;
        panel.Children.Add(new TextBlock{Text="영역별 글자 크기",FontSize=22,FontWeight=FontWeights.SemiBold});
        var refresh=new List<Action<UiLayoutOptions>>();bool updating=false;
        void Add(string label,int min,int max,Func<UiLayoutOptions,int> get,Func<UiLayoutOptions,int,UiLayoutOptions> set){var text=new TextBlock{Margin=new Thickness(0,18,0,8)};var slider=new Slider{Minimum=min,Maximum=max,Value=get(value),TickFrequency=1,IsSnapToTickEnabled=true};panel.Children.Add(text);panel.Children.Add(slider);text.Text=label+" · "+get(value);slider.ValueChanged+=(_,e)=>{text.Text=label+" · "+(int)e.NewValue;if(!updating){value=set(value,(int)e.NewValue);changed(value);}};refresh.Add(v=>{slider.Value=get(v);text.Text=label+" · "+get(v);});}
        Add("본문",12,20,v=>v.Body,(v,n)=>v with{Body=n});Add("메뉴",12,20,v=>v.Menu,(v,n)=>v with{Menu=n});Add("표 내용",10,20,v=>v.Table,(v,n)=>v with{Table=n});Add("표 제목",11,22,v=>v.TableHeader,(v,n)=>v with{TableHeader=n});Add("화면 제목",20,36,v=>v.Title,(v,n)=>v with{Title=n});
        Add("ICD 목록 너비 (px)",180,500,v=>v.ProfileWidth,(v,n)=>v with{ProfileWidth=n});Add("NIC 목록 비율 (%)",30,75,v=>v.NicPercent,(v,n)=>v with{NicPercent=n});
        var reset=new Button{Content="기본 설정 복원",Margin=new Thickness(0,24,0,0),Padding=new Thickness(12)};panel.Children.Add(reset);reset.Click+=(_,_)=>{value=new();updating=true;foreach(var f in refresh)f(value);updating=false;changed(value);};
    }
}
