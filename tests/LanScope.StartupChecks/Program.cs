using System.Windows;
using System.Windows.Controls;
using LanScope;
internal static class Program
{
    [STAThread]
    private static int Main()
    {
        var app=new App{ShutdownMode=ShutdownMode.OnExplicitShutdown};
        try {
            app.InitializeComponent();var window=new MainWindow();
            foreach(string name in new[]{"DecodeGrid","MessageBoxSelect","WriteFieldBox","ByteOrderBox","StructPackBox","StructBitBox"})
                if(window.FindName(name)==null)throw new Exception("Control not constructed: "+name);
            // This path crashed before construction completed; it must also work once controls are ready.
            foreach(string name in new[]{"ByteOrderBox","StructPackBox","StructBitBox"}){
                var box=(ComboBox)window.FindName(name);box.SelectedIndex=1;box.SelectedIndex=0;
            }
            if(((DataGrid)window.FindName("DecodeGrid")).Items.Count!=0)throw new Exception("Empty ICD should have no decoded rows.");
            var id=new IcdField("TargetTrack","code",0,0,16,"uint","be","msb0",1,0,"","",0);var length=id with{Name="wireBytes",ByteOffset=2};
            var policy=new CapturePolicy{MatchByStructure=true,RequireHeaderLayout=true,SeparateHeader=true,HeaderName="TargetTrack",HeaderBytes=4,IdField=id,LengthField=length,HeaderFields=[id,length],HeaderSources=[new StructSource("target.h",System.Text.Encoding.UTF8.GetBytes("struct Entry { float x; }; struct TargetTrack { uint16_t code; uint16_t wireBytes; Entry entries[2]; };"))]};
            var headerWindow=new HeaderMatchSettingsWindow(new IcdSchema(),policy);
            var headerSize=Descendants<TextBox>(headerWindow).Single();if(headerSize.Text!="4")throw new Exception("Reopening header replaced saved prefix size with whole message size.");
            var bitOrder=Descendants<ComboBox>(headerWindow).Single(b=>b.Items.Contains("lsb0")&&b.Items.Contains("msb0"));bitOrder.SelectedItem="msb0";
            if(headerSize.Text!="4"||!Descendants<ComboBox>(headerWindow).Any(b=>Equals(b.SelectedItem,"TargetTrack")))throw new Exception("Changing header options lost type selection or prefix size.");
            var selectedRoles=Descendants<ComboBox>(headerWindow).Select(b=>b.SelectedItem).OfType<IcdField>().Select(f=>f.Name).ToHashSet();if(!selectedRoles.Contains("code")||!selectedRoles.Contains("wireBytes"))throw new Exception("Changing options lost user-selected nonstandard ID/Length names.");headerWindow.Close();
            window.Close();Console.WriteLine("PASS: WPF startup and default/changed ICD selections; all HEX controls constructed; saved header prefix/type/roles survive option changes.");return 0;
        }catch(Exception e){Console.Error.WriteLine(e);return 1;}
        finally{app.Shutdown();}
    }
    private static IEnumerable<T> Descendants<T>(DependencyObject root) where T:DependencyObject
    {
        foreach(var child in LogicalTreeHelper.GetChildren(root).OfType<DependencyObject>()){if(child is T found)yield return found;foreach(var nested in Descendants<T>(child))yield return nested;}
    }

}
