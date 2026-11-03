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
            window.Close();Console.WriteLine("PASS: WPF startup and default/changed ICD selections; all HEX controls constructed.");return 0;
        }catch(Exception e){Console.Error.WriteLine(e);return 1;}
        finally{app.Shutdown();}
    }
}
