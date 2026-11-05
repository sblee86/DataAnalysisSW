"""Cross-platform check for the BAML construction-order startup regression.
The actual WPF runtime probe is tests/LanScope.StartupChecks (Windows only).
"""
from pathlib import Path
import xml.etree.ElementTree as E
root=Path(__file__).resolve().parents[1]
xaml=E.parse(root/'src/LanScope/MainWindow.xaml').getroot()
code=(root/'src/LanScope/MainWindow.xaml.cs').read_text()
xname='{http://schemas.microsoft.com/winfx/2006/xaml}Name'
expected={'ConversionProfileBox':'ConversionProfileSelected','ProfilesList':'ProfileSelected','ByteOrderBox':'IcdOptionChanged','StructPackBox':'IcdOptionChanged','StructBitBox':'IcdOptionChanged','MessageBoxSelect':'WriteMessageSelected','NicGrid':'NicSelected','CurrentMessageBox':'CurrentMessageChanged','RangeFieldBox':'RangeFieldChanged'}
constructor=code.split('public MainWindow()',1)[1].split('private readonly UiPreferences',1)[0]
for node in xaml.iter():
    assert 'SelectionChanged' not in node.attrib, f'Construction-time handler: {node.get(xname)}'
for control,handler in expected.items():
    statement=f'{control}.SelectionChanged+={handler};'
    assert constructor.count(statement)==1, f'Handler missing or duplicated: {statement}'
    assert constructor.index('InitializeComponent();')<constructor.index(statement)<constructor.index('ApplyUiLayout(')
assert 'DecodeGrid.ItemsSource=null' in code, 'Preview should still clear old decode results after initialization'
print('PASS: nine dependent selection handlers wired once after InitializeComponent, never during BAML construction')
