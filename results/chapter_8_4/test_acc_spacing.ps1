$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$src = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Section_8_4_Analysis.xlsx"
$exportDir = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\excel_exports"
$wb = $excel.Workbooks.Open($src)

$sh = $wb.Sheets.Item("Accuracy Graph")
$chart = $sh.ChartObjects(1).Chart
while ($chart.Shapes.Count -gt 0) { $chart.Shapes.Item(1).Delete() }

$chart.PlotArea.Select() | Out-Null
$excel.Selection.Width = 485
$excel.Selection.Left = 68
$chart.Axes(2).AxisTitle.Left = 18

$tb = $chart.Shapes.AddTextbox(2, 4, 80, 14, 200)
$tb.TextFrame2.MarginLeft = 0
$tb.TextFrame2.MarginRight = 0
$tb.TextFrame2.MarginTop = 0
$tb.TextFrame2.MarginBottom = 0
$tb.TextFrame2.WordWrap = 0 # msoFalse
$tb.TextFrame2.TextRange.Text = "Scale: Percentage Metric (0% - 100%)"
$tb.TextFrame2.TextRange.Font.Name = "Segoe UI"
$tb.TextFrame2.TextRange.Font.Size = 9.0
$tb.TextFrame2.TextRange.Font.Bold = $true
$tb.TextFrame2.TextRange.Font.Fill.ForeColor.RGB = 51 + (65 * 256) + (85 * 65536) # Slate #334155
$tb.Line.Visible = $false
$tb.Fill.Visible = $false

$chart.Export("$exportDir\test_acc_perfect.png", "PNG")
Write-Host "Exported test_acc_perfect.png"

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
