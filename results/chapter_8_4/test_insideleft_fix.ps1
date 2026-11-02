$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$src = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Section_8_4_Analysis.xlsx"
$exportDir = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\excel_exports"
$wb = $excel.Workbooks.Open($src)

$sh = $wb.Sheets.Item("Accuracy Graph")
$chartObj = $sh.ChartObjects(1)
$chart = $chartObj.Chart
while ($chart.Shapes.Count -gt 0) { $chart.Shapes.Item(1).Delete() }

Write-Host "Before: PlotArea.Width:" $chart.PlotArea.Width "InsideWidth:" $chart.PlotArea.InsideWidth "InsideLeft:" $chart.PlotArea.InsideLeft

# 1. First reduce InsideWidth so InsideLeft has headroom
$chart.PlotArea.InsideWidth = 460
# 2. Now increase InsideLeft
$chart.PlotArea.InsideLeft = 80
# 3. Position AxisTitle comfortably between Scale and Numbers
$chart.Axes(2).AxisTitle.Left = 32

Write-Host "After: InsideWidth:" $chart.PlotArea.InsideWidth "InsideLeft:" $chart.PlotArea.InsideLeft "AxisTitle.Left:" $chart.Axes(2).AxisTitle.Left

# 4. Add vertical scale textbox at Left = 8
$tb = $chart.Shapes.AddTextbox(2, 8, 80, 18, 200)
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

$chart.Export("$exportDir\test_insideleft_success.png", "PNG")
Write-Host "Exported test_insideleft_success.png"

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
