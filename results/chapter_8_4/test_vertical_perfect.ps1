$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$src = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Section_8_4_Analysis.xlsx"
$exportDir = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\excel_exports"
$wb = $excel.Workbooks.Open($src)

$sh = $wb.Sheets.Item("Accuracy Graph")
$chartObj = $sh.ChartObjects(1)
$chart = $chartObj.Chart

# Clean existing shapes
while ($chart.Shapes.Count -gt 0) { $chart.Shapes.Item(1).Delete() }

# Let's inspect initial layout
Write-Host "Initial PlotArea InsideLeft:" $chart.PlotArea.InsideLeft "Width:" $chart.PlotArea.InsideWidth
Write-Host "Initial AxisTitle Left:" $chart.Axes(2).AxisTitle.Left "Top:" $chart.Axes(2).AxisTitle.Top

# Slightly widen chart object by 25 points so plot area has plenty of width
$chartObj.Width = 605

# Shift InsideLeft to 82 to create space on the left for both Y-axis title and Scale annotation
$chart.PlotArea.InsideLeft = 82
$chart.PlotArea.InsideWidth = 495

# Position Y-axis title
$chart.Axes(2).AxisTitle.Left = 28

# Add vertical scale textbox at Left = 8, Top = 80, Width = 18, Height = 200
# msoTextOrientationUpward = 2 (rotates 90 degrees counter-clockwise)
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

$chart.Export("$exportDir\test_vertical_perfect.png", "PNG")
Write-Host "Exported test_vertical_perfect.png"

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
