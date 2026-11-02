$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$src = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Section_8_4_Analysis.xlsx"
$exportDir = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\excel_exports"
$wb = $excel.Workbooks.Open($src)

# -------------------------------------------------------------
# Test 1: Vertical scale label on the left margin (like reference image)
# -------------------------------------------------------------
$sh1 = $wb.Sheets.Item("Accuracy Graph")
$chart1 = $sh1.ChartObjects(1).Chart

# Adjust PlotArea slightly to make room on the left
$chart1.PlotArea.Left = 52
$chart1.PlotArea.Width = 512

# Add vertical textbox on far left
# msoTextOrientationUpward = 2 (rotates 90 deg counter-clockwise)
$tb1 = $chart1.Shapes.AddTextbox(2, 6, 60, 24, 210)
$tb1.TextFrame2.TextRange.Text = 'Scale: Percentage Metric (0% - 100%)'
$tb1.TextFrame2.TextRange.Font.Name = 'Segoe UI'
$tb1.TextFrame2.TextRange.Font.Size = 9.5
$tb1.TextFrame2.TextRange.Font.Bold = $true
$tb1.TextFrame2.TextRange.Font.Fill.ForeColor.RGB = 51 + (65 * 256) + (85 * 65536) # Slate
$tb1.Line.Visible = $false
$tb1.Fill.Visible = $false

$chart1.Export("$exportDir\test_scale_vertical.png", "PNG")
Write-Host "Exported test_scale_vertical.png"

# -------------------------------------------------------------
# Test 2: Horizontal scale label near top-left of Y-axis
# -------------------------------------------------------------
$sh2 = $wb.Sheets.Item("Precision Graph")
$chart2 = $sh2.ChartObjects(1).Chart

# Add horizontal textbox near top-left of Y-axis
$tb2 = $chart2.Shapes.AddTextbox(1, 35, 8, 260, 20)
$tb2.TextFrame2.TextRange.Text = 'Scale: Percentage Metric (0% - 100%)'
$tb2.TextFrame2.TextRange.Font.Name = 'Segoe UI'
$tb2.TextFrame2.TextRange.Font.Size = 9
$tb2.TextFrame2.TextRange.Font.Bold = $true
$tb2.TextFrame2.TextRange.Font.Fill.ForeColor.RGB = 51 + (65 * 256) + (85 * 65536)
$tb2.Line.Visible = $false
$tb2.Fill.Visible = $false

$chart2.Export("$exportDir\test_scale_near_yaxis.png", "PNG")
Write-Host "Exported test_scale_near_yaxis.png"

# -------------------------------------------------------------
# Test 3: Horizontal scale label below chart legend
# -------------------------------------------------------------
$sh3 = $wb.Sheets.Item("Recall Graph")
$chart3 = $sh3.ChartObjects(1).Chart

# Add horizontal textbox at the bottom right/center
$tb3 = $chart3.Shapes.AddTextbox(1, 160, 325, 260, 18)
$tb3.TextFrame2.TextRange.Text = 'Scale: Percentage Metric (0% - 100%)'
$tb3.TextFrame2.TextRange.Font.Name = 'Segoe UI'
$tb3.TextFrame2.TextRange.Font.Size = 9
$tb3.TextFrame2.TextRange.Font.Bold = $true
$tb3.TextFrame2.TextRange.Font.Fill.ForeColor.RGB = 51 + (65 * 256) + (85 * 65536)
$tb3.Line.Visible = $false
$tb3.Fill.Visible = $false

$chart3.Export("$exportDir\test_scale_below_chart.png", "PNG")
Write-Host "Exported test_scale_below_chart.png"

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
