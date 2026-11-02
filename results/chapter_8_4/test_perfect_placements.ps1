$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$src = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Section_8_4_Analysis.xlsx"
$exportDir = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\excel_exports"
$wb = $excel.Workbooks.Open($src)

# -------------------------------------------------------------------------
# Test A: Top-left horizontal badge above Y-axis (Left = 14, Top = 8)
# -------------------------------------------------------------------------
$sh1 = $wb.Sheets.Item("Accuracy Graph")
$chart1 = $sh1.ChartObjects(1).Chart
# Remove existing added shapes
while ($chart1.Shapes.Count -gt 0) { $chart1.Shapes.Item(1).Delete() }

$tbA = $chart1.Shapes.AddTextbox(1, 14, 8, 180, 16)
$tbA.TextFrame2.TextRange.Text = "Scale: Percentage Metric (0% - 100%)"
$tbA.TextFrame2.TextRange.Font.Name = "Segoe UI"
$tbA.TextFrame2.TextRange.Font.Size = 8.5
$tbA.TextFrame2.TextRange.Font.Bold = $true
$tbA.TextFrame2.TextRange.Font.Fill.ForeColor.RGB = 51 + (65 * 256) + (85 * 65536) # Slate #334155
$tbA.Line.Visible = $false
$tbA.Fill.Visible = $false

$chart1.Export("$exportDir\test_pos_topleft.png", "PNG")
Write-Host "Exported test_pos_topleft.png"

# -------------------------------------------------------------------------
# Test B: Vertical on left with PlotArea repositioned via InsideLeft
# -------------------------------------------------------------------------
$sh2 = $wb.Sheets.Item("Precision Graph")
$chart2 = $sh2.ChartObjects(1).Chart
while ($chart2.Shapes.Count -gt 0) { $chart2.Shapes.Item(1).Delete() }

# Let's see if InsideLeft can be adjusted
try {
    $chart2.PlotArea.InsideLeft = 45
    Write-Host "InsideLeft set successfully to 45"
} catch {
    Write-Host "InsideLeft failed: $_"
}

$tbB = $chart2.Shapes.AddTextbox(2, 6, 80, 20, 190)
$tbB.TextFrame2.TextRange.Text = "Scale: Percentage Metric (0% - 100%)"
$tbB.TextFrame2.TextRange.Font.Name = "Segoe UI"
$tbB.TextFrame2.TextRange.Font.Size = 8.5
$tbB.TextFrame2.TextRange.Font.Bold = $true
$tbB.TextFrame2.TextRange.Font.Fill.ForeColor.RGB = 51 + (65 * 256) + (85 * 65536)
$tbB.Line.Visible = $false
$tbB.Fill.Visible = $false

$chart2.Export("$exportDir\test_pos_vertical.png", "PNG")
Write-Host "Exported test_pos_vertical.png"

# -------------------------------------------------------------------------
# Test C: Bottom Left below X-Axis, beside legend
# -------------------------------------------------------------------------
$sh3 = $wb.Sheets.Item("Recall Graph")
$chart3 = $sh3.ChartObjects(1).Chart
while ($chart3.Shapes.Count -gt 0) { $chart3.Shapes.Item(1).Delete() }

# Place legend slightly shifted or place scale at bottom left
$tbC = $chart3.Shapes.AddTextbox(1, 14, 326, 185, 16)
$tbC.TextFrame2.TextRange.Text = "Scale: Percentage Metric (0% - 100%)"
$tbC.TextFrame2.TextRange.Font.Name = "Segoe UI"
$tbC.TextFrame2.TextRange.Font.Size = 8.5
$tbC.TextFrame2.TextRange.Font.Bold = $true
$tbC.TextFrame2.TextRange.Font.Fill.ForeColor.RGB = 51 + (65 * 256) + (85 * 65536)
$tbC.Line.Visible = $false
$tbC.Fill.Visible = $false

$chart3.Export("$exportDir\test_pos_bottomleft.png", "PNG")
Write-Host "Exported test_pos_bottomleft.png"

# -------------------------------------------------------------------------
# Test D: Top Left Styled Badge with subtle background / border
# -------------------------------------------------------------------------
$sh4 = $wb.Sheets.Item("F1-Score Graph")
$chart4 = $sh4.ChartObjects(1).Chart
while ($chart4.Shapes.Count -gt 0) { $chart4.Shapes.Item(1).Delete() }

$tbD = $chart4.Shapes.AddTextbox(1, 14, 8, 185, 18)
$tbD.TextFrame2.TextRange.Text = "Scale: Percentage Metric (0% - 100%)"
$tbD.TextFrame2.TextRange.Font.Name = "Segoe UI"
$tbD.TextFrame2.TextRange.Font.Size = 8.5
$tbD.TextFrame2.TextRange.Font.Bold = $true
$tbD.TextFrame2.TextRange.Font.Fill.ForeColor.RGB = 51 + (65 * 256) + (85 * 65536)
# Subtle light gray fill and border
$tbD.Fill.Solid()
$tbD.Fill.ForeColor.RGB = 241 + (245 * 256) + (249 * 65536) # #F1F5F9
$tbD.Line.Visible = $true
$tbD.Line.ForeColor.RGB = 203 + (213 * 256) + (225 * 65536) # #CBD5E1
$tbD.Line.Weight = 0.75

$chart4.Export("$exportDir\test_pos_badge.png", "PNG")
Write-Host "Exported test_pos_badge.png"

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
