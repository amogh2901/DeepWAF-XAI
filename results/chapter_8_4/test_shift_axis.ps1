$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$src = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Section_8_4_Analysis.xlsx"
$exportDir = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\excel_exports"
$wb = $excel.Workbooks.Open($src)

$sh = $wb.Sheets.Item("Accuracy Graph")
$chart = $sh.ChartObjects(1).Chart
while ($chart.Shapes.Count -gt 0) { $chart.Shapes.Item(1).Delete() }

Write-Host "Initial AxisTitle Left:" $chart.Axes(2).AxisTitle.Left
Write-Host "Initial PlotArea Left:" $chart.PlotArea.Left "InsideLeft:" $chart.PlotArea.InsideLeft

# Test setting AxisTitle.Left
try {
    $chart.Axes(2).AxisTitle.Left = 24
    Write-Host "Successfully set AxisTitle.Left = 24. New value:" $chart.Axes(2).AxisTitle.Left
} catch {
    Write-Host "Failed to set AxisTitle.Left: $_"
}

# Test setting PlotArea.InsideLeft
try {
    $chart.PlotArea.InsideLeft = 58
    Write-Host "Successfully set PlotArea.InsideLeft = 58. New value:" $chart.PlotArea.InsideLeft
} catch {
    Write-Host "Failed to set PlotArea.InsideLeft: $_"
}

# Add vertical textbox at Left = 6
$tb = $chart.Shapes.AddTextbox(2, 6, 75, 18, 200)
$tb.TextFrame2.TextRange.Text = "Scale: Percentage Metric (0% - 100%)"
$tb.TextFrame2.TextRange.Font.Name = "Segoe UI"
$tb.TextFrame2.TextRange.Font.Size = 8.5
$tb.TextFrame2.TextRange.Font.Bold = $true
$tb.TextFrame2.TextRange.Font.Fill.ForeColor.RGB = 51 + (65 * 256) + (85 * 65536) # Slate
$tb.Line.Visible = $false
$tb.Fill.Visible = $false

$chart.Export("$exportDir\test_vertical_shifted.png", "PNG")
Write-Host "Exported test_vertical_shifted.png"

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
