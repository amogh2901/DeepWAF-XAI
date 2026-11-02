$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$src = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Section_8_4_Analysis.xlsx"
$exportDir = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\excel_exports"
$wb = $excel.Workbooks.Open($src)

$graphConfigs = @(
    @{ SheetName = "Accuracy Graph"; OutFile = "Figure_8_4_1_Accuracy_Comparison_With_Scale.png" },
    @{ SheetName = "Precision Graph"; OutFile = "Figure_8_4_2_Precision_Comparison_With_Scale.png" },
    @{ SheetName = "Recall Graph"; OutFile = "Figure_8_4_3_Recall_Comparison_With_Scale.png" },
    @{ SheetName = "F1-Score Graph"; OutFile = "Figure_8_4_4_F1-Score_Comparison_With_Scale.png" }
)

foreach ($cfg in $graphConfigs) {
    $sh = $wb.Sheets.Item($cfg.SheetName)
    $chart = $sh.ChartObjects(1).Chart
    
    while ($chart.Shapes.Count -gt 0) { $chart.Shapes.Item(1).Delete() }
    
    # Select plot area and position it
    $chart.PlotArea.Select() | Out-Null
    $excel.Selection.Left = 60
    $excel.Selection.Width = 495
    
    # Position Y-axis title
    $chart.Axes(2).AxisTitle.Left = 28
    
    # Add vertical scale textbox at Left = 8, Top = 80, Width = 18, Height = 200
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
    
    $chart.Export("$exportDir\$($cfg.OutFile)", "PNG")
    Write-Host "Exported $($cfg.OutFile)"
}

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
