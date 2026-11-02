$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$src = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Section_8_4_Analysis.xlsx"
$exportDir = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\excel_exports"
$wb = $excel.Workbooks.Open($src)

$graphConfigs = @(
    @{ SheetName = "Accuracy Graph"; OutFile = "final_preview_accuracy.png" },
    @{ SheetName = "Precision Graph"; OutFile = "final_preview_precision.png" },
    @{ SheetName = "Recall Graph"; OutFile = "final_preview_recall.png" },
    @{ SheetName = "F1-Score Graph"; OutFile = "final_preview_f1.png" }
)

foreach ($cfg in $graphConfigs) {
    $sh = $wb.Sheets.Item($cfg.SheetName)
    $chart = $sh.ChartObjects(1).Chart
    
    # Clean previous shapes
    while ($chart.Shapes.Count -gt 0) { $chart.Shapes.Item(1).Delete() }
    
    # Add small readable text label near the Y-axis
    $tb = $chart.Shapes.AddTextbox(1, 14, 9, 180, 18)
    $tb.TextFrame2.MarginLeft = 0
    $tb.TextFrame2.MarginRight = 0
    $tb.TextFrame2.MarginTop = 0
    $tb.TextFrame2.MarginBottom = 0
    $tb.TextFrame2.WordWrap = 0 # msoFalse
    $tb.TextFrame2.TextRange.Text = "Scale: Percentage Metric (0% - 100%)"
    $tb.TextFrame2.TextRange.Font.Name = "Segoe UI"
    $tb.TextFrame2.TextRange.Font.Size = 8.5
    $tb.TextFrame2.TextRange.Font.Bold = $true
    $tb.TextFrame2.TextRange.Font.Fill.ForeColor.RGB = 51 + (65 * 256) + (85 * 65536) # #334155 Slate
    $tb.Line.Visible = $false
    $tb.Fill.Visible = $false
    
    $chart.Export("$exportDir\$($cfg.OutFile)", "PNG")
    Write-Host "Exported $($cfg.OutFile)"
}

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
