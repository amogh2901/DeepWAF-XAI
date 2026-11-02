$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$origPath = "D:\Amogh\MCA\DeepWAF-XAI\DeepWAF_XAI_Section_8_4_Analysis.xlsx"
$newResultsPath = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Section_8_4_Graphs_With_Scale.xlsx"
$newRootPath = "D:\Amogh\MCA\DeepWAF-XAI\DeepWAF_XAI_Section_8_4_Graphs_With_Scale.xlsx"
$exportDir = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\excel_exports"

if (!(Test-Path $exportDir)) {
    New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
}

# Open the original workbook read-only so it remains strictly untouched
$wb = $excel.Workbooks.Open($origPath, $false, $true)

$graphConfigs = @(
    @{
        SheetName = "Accuracy Graph"
        Metric = "Accuracy"
        ChartName = "chart_8_4_1_accuracy_with_scale.png"
    },
    @{
        SheetName = "Precision Graph"
        Metric = "Precision"
        ChartName = "chart_8_4_2_precision_with_scale.png"
    },
    @{
        SheetName = "Recall Graph"
        Metric = "Recall"
        ChartName = "chart_8_4_3_recall_with_scale.png"
    },
    @{
        SheetName = "F1-Score Graph"
        Metric = "F1-Score"
        ChartName = "chart_8_4_4_f1_score_with_scale.png"
    }
)

foreach ($cfg in $graphConfigs) {
    $sh = $wb.Sheets.Item($cfg.SheetName)
    Write-Host "Updating sheet: $($cfg.SheetName)"
    
    # 1. Update text note in worksheet
    $sh.Cells.Item(12, 1).Value2 = "Scale Definition & Academic Note:"
    $sh.Cells.Item(12, 1).Font.Name = "Segoe UI"
    $sh.Cells.Item(12, 1).Font.Size = 9.5
    $sh.Cells.Item(12, 1).Font.Bold = $true
    $sh.Cells.Item(12, 1).Font.Color = 51 + (65 * 256) + (85 * 65536) # Slate
    
    $existingNote = [string]($sh.Cells.Item(13, 1).Value2)
    $scalePrefix = "[Scale: Percentage Metric (0.00% - 100.00%, where 100.00% represents optimal detection performance)]. "
    if (!($existingNote.StartsWith("[Scale:"))) {
        $sh.Cells.Item(13, 1).Value2 = $scalePrefix + $existingNote
    }

    # 2. Add native Scale label inside Chart Object near Y-Axis
    $chartObj = $sh.ChartObjects(1)
    $chart = $chartObj.Chart
    
    # Remove any existing custom shapes added previously
    while ($chart.Shapes.Count -gt 0) {
        $chart.Shapes.Item(1).Delete()
    }
    
    # Add small readable text label near the Y-axis
    # Position: Left=14, Top=9, Width=180, Height=18
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
    
    # Export chart image for verification and documentation
    $exportFile = Join-Path $exportDir $cfg.ChartName
    $chart.Export($exportFile, "PNG")
    Write-Host "Exported: $exportFile"
}

# Remove existing new files if present to avoid write lock errors
if (Test-Path $newResultsPath) { Remove-Item $newResultsPath -Force }
if (Test-Path $newRootPath) { Remove-Item $newRootPath -Force }

# Save as new workbook
$wb.SaveAs($newResultsPath)
$wb.SaveCopyAs($newRootPath)
Write-Host "Saved new workbook with scale to:"
Write-Host "  1. $newResultsPath"
Write-Host "  2. $newRootPath"

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
Write-Host "Completed successfully!"
