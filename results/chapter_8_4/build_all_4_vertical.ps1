$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$src = "D:\Amogh\MCA\DeepWAF-XAI\DeepWAF_XAI_Section_8_4_Analysis.xlsx"
$newResultsPath = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Graphs_With_Scale.xlsx"
$newRootPath = "D:\Amogh\MCA\DeepWAF-XAI\DeepWAF_XAI_Graphs_With_Scale.xlsx"
$exportDir = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\excel_exports"

if (!(Test-Path $exportDir)) {
    New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
}

# Open the original workbook read-only so it remains strictly untouched
$wb = $excel.Workbooks.Open($src, $false, $true)

$graphConfigs = @(
    @{
        SheetName = "Accuracy Graph"
        Metric = "Accuracy"
        OutFile = "graph_8_4_1_accuracy_vertical_scale.png"
    },
    @{
        SheetName = "Precision Graph"
        Metric = "Precision"
        OutFile = "graph_8_4_2_precision_vertical_scale.png"
    },
    @{
        SheetName = "Recall Graph"
        Metric = "Recall"
        OutFile = "graph_8_4_3_recall_vertical_scale.png"
    },
    @{
        SheetName = "F1-Score Graph"
        Metric = "F1-Score"
        OutFile = "graph_8_4_4_f1_score_vertical_scale.png"
    }
)

foreach ($cfg in $graphConfigs) {
    $sh = $wb.Sheets.Item($cfg.SheetName)
    Write-Host "Configuring vertical scale for: $($cfg.SheetName)"
    
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

    # 2. Add native vertical Scale label inside Chart Object beside Y-Axis
    $chartObj = $sh.ChartObjects(1)
    $chart = $chartObj.Chart
    
    # Remove any existing shapes
    while ($chart.Shapes.Count -gt 0) {
        $chart.Shapes.Item(1).Delete()
    }
    
    # Slightly widen chart object to ensure comfortable margins on both sides
    $chartObj.Width = 605
    
    # Position PlotArea InsideLeft to make space for both Y-axis title and Scale annotation
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
    
    # Export chart image for verification
    $exportFile = Join-Path $exportDir $cfg.OutFile
    $chart.Export($exportFile, "PNG")
    Write-Host "Exported: $exportFile"
}

# Remove existing new files if present to avoid write lock errors
if (Test-Path $newResultsPath) { Remove-Item $newResultsPath -Force }
if (Test-Path $newRootPath) { Remove-Item $newRootPath -Force }

# Save as new workbook: DeepWAF_XAI_Graphs_With_Scale.xlsx
$wb.SaveAs($newResultsPath)
$wb.SaveCopyAs($newRootPath)
Write-Host "Saved final workbook to:"
Write-Host "  1. $newResultsPath"
Write-Host "  2. $newRootPath"

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
Write-Host "Completed successfully!"
