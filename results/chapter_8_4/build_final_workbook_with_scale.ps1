$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$origPath = "D:\Amogh\MCA\DeepWAF-XAI\DeepWAF_XAI_Section_8_4_Analysis.xlsx"
$targetWorkbookRoot = "D:\Amogh\MCA\DeepWAF-XAI\DeepWAF_XAI_Graphs_With_Scale.xlsx"
$targetWorkbookResults = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Graphs_With_Scale.xlsx"
$targetAliasRoot = "D:\Amogh\MCA\DeepWAF-XAI\DeepWAF_XAI_Section_8_4_Graphs_With_Scale.xlsx"
$targetAliasResults = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Section_8_4_Graphs_With_Scale.xlsx"

$exportDir = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\excel_exports"
$resultsDir = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4"

if (!(Test-Path $exportDir)) {
    New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
}

Write-Host "Opening original workbook in read-only mode..."
$wb = $excel.Workbooks.Open($origPath, $false, $true)

$graphConfigs = @(
    @{
        SheetName = "Accuracy Graph"
        Metric = "Accuracy"
        ExportBaseName = "Figure_8_4_1_Accuracy_Comparison_With_Scale"
        ShortName = "graph_8_4_1_accuracy_with_scale"
    },
    @{
        SheetName = "Precision Graph"
        Metric = "Precision"
        ExportBaseName = "Figure_8_4_2_Precision_Comparison_With_Scale"
        ShortName = "graph_8_4_2_precision_with_scale"
    },
    @{
        SheetName = "Recall Graph"
        Metric = "Recall"
        ExportBaseName = "Figure_8_4_3_Recall_Comparison_With_Scale"
        ShortName = "graph_8_4_3_recall_with_scale"
    },
    @{
        SheetName = "F1-Score Graph"
        Metric = "F1-Score"
        ExportBaseName = "Figure_8_4_4_F1-Score_Comparison_With_Scale"
        ShortName = "graph_8_4_4_f1_score_with_scale"
    }
)

foreach ($cfg in $graphConfigs) {
    $sh = $wb.Sheets.Item($cfg.SheetName)
    Write-Host "Processing sheet: $($cfg.SheetName)"
    
    # 1. Update text note in worksheet
    $sh.Cells.Item(12, 1).Value2 = "Scale Definition & Academic Note:"
    $sh.Cells.Item(12, 1).Font.Name = "Segoe UI"
    $sh.Cells.Item(12, 1).Font.Size = 9.5
    $sh.Cells.Item(12, 1).Font.Bold = $true
    $sh.Cells.Item(12, 1).Font.Color = 51 + (65 * 256) + (85 * 65536) # Slate #334155
    
    $existingNote = [string]($sh.Cells.Item(13, 1).Value2)
    $scalePrefix = "[Scale: Percentage Metric (0.00% - 100.00%, where 100.00% represents optimal detection performance)]. "
    if (!($existingNote.StartsWith("[Scale:"))) {
        $sh.Cells.Item(13, 1).Value2 = $scalePrefix + $existingNote
    }

    # 2. Add native vertical Scale label inside Chart Object beside Y-Axis
    $chartObj = $sh.ChartObjects(1)
    $chartObj.Width = 605
    $chart = $chartObj.Chart
    
    # Remove any existing custom shapes added previously
    while ($chart.Shapes.Count -gt 0) {
        $chart.Shapes.Item(1).Delete()
    }
    
    # Position PlotArea
    $chart.PlotArea.InsideWidth = 460
    $chart.PlotArea.InsideLeft = 80
    
    # Position Y-Axis Title
    $chart.Axes(2).AxisTitle.Left = 32
    
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
    $tb.TextFrame2.TextRange.Font.Fill.ForeColor.RGB = 51 + (65 * 256) + (85 * 65536) # #334155 Slate
    $tb.Line.Visible = $false
    $tb.Fill.Visible = $false
    
    # Export chart images
    $exportFile1 = Join-Path $exportDir "$($cfg.ExportBaseName).png"
    $chart.Export($exportFile1, "PNG")
    Write-Host "Exported: $exportFile1"
    
    $exportFile2 = Join-Path $resultsDir "$($cfg.ShortName).png"
    $chart.Export($exportFile2, "PNG")
    Write-Host "Exported: $exportFile2"
}

# Ensure destination files are unlocked
foreach ($p in @($targetWorkbookRoot, $targetWorkbookResults, $targetAliasRoot, $targetAliasResults)) {
    if (Test-Path $p) {
        try { Remove-Item $p -Force -ErrorAction SilentlyContinue } catch {}
    }
}

# Save new workbooks
$wb.SaveAs($targetWorkbookResults)
$wb.SaveCopyAs($targetWorkbookRoot)
$wb.SaveCopyAs($targetAliasResults)
$wb.SaveCopyAs($targetAliasRoot)

Write-Host "Saved new workbooks successfully to:"
Write-Host "  1. $targetWorkbookRoot"
Write-Host "  2. $targetWorkbookResults"
Write-Host "  3. $targetAliasRoot"
Write-Host "  4. $targetAliasResults"

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
Write-Host "Workbook generation with scale completed cleanly!"
