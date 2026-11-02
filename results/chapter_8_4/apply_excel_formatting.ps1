$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$tempPath = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\temp_base_workbook.xlsx"
$finalResultPath = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Section_8_4_Analysis.xlsx"
$finalRootPath = "D:\Amogh\MCA\DeepWAF-XAI\DeepWAF_XAI_Section_8_4_Analysis.xlsx"
$exportDir = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\excel_exports"

if (!(Test-Path $exportDir)) { New-Item -ItemType Directory -Path $exportDir | Out-Null }

$wb = $excel.Workbooks.Open($tempPath)

# Color definitions in Excel OLE format: R + (G * 256) + (B * 65536)
$colorSlate = 51 + (65 * 256) + (85 * 65536)       # #334155
$colorEmerald = 5 + (150 * 256) + (105 * 65536)    # #059669
$colorDarkEmerald = 6 + (78 * 256) + (59 * 65536)  # #064E3B
$colorWhite = 16777215                             # #FFFFFF

$graphConfigs = @(
    @{
        SheetName = "Accuracy Graph"
        Title = "Figure 8.4.1: Accuracy Comparison"
        YTitle = "Accuracy (%)"
        Min = 70
        Max = 105
    },
    @{
        SheetName = "Precision Graph"
        Title = "Figure 8.4.2: Precision Comparison"
        YTitle = "Precision (%)"
        Min = 0
        Max = 110
    },
    @{
        SheetName = "Recall Graph"
        Title = "Figure 8.4.3: Recall Comparison"
        YTitle = "Recall (%)"
        Min = 65
        Max = 105
    },
    @{
        SheetName = "F1-Score Graph"
        Title = "Figure 8.4.4: F1-Score Comparison"
        YTitle = "F1-Score (%)"
        Min = 15
        Max = 105
    }
)

foreach ($cfg in $graphConfigs) {
    $sh = $wb.Sheets.Item($cfg.SheetName)
    Write-Host "Creating native Excel chart on sheet: $($cfg.SheetName)"

    # Remove any existing chart objects on sheet
    while ($sh.ChartObjects().Count -gt 0) {
        $sh.ChartObjects(1).Delete()
    }

    # Add Chart Object: Left=460, Top=40, Width=580, Height=350
    $chartObj = $sh.ChartObjects().Add(460, 40, 580, 350)
    $chart = $chartObj.Chart
    $chart.ChartType = 65 # xlLineMarkers

    $dataRange = $sh.Range("A4:C10")
    $chart.SetSourceData($dataRange)

    $chart.HasTitle = $true
    $chart.ChartTitle.Text = $cfg.Title
    $chart.ChartTitle.Font.Name = "Segoe UI"
    $chart.ChartTitle.Font.Size = 12
    $chart.ChartTitle.Font.Bold = $true

    # Category Axis (X Axis)
    $catAxis = $chart.Axes(1)
    $catAxis.HasTitle = $true
    $catAxis.AxisTitle.Text = "Attack Category / Evaluation Scope"
    $catAxis.AxisTitle.Font.Name = "Segoe UI"
    $catAxis.AxisTitle.Font.Size = 10
    $catAxis.AxisTitle.Font.Bold = $true
    $catAxis.TickLabels.Font.Name = "Segoe UI"
    $catAxis.TickLabels.Font.Size = 8.5
    $catAxis.TickLabels.Font.Bold = $true

    # Value Axis (Y Axis)
    $valAxis = $chart.Axes(2)
    $valAxis.HasTitle = $true
    $valAxis.AxisTitle.Text = $cfg.YTitle
    $valAxis.AxisTitle.Font.Name = "Segoe UI"
    $valAxis.AxisTitle.Font.Size = 10
    $valAxis.AxisTitle.Font.Bold = $true
    $valAxis.MinimumScale = $cfg.Min
    $valAxis.MaximumScale = $cfg.Max
    $valAxis.HasMajorGridlines = $true
    $valAxis.TickLabels.Font.Name = "Segoe UI"
    $valAxis.TickLabels.Font.Size = 9

    # Series 1: Existing Systems (Average) - Circular markers, Slate color
    $s1 = $chart.SeriesCollection(1)
    $s1.Name = "Existing Systems (Average)"
    $s1.MarkerStyle = 8 # xlMarkerStyleCircle
    $s1.MarkerSize = 8
    $s1.Format.Line.ForeColor.RGB = $colorSlate
    $s1.Format.Line.Weight = 2.25
    $s1.MarkerBackgroundColor = $colorWhite
    $s1.MarkerForegroundColor = $colorSlate
    $s1.ApplyDataLabels()
    $s1.DataLabels().ShowValue = $true
    $s1.DataLabels().ShowSeriesName = $false
    $s1.DataLabels().ShowCategoryName = $false
    $s1.DataLabels().Font.Name = "Segoe UI"
    $s1.DataLabels().Font.Size = 8.5
    $s1.DataLabels().Font.Bold = $true

    # Series 2: Proposed DeepWAF-XAI - Square markers, Emerald color
    $s2 = $chart.SeriesCollection(2)
    $s2.Name = "Proposed DeepWAF-XAI"
    $s2.MarkerStyle = 1 # xlMarkerStyleSquare
    $s2.MarkerSize = 8
    $s2.Format.Line.ForeColor.RGB = $colorEmerald
    $s2.Format.Line.Weight = 2.5
    $s2.MarkerBackgroundColor = $colorEmerald
    $s2.MarkerForegroundColor = $colorDarkEmerald
    $s2.ApplyDataLabels()
    $s2.DataLabels().ShowValue = $true
    $s2.DataLabels().ShowSeriesName = $false
    $s2.DataLabels().ShowCategoryName = $false
    $s2.DataLabels().Font.Name = "Segoe UI"
    $s2.DataLabels().Font.Size = 9
    $s2.DataLabels().Font.Bold = $true

    # Legend at bottom right
    $chart.HasLegend = $true
    $chart.Legend.Position = -4107 # xlLegendPositionBottom
    $chart.Legend.Font.Name = "Segoe UI"
    $chart.Legend.Font.Size = 9
}

# Apply PageSetup to ALL sheets
Write-Host "Configuring professional landscape PageSetup on all sheets..."
foreach ($sh in $wb.Sheets) {
    $ps = $sh.PageSetup
    $ps.Orientation = 2       # 2 = xlLandscape
    $ps.PaperSize = 9         # 9 = xlPaperA4
    $ps.Zoom = $false
    $ps.FitToPagesWide = 1
    $ps.PrintGridlines = $true
    $ps.TopMargin = $excel.InchesToPoints(0.5)
    $ps.BottomMargin = $excel.InchesToPoints(0.5)
    $ps.LeftMargin = $excel.InchesToPoints(0.5)
    $ps.RightMargin = $excel.InchesToPoints(0.5)

    if ($sh.Name -like "*Graph*") {
        $ps.FitToPagesTall = 1  # Exactly 1 page for table + chart
    } else {
        $ps.FitToPagesTall = $false # Naturally scrolls vertically without column splitting
    }
}

# Remove existing files if present to prevent overwrite lock issues
if (Test-Path $finalResultPath) { Remove-Item $finalResultPath -Force }
if (Test-Path $finalRootPath) { Remove-Item $finalRootPath -Force }

# Save final workbook to results directory and root
$wb.SaveAs($finalResultPath)
$wb.SaveCopyAs($finalRootPath)
Write-Host "Saved final workbook to $finalResultPath and $finalRootPath successfully!"

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
Write-Host "All Excel operations completed cleanly!"
