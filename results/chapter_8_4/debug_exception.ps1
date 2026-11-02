$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$wb = $excel.Workbooks.Open("D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Section_8_4_Analysis.xlsx")

foreach ($name in @("Accuracy Graph", "Precision Graph", "Recall Graph", "F1-Score Graph")) {
    $sh = $wb.Sheets.Item($name)
    $chart = $sh.ChartObjects(1).Chart
    Write-Host "=== $name ==="
    Write-Host "Width: $($chart.PlotArea.Width), Left: $($chart.PlotArea.Left)"
    Write-Host "InsideWidth: $($chart.PlotArea.InsideWidth), InsideLeft: $($chart.PlotArea.InsideLeft)"
    
    # Check what happens if we set ChartObj.Chart.PlotArea.Position
    Write-Host "Position: $($chart.PlotArea.Position)"
    
    # Try setting Width first
    try {
        $chart.PlotArea.Width = 480
        Write-Host "Set Width = 480 OK"
    } catch {
        Write-Host "Set Width failed: $($_.Exception.Message)"
    }
}

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
