$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

# Fresh copy of original workbook
$tempCopy = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\temp_fresh_copy.xlsx"
Copy-Item "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Section_8_4_Analysis.xlsx" $tempCopy -Force

$wb = $excel.Workbooks.Open($tempCopy)

foreach ($name in @("Accuracy Graph", "Precision Graph", "Recall Graph", "F1-Score Graph")) {
    $sh = $wb.Sheets.Item($name)
    $chart = $sh.ChartObjects(1).Chart
    Write-Host "=== $name ==="
    Write-Host "Initial: Left=$($chart.PlotArea.Left), Width=$($chart.PlotArea.Width), InsideLeft=$($chart.PlotArea.InsideLeft), InsideWidth=$($chart.PlotArea.InsideWidth)"
    
    # Try different sequence:
    # 1. First set PlotArea.Width to give room
    try {
        # Select chart to make it active
        $chart.ChartArea.Select() | Out-Null
        
        # Test setting InsideWidth with a safe margin
        $safeWidth = [Math]::Floor($chart.PlotArea.Width * 0.85)
        $chart.PlotArea.InsideWidth = 440
        $chart.PlotArea.InsideLeft = 75
        $chart.Axes(2).AxisTitle.Left = 30
        Write-Host "SUCCESS on $name : InsideLeft=$($chart.PlotArea.InsideLeft), InsideWidth=$($chart.PlotArea.InsideWidth)"
    } catch {
        Write-Host "FAILED on $name : $($_.Exception.Message)"
    }
}

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
Remove-Item $tempCopy -Force
