$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$src = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Section_8_4_Analysis.xlsx"
$wb = $excel.Workbooks.Open($src)

foreach ($shName in @("Accuracy Graph", "Precision Graph", "Recall Graph", "F1-Score Graph")) {
    $sh = $wb.Sheets.Item($shName)
    $chart = $sh.ChartObjects(1).Chart
    Write-Host "--- $shName ---"
    
    # Try setting PlotArea.Width and Left directly
    try {
        $chart.PlotArea.Width = 490
        $chart.PlotArea.Left = 50
        $chart.Axes(2).AxisTitle.Left = 18
        Write-Host "SUCCESS with direct PlotArea on $shName. Left: $($chart.PlotArea.Left), Width: $($chart.PlotArea.Width)"
    } catch {
        Write-Host "Direct failed on $shName"
    }
}

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
