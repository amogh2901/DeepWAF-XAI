$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$src = "D:\Amogh\MCA\DeepWAF-XAI\DeepWAF_XAI_Section_8_4_Analysis.xlsx"
$wb = $excel.Workbooks.Open($src, $false, $true)

foreach ($shName in @("Accuracy Graph", "Precision Graph", "Recall Graph", "F1-Score Graph")) {
    $sh = $wb.Sheets.Item($shName)
    $chart = $sh.ChartObjects(1).Chart
    Write-Host "=== $shName ==="
    Write-Host "ChartArea Width:" $chart.ChartArea.Width "Height:" $chart.ChartArea.Height
    Write-Host "PlotArea Width:" $chart.PlotArea.Width "Height:" $chart.PlotArea.Height "Left:" $chart.PlotArea.Left "Top:" $chart.PlotArea.Top
    Write-Host "InsideWidth:" $chart.PlotArea.InsideWidth "InsideHeight:" $chart.PlotArea.InsideHeight "InsideLeft:" $chart.PlotArea.InsideLeft "InsideTop:" $chart.PlotArea.InsideTop
}

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
