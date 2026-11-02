$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$src = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Section_8_4_Analysis.xlsx"
$wb = $excel.Workbooks.Open($src)

foreach ($shName in @("Accuracy Graph", "Precision Graph", "Recall Graph", "F1-Score Graph")) {
    $sh = $wb.Sheets.Item($shName)
    $chartObj = $sh.ChartObjects(1)
    $chart = $chartObj.Chart
    Write-Host "=== $shName ==="
    Write-Host "ChartObj Left:" $chartObj.Left "Top:" $chartObj.Top "Width:" $chartObj.Width "Height:" $chartObj.Height
    Write-Host "PlotArea Left:" $chart.PlotArea.Left "Top:" $chart.PlotArea.Top "Width:" $chart.PlotArea.Width "Height:" $chart.PlotArea.Height
    Write-Host "ChartArea Width:" $chart.ChartArea.Width "Height:" $chart.ChartArea.Height
    Write-Host "Y-Axis Title Left:" $chart.Axes(2).AxisTitle.Left "Top:" $chart.Axes(2).AxisTitle.Top "Width:" $chart.Axes(2).AxisTitle.Width "Height:" $chart.Axes(2).AxisTitle.Height
}

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
