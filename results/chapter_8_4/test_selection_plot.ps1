$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$excel.DisplayAlerts = $false

$src = "D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4\DeepWAF_XAI_Section_8_4_Analysis.xlsx"
$wb = $excel.Workbooks.Open($src)

foreach ($shName in @("Accuracy Graph", "Precision Graph", "Recall Graph", "F1-Score Graph")) {
    $sh = $wb.Sheets.Item($shName)
    $chart = $sh.ChartObjects(1).Chart
    Write-Host "--- $shName ---"
    try {
        $chart.PlotArea.Select()
        $excel.Selection.Left = 55
        $excel.Selection.Width = 505
        $chart.Axes(2).AxisTitle.Left = 24
        Write-Host "SUCCESS with Selection on $shName. New Left:" $excel.Selection.Left
    } catch {
        Write-Host "FAILED on $shName : $_"
    }
}

$wb.Close($false)
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
