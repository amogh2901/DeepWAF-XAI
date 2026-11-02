"""
create_comparison_workbook.py
--------------------------------------------------------------------------------
Generates the complete, professionally formatted Excel workbook:
'DeepWAF_XAI_Attack_Response_Time_Comparison.xlsx'

Sheets:
1. 'Response Time Data'
   - Formatted table with all 6 categories and illustrative values
   - Calculated overall averages using Excel formulas =AVERAGE(B5:B9) and =AVERAGE(C5:C9)
   - Additional analytical columns: Latency Reduction (ms), Improvement Ratio (%), Notes
   - Visible methodological notice
2. 'Response Time Graph'
   - Native, editable 2D Line Chart based on Sheet 1
   - Dark navy-blue line with hollow circular markers for Existing Systems (Average)
   - Teal-green line with solid square markers & dark-green borders for Proposed DeepWAF-XAI
   - White background with thin light-grey outer border
   - Horizontal grey gridlines
   - Y-axis: 0 to 350 ms (step 50)
   - Legend centered below x-axis
   - X-axis title below categories
   - Interpretation note beneath chart explaining lower response time is better
3. 'Visual Chart Preview'
   - Embedded 300 DPI high-resolution publication PNG
"""

import os
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.chart import LineChart, Reference
from openpyxl.chart.label import DataLabelList
from openpyxl.chart.shapes import GraphicalProperties
from openpyxl.drawing.line import LineProperties
from openpyxl.drawing.image import Image

def generate_workbook():
    wb = openpyxl.Workbook()
    wb.remove(wb.active)  # Remove default blank sheet

    # Typography & Palette
    font_name = 'Segoe UI'
    title_font = Font(name=font_name, size=14, bold=True, color='0F172A')
    subtitle_font = Font(name=font_name, size=10, italic=True, color='475569')
    header_font = Font(name=font_name, size=11, bold=True, color='FFFFFF')
    bold_font = Font(name=font_name, size=10.5, bold=True, color='0F172A')
    regular_font = Font(name=font_name, size=10, color='1E293B')
    formula_font = Font(name=font_name, size=10.5, bold=True, color='1E40AF')
    highlight_font = Font(name=font_name, size=10.5, bold=True, color='0F766E')
    note_title_font = Font(name=font_name, size=10, bold=True, color='991B1B')
    note_body_font = Font(name=font_name, size=9.5, italic=True, color='475569')

    header_fill = PatternFill(start_color='1E3A8A', end_color='1E3A8A', fill_type='solid')  # Dark Navy
    accent_fill = PatternFill(start_color='F8FAFC', end_color='F8FAFC', fill_type='solid')
    summary_fill = PatternFill(start_color='EFF6FF', end_color='EFF6FF', fill_type='solid')
    teal_summary_fill = PatternFill(start_color='F0FDFA', end_color='F0FDFA', fill_type='solid')
    note_box_fill = PatternFill(start_color='FEF2F2', end_color='FEF2F2', fill_type='solid')

    thin_border_side = Side(style='thin', color='CBD5E1')
    thin_border = Border(left=thin_border_side, right=thin_border_side, top=thin_border_side, bottom=thin_border_side)
    double_bottom_border = Border(left=thin_border_side, right=thin_border_side, top=thin_border_side, bottom=Side(style='double', color='1E3A8A'))

    align_center = Alignment(horizontal='center', vertical='center')
    align_left = Alignment(horizontal='left', vertical='center')
    align_right = Alignment(horizontal='right', vertical='center')
    align_wrap = Alignment(horizontal='left', vertical='center', wrap_text=True)

    # ==========================================================================
    # SHEET 1: Response Time Data
    # ==========================================================================
    ws1 = wb.create_sheet(title='Response Time Data')
    ws1.views.sheetView[0].showGridLines = True

    # Title Block
    ws1['A1'] = 'DeepWAF-XAI: Web Attack Response Time Benchmark'
    ws1['A1'].font = title_font
    ws1['A2'] = 'Comparative performance analysis of latency between Existing Systems (Average) and Proposed DeepWAF-XAI.'
    ws1['A2'].font = subtitle_font

    # Table Headers (Row 4)
    table_headers = [
        'Attack Category / Evaluation Scope',
        'Existing Systems (Average) (ms)',
        'Proposed DeepWAF-XAI (ms)',
        'Latency Reduction (ms)',
        'Improvement Ratio (%)',
        'Evaluation Scope & Processing Notes'
    ]

    ws1.row_dimensions[4].height = 28
    for c_idx, h in enumerate(table_headers, start=1):
        c = ws1.cell(row=4, column=c_idx, value=h)
        c.font = header_font
        c.fill = header_fill
        c.alignment = align_center
        c.border = thin_border

    # Data Rows (Rows 5-9)
    raw_data = [
        ('Normal Request', 180, 125, '=B5-C5', '=(B5-C5)/B5', 'Benign baseline traffic; fast-path evaluation without attack mitigation overhead.'),
        ('SQL Injection', 240, 165, '=B6-C6', '=(B6-C6)/B6', 'SQL syntax parsing and character tokenization; BiLSTM forward classification pass.'),
        ('Cross-Site Scripting (XSS)', 265, 185, '=B7-C7', '=(B7-C7)/B7', 'Script tag and event handler inspection; recursive payload normalization pipeline.'),
        ('Path Traversal', 230, 155, '=B8-C8', '=(B8-C8)/B8', 'Directory traversal sequences (../) and encoding bypass detection.'),
        ('Phishing URL', 290, 205, '=B9-C9', '=(B9-C9)/B9', 'Lexical URL parsing, domain tokenization, and character n-gram inference.')
    ]

    for idx, r_val in enumerate(raw_data):
        r_num = 5 + idx
        ws1.row_dimensions[r_num].height = 22
        fill = accent_fill if idx % 2 == 1 else PatternFill(fill_type=None)
        for c_idx, val in enumerate(r_val, start=1):
            cell = ws1.cell(row=r_num, column=c_idx, value=val)
            cell.border = thin_border
            cell.fill = fill
            if c_idx == 1:
                cell.font = bold_font
                cell.alignment = align_left
            elif c_idx in (2, 3):
                cell.font = regular_font
                cell.alignment = align_right
                cell.number_format = '0'
            elif c_idx == 4:
                cell.font = formula_font
                cell.alignment = align_right
                cell.number_format = '+0;-0;0'
            elif c_idx == 5:
                cell.font = highlight_font
                cell.alignment = align_right
                cell.number_format = '+0.0%;-0.0%;0.0%'
            else:
                cell.font = regular_font
                cell.alignment = align_wrap

    # Row 10: Overall Average (Calculated via Excel formulas)
    ws1.row_dimensions[10].height = 24
    c1 = ws1.cell(row=10, column=1, value='Overall Average')
    c1.font = bold_font
    c1.alignment = align_left
    c1.fill = summary_fill
    c1.border = double_bottom_border

    c2 = ws1.cell(row=10, column=2, value='=AVERAGE(B5:B9)')
    c2.font = formula_font
    c2.alignment = align_right
    c2.number_format = '0'
    c2.fill = summary_fill
    c2.border = double_bottom_border

    c3 = ws1.cell(row=10, column=3, value='=AVERAGE(C5:C9)')
    c3.font = highlight_font
    c3.alignment = align_right
    c3.number_format = '0'
    c3.fill = teal_summary_fill
    c3.border = double_bottom_border

    c4 = ws1.cell(row=10, column=4, value='=B10-C10')
    c4.font = formula_font
    c4.alignment = align_right
    c4.number_format = '+0;-0;0'
    c4.fill = summary_fill
    c4.border = double_bottom_border

    c5 = ws1.cell(row=10, column=5, value='=(B10-C10)/B10')
    c5.font = highlight_font
    c5.alignment = align_right
    c5.number_format = '+0.0%;-0.0%;0.0%'
    c5.fill = teal_summary_fill
    c5.border = double_bottom_border

    c6 = ws1.cell(row=10, column=6, value='Calculated overall average across all five attack categories; DeepWAF-XAI achieves 30.7% lower average latency.')
    c6.font = regular_font
    c6.alignment = align_wrap
    c6.fill = summary_fill
    c6.border = double_bottom_border

    # Explicit Visible Note (Rows 12-14)
    ws1.cell(row=12, column=1, value='MANDATORY METHODOLOGICAL NOTICE:').font = note_title_font
    note_text_s1 = (
        '“Illustrative values for visualization only; replace with experimentally measured results before reporting.”\n'
        'Scale: Response time in milliseconds (ms). Lower response time indicates faster processing and superior real-time mitigation capability. '
        'Averages are calculated dynamically using Excel =AVERAGE(B5:B9) and =AVERAGE(C5:C9) formulas.'
    )
    note_cell = ws1.cell(row=13, column=1, value=note_text_s1)
    note_cell.font = note_body_font
    note_cell.alignment = align_wrap
    note_cell.fill = note_box_fill
    ws1.merge_cells(start_row=13, start_column=1, end_row=14, end_column=6)

    # Column Widths
    ws1.column_dimensions['A'].width = 34
    ws1.column_dimensions['B'].width = 28
    ws1.column_dimensions['C'].width = 26
    ws1.column_dimensions['D'].width = 22
    ws1.column_dimensions['E'].width = 22
    ws1.column_dimensions['F'].width = 65

    # ==========================================================================
    # SHEET 2: Response Time Graph
    # ==========================================================================
    ws2 = wb.create_sheet(title='Response Time Graph')
    ws2.views.sheetView[0].showGridLines = True

    # Title Block on Sheet 2
    ws2['A1'] = 'DeepWAF-XAI: Attack Response Time Comparison Chart'
    ws2['A1'].font = title_font
    ws2['A2'] = 'Dynamic 2D Line Chart based on Sheet 1 (Response Time Data). Changes to Sheet 1 automatically update this chart.'
    ws2['A2'].font = subtitle_font

    # Native Editable Excel LineChart
    chart = LineChart()
    chart.title = 'Attack Response Time Comparison'
    chart.title.overlay = False
    chart.style = 13
    chart.y_axis.title = 'Average Attack Response Time (ms)'
    chart.x_axis.title = 'Attack Category / Evaluation Scope'

    # Axis Scaling: Min 0.0, Max 350.0, MajorUnit 50.0
    chart.y_axis.scaling.min = 0.0
    chart.y_axis.scaling.max = 350.0
    chart.y_axis.majorUnit = 50.0

    # Chart dimensions (clean, wide, readable for thesis report)
    chart.width = 18.5
    chart.height = 12.0

    # White background & thin light-grey outer border
    chart.graphical_properties = GraphicalProperties()
    chart.graphical_properties.line = LineProperties(solidFill='D1D5DB', w=10000)
    chart.graphical_properties.solidFill = 'FFFFFF'

    # Legend centered below x-axis labels
    chart.legend.legendPos = 'b'
    chart.legend.overlay = False

    # Cross-sheet references to Sheet 1:
    # Data range: Sheet 1 Columns B & C, rows 4 to 10 (includes all 6 categories and headers)
    # Categories range: Sheet 1 Column A, rows 5 to 10
    data_ref = Reference(ws1, min_col=2, min_row=4, max_col=3, max_row=10)
    cats_ref = Reference(ws1, min_col=1, min_row=5, max_row=10)
    chart.add_data(data_ref, titles_from_data=True)
    chart.set_categories(cats_ref)

    # Disable cluttered text data labels on points
    chart.dataLabels = DataLabelList()
    chart.dataLabels.showVal = False
    chart.dataLabels.showCatName = False
    chart.dataLabels.showSerName = False
    chart.dataLabels.showPercent = False

    # Series 0: Existing Systems (Average) - Dark navy-blue line with hollow circular markers
    s1 = chart.series[0]
    s1.smooth = False  # Straight point-to-point lines
    s1.marker.symbol = 'circle'
    s1.marker.size = 8
    s1.graphicalProperties.line.solidFill = '1E3A8A'  # Dark navy-blue
    s1.graphicalProperties.line.width = 25000
    s1.marker.graphicalProperties.solidFill = 'FFFFFF'  # Hollow interior
    s1.marker.graphicalProperties.line.solidFill = '1E3A8A'  # Navy-blue outer circle border
    s1.marker.graphicalProperties.line.width = 20000

    # Series 1: Proposed DeepWAF-XAI - Teal-green line with solid square markers & dark-green borders
    s2 = chart.series[1]
    s2.smooth = False  # Straight point-to-point lines
    s2.marker.symbol = 'square'
    s2.marker.size = 8
    s2.graphicalProperties.line.solidFill = '0D9488'  # Teal-green line
    s2.graphicalProperties.line.width = 25000
    s2.marker.graphicalProperties.solidFill = '0D9488'  # Solid teal-green fill
    s2.marker.graphicalProperties.line.solidFill = '064E3B'  # Dark-green border
    s2.marker.graphicalProperties.line.width = 20000

    # Position chart cleanly at Cell B4
    ws2.add_chart(chart, 'B4')

    # Note beneath chart explaining lower response time (Row 25)
    ws2.cell(row=25, column=2, value='Interpretation & Methodology Note:').font = Font(name=font_name, size=10, bold=True, color='0F172A')
    chart_note = (
        'Note: Lower response time indicates faster processing and superior real-time mitigation capability. '
        'All plotted values are illustrative placeholders for dissertation visualization only. '
        'Replace with experimentally measured results before final reporting.'
    )
    note_c2 = ws2.cell(row=26, column=2, value=chart_note)
    note_c2.font = note_body_font
    note_c2.alignment = align_wrap
    ws2.merge_cells(start_row=26, start_column=2, end_row=27, end_column=12)

    ws2.column_dimensions['A'].width = 4
    ws2.column_dimensions['B'].width = 18

    # ==========================================================================
    # SHEET 3: Visual Chart Preview (High-Resolution 300 DPI Graphic)
    # ==========================================================================
    ws3 = wb.create_sheet(title='Visual Chart Preview')
    ws3.views.sheetView[0].showGridLines = True
    ws3['A1'] = 'Figure 8.4.5: Attack Response Time Comparison (High-Resolution Visual Preview)'
    ws3['A1'].font = title_font
    ws3['A2'] = 'Generated at 300 DPI publication quality strictly following your visual specification.'
    ws3['A2'].font = subtitle_font

    img_p = 'results/chapter_8_4/graphs/fig_8_4_5_attack_response_time_comparison.png'
    if os.path.exists(img_p):
        img_obj = Image(img_p)
        img_obj.width = 750
        img_obj.height = 422
        ws3.add_image(img_obj, 'B4')

    # Save Deliverables
    out_main = 'DeepWAF_XAI_Attack_Response_Time_Comparison.xlsx'
    wb.save(out_main)
    print(f'Successfully created {out_main} in root directory!')

    # Save copy in results/chapter_8_4/
    out_folder = 'results/chapter_8_4/DeepWAF_XAI_Attack_Response_Time_Comparison.xlsx'
    wb.save(out_folder)
    print(f'Successfully created copy at {out_folder}!')

if __name__ == '__main__':
    generate_workbook()

