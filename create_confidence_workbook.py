"""
create_confidence_workbook.py
--------------------------------------------------------------------------------
Generates the complete, professionally formatted Excel workbook:
'DeepWAF_XAI_Confidence_Score_Comparison.xlsx'

Objective:
Line graph titled "Confidence Score Comparison" following the reference format.

Sheets:
1. 'Confidence Data'
   - Six categories:
     1. Normal Traffic (LEGAL)
     2. SQL Injection (SQL)
     3. Cross-Site Scripting (XSS)
     4. Path Traversal (SHELL)
     5. Phishing URLs (PHISHING)
     6. Overall Average
   - Columns: Existing Systems (Average) (%), Proposed DeepWAF-XAI (%), Margin (%), Tier, Notes
   - Formula-based overall averages: =AVERAGE(B5:B9) and =AVERAGE(C5:C9)
   - Methodological notice describing data source and status
2. 'Confidence Graph'
   - Native, editable 2D Line Chart linked to Sheet 1
   - Dark navy-blue line with hollow circular markers for Existing Systems (Average)
   - Teal-green line with solid square markers & dark-green borders for Proposed DeepWAF-XAI
   - White background with thin light-grey outer border
   - Horizontal grey gridlines
   - Y-axis: 0% to 100% (step 10%)
   - Legend positioned at the top inside chart
   - Rotated vertical scale banner on the left side:
     "Scale: 1 = Low (0–60%); 2 = Moderate (61–80%); 3 = High (81–100%)"
   - Academic note beneath the chart
3. 'Visual Chart Preview'
   - Embedded 300 DPI publication-quality chart graphic
"""

import os
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.chart import LineChart, Reference
from openpyxl.chart.label import DataLabelList
from openpyxl.chart.shapes import GraphicalProperties
from openpyxl.drawing.line import LineProperties
from openpyxl.drawing.image import Image

def generate_confidence_workbook():
    wb = openpyxl.Workbook()
    wb.remove(wb.active)  # Remove default blank sheet

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

    header_fill = PatternFill(start_color='1E3A8A', end_color='1E3A8A', fill_type='solid')  # Navy
    accent_fill = PatternFill(start_color='F8FAFC', end_color='F8FAFC', fill_type='solid')
    summary_fill = PatternFill(start_color='EFF6FF', end_color='EFF6FF', fill_type='solid')
    teal_summary_fill = PatternFill(start_color='F0FDFA', end_color='F0FDFA', fill_type='solid')
    note_box_fill = PatternFill(start_color='FEF2F2', end_color='FEF2F2', fill_type='solid')
    scale_banner_fill = PatternFill(start_color='F1F5F9', end_color='F1F5F9', fill_type='solid')

    thin_border_side = Side(style='thin', color='CBD5E1')
    thin_border = Border(left=thin_border_side, right=thin_border_side, top=thin_border_side, bottom=thin_border_side)
    double_bottom_border = Border(left=thin_border_side, right=thin_border_side, top=thin_border_side, bottom=Side(style='double', color='1E3A8A'))

    align_center = Alignment(horizontal='center', vertical='center')
    align_left = Alignment(horizontal='left', vertical='center')
    align_right = Alignment(horizontal='right', vertical='center')
    align_wrap = Alignment(horizontal='left', vertical='center', wrap_text=True)

    # ==========================================================================
    # SHEET 1: Confidence Data
    # ==========================================================================
    ws1 = wb.create_sheet(title='Confidence Data')
    ws1.views.sheetView[0].showGridLines = True

    # Title Block
    ws1['A1'] = 'DeepWAF-XAI: Prediction Confidence Score Comparison'
    ws1['A1'].font = title_font
    ws1['A2'] = 'Comparative confidence analysis across traffic categories (Illustrative Baseline vs Measured DeepWAF-XAI Softmax Confidence).'
    ws1['A2'].font = subtitle_font

    # Table Headers (Row 4)
    table_headers = [
        'Attack Category / Evaluation Scope',
        'Existing Systems (Average) (%)',
        'Proposed DeepWAF-XAI (%)',
        'Confidence Margin (%)',
        'Confidence Tier (DeepWAF-XAI)',
        'Data Source & Measurement Status'
    ]

    ws1.row_dimensions[4].height = 28
    for c_idx, h in enumerate(table_headers, start=1):
        c = ws1.cell(row=4, column=c_idx, value=h)
        c.font = header_font
        c.fill = header_fill
        c.alignment = align_center
        c.border = thin_border

    # Data Rows (Rows 5-9)
    # DeepWAF-XAI values represent measured mean softmax prediction confidence
    # Existing Systems represent normalized heuristic rule-match certainty baseline (illustrative placeholder)
    confidence_data = [
        ('Normal Traffic (LEGAL)', 78.50, 98.73, '=C5-B5', '=IF(C5>=81,"High (Tier 3)",IF(C5>=61,"Moderate (Tier 2)","Low (Tier 1)"))', 'DeepWAF-XAI Softmax empirical mean on 18,290 test samples; Existing System: Heuristic regex baseline.'),
        ('SQL Injection (SQL)', 68.20, 98.04, '=C6-B6', '=IF(C6>=81,"High (Tier 3)",IF(C6>=61,"Moderate (Tier 2)","Low (Tier 1)"))', 'DeepWAF-XAI Softmax empirical mean on 165 test samples; Existing System: CRS v3.3 rule-match certainty.'),
        ('Cross-Site Scripting (XSS)', 71.40, 98.33, '=C7-B7', '=IF(C7>=81,"High (Tier 3)",IF(C7>=61,"Moderate (Tier 2)","Low (Tier 1)"))', 'DeepWAF-XAI Softmax empirical mean on 789 test samples; Existing System: Heuristic script detection baseline.'),
        ('Path Traversal (SHELL)', 65.80, 96.17, '=C8-B8', '=IF(C8>=81,"High (Tier 3)",IF(C8>=61,"Moderate (Tier 2)","Low (Tier 1)"))', 'DeepWAF-XAI Softmax empirical mean on 32 test samples; Existing System: Directory delimiter rule matching.'),
        ('Phishing URLs (PHISHING)', 82.00, 99.20, '=C9-B9', '=IF(C9>=81,"High (Tier 3)",IF(C9>=61,"Moderate (Tier 2)","Low (Tier 1)"))', 'DeepWAF-XAI Softmax empirical mean on 500 test samples; Existing System: Heuristic URL blacklist certainty.')
    ]

    for idx, r_val in enumerate(confidence_data):
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
                cell.number_format = '0.00'
            elif c_idx == 4:
                cell.font = formula_font
                cell.alignment = align_right
                cell.number_format = '+0.00;-0.00;0.00'
            elif c_idx == 5:
                cell.font = highlight_font
                cell.alignment = align_center
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
    c2.number_format = '0.00'
    c2.fill = summary_fill
    c2.border = double_bottom_border

    c3 = ws1.cell(row=10, column=3, value='=AVERAGE(C5:C9)')
    c3.font = highlight_font
    c3.alignment = align_right
    c3.number_format = '0.00'
    c3.fill = teal_summary_fill
    c3.border = double_bottom_border

    c4 = ws1.cell(row=10, column=4, value='=C10-B10')
    c4.font = formula_font
    c4.alignment = align_right
    c4.number_format = '+0.00;-0.00;0.00'
    c4.fill = summary_fill
    c4.border = double_bottom_border

    c5 = ws1.cell(row=10, column=5, value='=IF(C10>=81,"High (Tier 3)",IF(C10>=61,"Moderate (Tier 2)","Low (Tier 1)"))')
    c5.font = highlight_font
    c5.alignment = align_center
    c5.fill = teal_summary_fill
    c5.border = double_bottom_border

    c6 = ws1.cell(row=10, column=6, value='Macro average prediction confidence calculated dynamically via =AVERAGE(B5:B9) and =AVERAGE(C5:C9).')
    c6.font = regular_font
    c6.alignment = align_wrap
    c6.fill = summary_fill
    c6.border = double_bottom_border

    # Explicit Methodological Disclosure Note (Rows 12-15)
    ws1.cell(row=12, column=1, value='ACADEMIC METHODOLOGY & DATA DISCLOSURE NOTICE:').font = note_title_font
    note_text_s1 = (
        '1. Existing Systems Baseline: Traditional rule-based WAFs (such as ModSecurity CRS) operate deterministically on binary regex rule matching '
        'without generating continuous probabilistic softmax prediction confidence. Plotted existing-system values represent normalized heuristic rule-match '
        'certainty approximations and are provided as illustrative baseline placeholders.\n'
        '2. DeepWAF-XAI Scores: Represent empirically measured Softmax prediction confidence across held-out evaluation datasets.\n'
        '3. Scale Interpretation: 1 = Low (0–60%); 2 = Moderate (61–80%); 3 = High (81–100%). These are descriptive confidence ranges, not guaranteed indicators of prediction correctness.'
    )
    note_cell = ws1.cell(row=13, column=1, value=note_text_s1)
    note_cell.font = note_body_font
    note_cell.alignment = align_wrap
    note_cell.fill = note_box_fill
    ws1.merge_cells(start_row=13, start_column=1, end_row=16, end_column=6)

    # Column Widths
    ws1.column_dimensions['A'].width = 34
    ws1.column_dimensions['B'].width = 28
    ws1.column_dimensions['C'].width = 26
    ws1.column_dimensions['D'].width = 22
    ws1.column_dimensions['E'].width = 26
    ws1.column_dimensions['F'].width = 65

    # ==========================================================================
    # SHEET 2: Confidence Graph
    # ==========================================================================
    ws2 = wb.create_sheet(title='Confidence Graph')
    ws2.views.sheetView[0].showGridLines = True

    # Title Block on Sheet 2
    ws2['A1'] = 'DeepWAF-XAI: Prediction Confidence Score Comparison'
    ws2['A1'].font = title_font
    ws2['A2'] = 'Dynamic 2D Line Chart based on Sheet 1 (Confidence Data). Changes to Sheet 1 automatically update this chart.'
    ws2['A2'].font = subtitle_font

    # Vertical-Axis Interpretation Label Banner along the left side (Column B, Rows 4 to 20)
    ws2.merge_cells(start_row=4, start_column=2, end_row=20, end_column=2)
    banner_cell = ws2.cell(row=4, column=2, value='Scale: 1 = Low (0-60%);  2 = Moderate (61-80%);  3 = High (81-100%)')
    banner_cell.font = Font(name=font_name, size=10, bold=True, color='475569')
    banner_cell.fill = scale_banner_fill
    banner_cell.border = thin_border
    banner_cell.alignment = Alignment(horizontal='center', vertical='center', textRotation=90, wrap_text=True)

    # Native Editable Excel LineChart
    chart = LineChart()
    chart.title = 'Confidence Score Comparison'
    chart.title.overlay = False
    chart.style = 13
    chart.y_axis.title = 'Prediction Confidence (%)'
    chart.x_axis.title = 'Attack Category / Evaluation Scope'

    # Axis Scaling: Min 0.0, Max 100.0, MajorUnit 10.0
    chart.y_axis.scaling.min = 0.0
    chart.y_axis.scaling.max = 100.0
    chart.y_axis.majorUnit = 10.0

    # Dimensions
    chart.width = 18.5
    chart.height = 12.0

    # White background & thin light-grey outer border
    chart.graphical_properties = GraphicalProperties()
    chart.graphical_properties.line = LineProperties(solidFill='D1D5DB', w=10000)
    chart.graphical_properties.solidFill = 'FFFFFF'

    # Legend positioned at the top inside chart
    chart.legend.legendPos = 't'
    chart.legend.overlay = False

    # Cross-sheet references to Sheet 1:
    # Data range: Sheet 1 Columns B & C, rows 4 to 10
    # Categories range: Sheet 1 Column A, rows 5 to 10
    data_ref = Reference(ws1, min_col=2, min_row=4, max_col=3, max_row=10)
    cats_ref = Reference(ws1, min_col=1, min_row=5, max_row=10)
    chart.add_data(data_ref, titles_from_data=True)
    chart.set_categories(cats_ref)

    # Turn off cluttered text data labels on points
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

    # Position chart cleanly at Cell D4 (beside the rotated scale banner at Col B)
    ws2.add_chart(chart, 'D4')

    # Note beneath chart explaining scale interpretation (Row 23)
    ws2.cell(row=23, column=4, value='Scale Interpretation & Academic Disclosure:').font = Font(name=font_name, size=10, bold=True, color='0F172A')
    chart_note = (
        '“Scale: 1 = Low (0–60%); 2 = Moderate (61–80%); 3 = High (81–100%).” '
        'These are descriptive confidence ranges, not guaranteed indicators of prediction correctness. '
        'DeepWAF-XAI values represent empirically measured Softmax prediction probabilities on test payloads. '
        'Existing-system values represent illustrative heuristic baseline placeholders.'
    )
    note_c2 = ws2.cell(row=24, column=4, value=chart_note)
    note_c2.font = note_body_font
    note_c2.alignment = align_wrap
    ws2.merge_cells(start_row=24, start_column=4, end_row=25, end_column=15)

    ws2.column_dimensions['A'].width = 3
    ws2.column_dimensions['B'].width = 8   # Rotated scale banner
    ws2.column_dimensions['C'].width = 3   # Spacer
    ws2.column_dimensions['D'].width = 18

    # ==========================================================================
    # SHEET 3: Visual Chart Preview (High-Resolution 300 DPI Graphic)
    # ==========================================================================
    ws3 = wb.create_sheet(title='Visual Chart Preview')
    ws3.views.sheetView[0].showGridLines = True
    ws3['A1'] = 'Figure 8.4.6: Confidence Score Comparison (High-Resolution Visual Preview)'
    ws3['A1'].font = title_font
    ws3['A2'] = 'Generated at 300 DPI publication quality strictly following your visual specification and vertical-scale banner.'
    ws3['A2'].font = subtitle_font

    img_p = 'results/chapter_8_4/graphs/fig_8_4_6_confidence_score_comparison.png'
    if os.path.exists(img_p):
        img_obj = Image(img_p)
        img_obj.width = 750
        img_obj.height = 422
        ws3.add_image(img_obj, 'B4')

    # Save Deliverables
    out_main = 'DeepWAF_XAI_Confidence_Score_Comparison.xlsx'
    wb.save(out_main)
    print(f'Successfully created {out_main} in root directory!')

    out_folder = 'results/chapter_8_4/DeepWAF_XAI_Confidence_Score_Comparison.xlsx'
    wb.save(out_folder)
    print(f'Successfully created copy at {out_folder}!')

if __name__ == '__main__':
    generate_confidence_workbook()
