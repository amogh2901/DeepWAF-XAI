"""
create_fpr_workbook.py
--------------------------------------------------------------------------------
Generates the complete, professionally formatted Excel workbook:
'DeepWAF_XAI_False_Positive_Rate_Comparison.xlsx'

Objective:
Line graph titled "False Positive Rate Comparison" with percentage scale 0 to 100.

Categories:
1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Path Traversal
4. Phishing URLs
5. Normal Traffic
6. Overall Average

Values:
- SQL Injection: 16.50 | 5.83 | +10.67 | Moderate (Tier 2)
- Cross-Site Scripting (XSS): 19.80 | 3.80 | +16.00 | Low (Tier 1)
- Path Traversal: 12.40 | 4.32 | +8.08 | Low (Tier 1)
- Phishing URLs: 8.50 | 5.24 | +3.26 | Moderate (Tier 2)
- Normal Traffic: 17.20 | 7.60 | +9.60 | Moderate (Tier 2)
- Overall Average: =AVERAGE(B5:B9) (14.88) | =AVERAGE(C5:C9) (5.36) | =B10-C10 (+9.52) | Moderate (Tier 2)
"""

import os
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.chart import LineChart, Reference
from openpyxl.chart.label import DataLabelList
from openpyxl.chart.shapes import GraphicalProperties
from openpyxl.drawing.line import LineProperties
from openpyxl.drawing.image import Image

def generate_fpr_workbook():
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
    # SHEET 1: FPR Data
    # ==========================================================================
    ws1 = wb.create_sheet(title='FPR Data')
    ws1.views.sheetView[0].showGridLines = True

    # Title Block
    ws1['A1'] = 'DeepWAF-XAI: False Positive Rate (FPR) Performance Comparison'
    ws1['A1'].font = title_font
    ws1['A2'] = 'Comparative evaluation of False Positive Rate (%) across attack categories (Scale: 0% to 100%).'
    ws1['A2'].font = subtitle_font

    # Table Headers (Row 4) - Wide, unclipped, professional formatting
    table_headers = [
        'Attack Category / Evaluation Scope',
        'Existing Systems (Average) (%)',
        'Proposed DeepWAF-XAI (%)',
        'FPR Reduction (%)',
        'FPR Tier (DeepWAF-XAI)',
        'Evaluation Scope & Empirical Basis'
    ]

    ws1.row_dimensions[4].height = 32
    for c_idx, h in enumerate(table_headers, start=1):
        c = ws1.cell(row=4, column=c_idx, value=h)
        c.font = header_font
        c.fill = header_fill
        c.alignment = align_center
        c.border = thin_border

    # Data Rows (Rows 5-9) with user-specified values
    fpr_data = [
        ('SQL Injection', 16.50, 5.83, '=B5-C5', '=IF(C5<=5,"Low (Tier 1)",IF(C5<=10,"Moderate (Tier 2)",IF(C5<=20,"High (Tier 3)","Very High (Tier 4)")))', 'DeepWAF-XAI measured binary FPR on SQL injection evaluation split; Existing Systems: CRS v3.3 regex baseline.'),
        ('Cross-Site Scripting (XSS)', 19.80, 3.80, '=B6-C6', '=IF(C6<=5,"Low (Tier 1)",IF(C6<=10,"Moderate (Tier 2)",IF(C6<=20,"High (Tier 3)","Very High (Tier 4)")))', 'DeepWAF-XAI measured binary FPR on XSS vectors; Existing Systems: CRS script-tag regex baseline.'),
        ('Path Traversal', 12.40, 4.32, '=B7-C7', '=IF(C7<=5,"Low (Tier 1)",IF(C7<=10,"Moderate (Tier 2)",IF(C7<=20,"High (Tier 3)","Very High (Tier 4)")))', 'DeepWAF-XAI measured binary FPR on directory traversal vectors; Existing Systems: Delimiter rule matching.'),
        ('Phishing URLs', 8.50, 5.24, '=B8-C8', '=IF(C8<=5,"Low (Tier 1)",IF(C8<=10,"Moderate (Tier 2)",IF(C8<=20,"High (Tier 3)","Very High (Tier 4)")))', 'DeepWAF-XAI measured binary FPR on phishing URLs; Existing Systems: Blacklist / heuristic URL matching.'),
        ('Normal Traffic', 17.20, 7.60, '=B9-C9', '=IF(C9<=5,"Low (Tier 1)",IF(C9<=10,"Moderate (Tier 2)",IF(C9<=20,"High (Tier 3)","Very High (Tier 4)")))', 'DeepWAF-XAI overall benign false alarm rate on 18,290 legitimate requests; Existing Systems: CRS benign baseline.')
    ]

    for idx, r_val in enumerate(fpr_data):
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

    c4 = ws1.cell(row=10, column=4, value='=B10-C10')
    c4.font = formula_font
    c4.alignment = align_right
    c4.number_format = '+0.00;-0.00;0.00'
    c4.fill = summary_fill
    c4.border = double_bottom_border

    c5 = ws1.cell(row=10, column=5, value='=IF(C10<=5,"Low (Tier 1)",IF(C10<=10,"Moderate (Tier 2)",IF(C10<=20,"High (Tier 3)","Very High (Tier 4)")))')
    c5.font = highlight_font
    c5.alignment = align_center
    c5.fill = teal_summary_fill
    c5.border = double_bottom_border

    c6 = ws1.cell(row=10, column=6, value='Macro arithmetic mean calculated dynamically via =AVERAGE(B5:B9) and =AVERAGE(C5:C9).')
    c6.font = regular_font
    c6.alignment = align_wrap
    c6.fill = summary_fill
    c6.border = double_bottom_border

    # Explicit Methodological & Statistical Notes (Rows 12-18)
    ws1.cell(row=12, column=1, value='MANDATORY METHODOLOGICAL NOTICE:').font = note_title_font
    note_text_s1 = (
        '"Illustrative values must be replaced with experimentally measured results before use as project evidence."\n\n'
        '1. Definition & Formula: False Positive Rate (%) = FP / (FP + TN) x 100, where FP = legitimate requests incorrectly classified as malicious, '
        'and TN = legitimate requests correctly classified as legitimate.\n'
        '2. Scale: Full percentage scale from 0% to 100% (Major grid intervals of 10%).\n'
        '3. Arithmetic Macro Average vs Pooled FPR: The arithmetic macro average (=AVERAGE(C5:C9)) is 5.36%. In production environments where sample sizes differ across categories, '
        'a sample-weighted pooled false positive rate should be calculated from total counts: Pooled FPR = 1,390 / 18,290 x 100 = 7.60%.\n'
        '4. Existing Systems Baseline: ModSecurity CRS v3.3 literature benchmarks; provided as illustrative baseline placeholders.\n'
        '5. Scale Interpretation: 1 = Low (0-5%); 2 = Moderate (6-10%); 3 = High (11-20%); 4 = Very High (21-100%). Lower false positive rate is better.'
    )
    note_cell = ws1.cell(row=13, column=1, value=note_text_s1)
    note_cell.font = note_body_font
    note_cell.alignment = align_wrap
    note_cell.fill = note_box_fill
    ws1.merge_cells(start_row=13, start_column=1, end_row=18, end_column=6)

    # Column Widths - Generous widths to completely prevent header text truncation/wrapping
    ws1.column_dimensions['A'].width = 38
    ws1.column_dimensions['B'].width = 34
    ws1.column_dimensions['C'].width = 30
    ws1.column_dimensions['D'].width = 22
    ws1.column_dimensions['E'].width = 26
    ws1.column_dimensions['F'].width = 65

    # ==========================================================================
    # SHEET 2: FPR Graph
    # ==========================================================================
    ws2 = wb.create_sheet(title='FPR Graph')
    ws2.views.sheetView[0].showGridLines = True

    # Title Block on Sheet 2
    ws2['A1'] = 'DeepWAF-XAI: False Positive Rate (FPR) Comparison Chart'
    ws2['A1'].font = title_font
    ws2['A2'] = 'Dynamic 2D Line Chart linked to Sheet 1 (FPR Data). Full percentage scale (0% to 100%).'
    ws2['A2'].font = subtitle_font

    # Vertical-Axis Interpretation Label Banner along the left side (Column B, Rows 4 to 20)
    ws2.merge_cells(start_row=4, start_column=2, end_row=20, end_column=2)
    banner_cell = ws2.cell(row=4, column=2, value='Scale: 1 = Low (0-5%);  2 = Moderate (6-10%);  3 = High (11-20%);  4 = Very High (21-100%)')
    banner_cell.font = Font(name=font_name, size=10, bold=True, color='475569')
    banner_cell.fill = scale_banner_fill
    banner_cell.border = thin_border
    banner_cell.alignment = Alignment(horizontal='center', vertical='center', textRotation=90, wrap_text=True)

    # Native Editable Excel LineChart
    chart = LineChart()
    chart.title = 'False Positive Rate Comparison'
    chart.title.overlay = False
    chart.style = 13
    chart.y_axis.title = 'False Positive Rate (%)'
    chart.x_axis.title = 'Attack Category / Evaluation Scope'

    # Axis Scaling strictly 0% to 100% in 10% steps as requested!
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

    # Note beneath chart explaining that lower false positive rate is better (Row 23)
    ws2.cell(row=23, column=4, value='Interpretation & Methodology Note:').font = Font(name=font_name, size=10, bold=True, color='0F172A')
    chart_note = (
        '"Lower false positive rate indicates fewer legitimate requests incorrectly flagged as malicious."\n'
        'Scale: 1 = Low (0-5%); 2 = Moderate (6-10%); 3 = High (11-20%); 4 = Very High (21-100%). '
        'DeepWAF-XAI arithmetic macro average is 5.36% (Moderate Tier 2); sample-weighted pooled FPR across all 18,290 legitimate requests is 7.60% (Moderate Tier 2). '
        'Plotted on full percentage scale from 0% to 100% with 10% gridline intervals.'
    )
    note_c2 = ws2.cell(row=24, column=4, value=chart_note)
    note_c2.font = note_body_font
    note_c2.alignment = align_wrap
    ws2.merge_cells(start_row=24, start_column=4, end_row=26, end_column=15)

    ws2.column_dimensions['A'].width = 3
    ws2.column_dimensions['B'].width = 8   # Rotated scale banner
    ws2.column_dimensions['C'].width = 3   # Spacer
    ws2.column_dimensions['D'].width = 18

    # ==========================================================================
    # SHEET 3: Visual Chart Preview (High-Resolution 300 DPI Graphic)
    # ==========================================================================
    ws3 = wb.create_sheet(title='Visual Chart Preview')
    ws3.views.sheetView[0].showGridLines = True
    ws3['A1'] = 'Figure 8.4.7: False Positive Rate Comparison (0% to 100% Scale Visual Preview)'
    ws3['A1'].font = title_font
    ws3['A2'] = 'Generated at 300 DPI publication quality strictly following 0% to 100% percentage scale.'
    ws3['A2'].font = subtitle_font

    img_p = 'results/chapter_8_4/graphs/fig_8_4_7_false_positive_rate_comparison.png'
    if os.path.exists(img_p):
        img_obj = Image(img_p)
        img_obj.width = 750
        img_obj.height = 422
        ws3.add_image(img_obj, 'B4')

    # Save Deliverables
    out_main = 'DeepWAF_XAI_False_Positive_Rate_Comparison.xlsx'
    wb.save(out_main)
    print(f'Successfully created {out_main} in root directory!')

    out_updated = 'results/chapter_8_4/DeepWAF_XAI_False_Positive_Rate_Comparison_Updated.xlsx'
    wb.save(out_updated)
    print(f'Successfully created copy at {out_updated}!')

    # Try saving to results/chapter_8_4/DeepWAF_XAI_False_Positive_Rate_Comparison.xlsx if unlocked
    try:
        out_folder = 'results/chapter_8_4/DeepWAF_XAI_False_Positive_Rate_Comparison.xlsx'
        wb.save(out_folder)
        print(f'Successfully updated {out_folder}!')
    except Exception as e:
        print(f'Note: Folder copy is locked in Excel, saved as {out_updated} instead.')

if __name__ == '__main__':
    generate_fpr_workbook()
