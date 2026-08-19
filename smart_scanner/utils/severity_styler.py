"""
Hàm trả về CSS style theo mức độ nguy hiểm.
High/Critical → đỏ | Medium → vàng | Low → xanh
"""


def border_style(severity):
    """Trả về CSS border-left color cho card theo severity."""
    styles = {
        'critical': 'border-left-color: #cf222e;',
        'high': 'border-left-color: #cf222e;',
        'medium': 'border-left-color: #9a6700;',
        'low': 'border-left-color: #0969da;',
    }
    return styles.get(severity.lower(), 'border-left-color: #d0d7de;')


def title_color(severity):
    """Trả về màu chữ cho tiêu đề theo severity."""
    colors = {
        'critical': '#cf222e',
        'high': '#cf222e',
        'medium': '#9a6700',
        'low': '#0969da',
    }
    return colors.get(severity.lower(), '#1f2328')


def badge_class(severity):
    """Trả về CSS class cho badge (hàm đồng bộ với render_finding_badge)."""
    classes = {
        'critical': 'sev-critical',
        'high': 'sev-high',
        'medium': 'sev-medium',
        'low': 'sev-low',
    }
    return classes.get(severity.lower(), 'sev-low')