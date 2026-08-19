"""
Hàm trả về CSS style theo mức độ nguy hiểm.
High/Critical → đỏ | Medium → vàng | Low → xanh
"""


def border_style(severity):
    """Trả về CSS border-left color cho card theo severity."""
    styles = {
        'critical': 'border-left-color: #f85149;',
        'high': 'border-left-color: #f85149;',
        'medium': 'border-left-color: #d29922;',
        'low': 'border-left-color: #58a6ff;',
    }
    return styles.get(severity.lower(), 'border-left-color: #30363d;')


def title_color(severity):
    """Trả về màu chữ cho tiêu đề theo severity."""
    colors = {
        'critical': '#f85149',
        'high': '#f85149',
        'medium': '#d29922',
        'low': '#58a6ff',
    }
    return colors.get(severity.lower(), '#e6edf3')


def badge_class(severity):
    """Trả về CSS class cho badge (hàm đồng bộ với render_finding_badge)."""
    classes = {
        'critical': 'sev-critical',
        'high': 'sev-high',
        'medium': 'sev-medium',
        'low': 'sev-low',
    }
    return classes.get(severity.lower(), 'sev-low')