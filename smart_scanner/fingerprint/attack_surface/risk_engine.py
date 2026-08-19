"""
RiskEngine — dùng cho passive-scan risk trong app.py.

Trước đây tự tính điểm bằng công thức riêng (100 - severity_count*weight),
là 1 trong 4 công thức risk score không đồng nhất từng tồn tại trong repo.
Nay delegate toàn bộ phép tính sang MultiFactorRiskEngine.calculate_from_findings
(report_exporters.py) — nguồn tính toán duy nhất — chỉ còn giữ shape trả về
cũ ({"score", "rating", "metrics"}, quy ước "score cao = an toàn") để không
phải sửa app.py.
"""
from report_exporters import MultiFactorRiskEngine


class RiskEngine:
    @staticmethod
    def calculate(findings):
        result = MultiFactorRiskEngine.calculate_from_findings(findings)

        # Quy ước cũ: score cao = an toàn (ngược với risk_score của
        # MultiFactorRiskEngine, nơi số cao = nguy hiểm) — quy đổi lại.
        safety_score = round(max(0.0, 100.0 - result['risk_score']))

        if safety_score >= 85:
            rating = "A - An Toàn"
        elif safety_score >= 70:
            rating = "B - Nguy Cơ Thấp"
        elif safety_score >= 50:
            rating = "C - Trung Bình"
        else:
            rating = "D - Nguy Cơ Cao"

        counts = result['counts']
        return {
            "score": safety_score,
            "rating": rating,
            "metrics": {
                "critical": counts['critical'],
                "high": counts['high'],
                "medium": counts['medium'],
                "low": counts['low'],
            },
        }
