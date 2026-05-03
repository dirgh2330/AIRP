from fpdf import FPDF
import datetime

class IRReportGenerator:
    def __init__(self):
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)

    def generate(self, incident_data, output_path):
        self.pdf.add_page()

        # Header bar
        self.pdf.set_font("Arial", "B", 18)
        self.pdf.set_fill_color(26, 82, 118)
        self.pdf.set_text_color(255, 255, 255)
        self.pdf.cell(0, 15, "AIRP - Incident Response Report", ln=True, fill=True)

        # Metadata
        self.pdf.set_text_color(0, 0, 0)
        self.pdf.set_font("Arial", "B", 12)
        self.pdf.ln(5)
        self.pdf.cell(0, 10, f"Incident Type: {incident_data['incident_type']}", ln=True)
        self.pdf.cell(0, 10, f"Analyst: {incident_data['analyst']}", ln=True)
        self.pdf.cell(0, 10, f"Timestamp: {incident_data['timestamp']}", ln=True)
        self.pdf.cell(0, 10, f"Status: {incident_data['status']}", ln=True)
        self.pdf.cell(0, 10, f"Severity: {incident_data['severity']}", ln=True)

        # Evidence
        self.pdf.ln(5)
        self.pdf.set_font("Arial", "B", 13)
        self.pdf.cell(0, 10, "Evidence Collected:", ln=True)
        self.pdf.set_font("Arial", size=11)
        for item in incident_data.get("evidence", []):
            self.pdf.cell(0, 8, f"  - {item}", ln=True)

        # Actions
        self.pdf.ln(3)
        self.pdf.set_font("Arial", "B", 13)
        self.pdf.cell(0, 10, "Response Actions Taken:", ln=True)
        self.pdf.set_font("Arial", size=11)
        for i, action in enumerate(incident_data.get("actions", []), 1):
            self.pdf.cell(0, 8, f"  {i}. {action}", ln=True)

        # Recommendations
        self.pdf.ln(3)
        self.pdf.set_font("Arial", "B", 13)
        self.pdf.cell(0, 10, "Recommendations:", ln=True)
        self.pdf.set_font("Arial", size=11)
        for item in incident_data.get("recommendations", []):
            self.pdf.cell(0, 8, f"  - {item}", ln=True)

        self.pdf.output(output_path)
        print(f"[AIRP] Report saved: {output_path}")