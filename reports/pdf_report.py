from weasyprint import HTML
import os

class PDFReportGenerator:
    def __init__(self):
        pass
    
    def generate_from_html(self, html_file, output_file):
        """
        Generate PDF from HTML file
        """
        try:
            HTML(filename=html_file).write_pdf(output_file)
            return output_file
        except Exception as e:
            raise Exception(f"Error generating PDF: {e}")
    
    def generate_report(self, scan_results, output_file):
        """
        Generate PDF report from scan results
        """
        # First generate HTML
        from reports.html_report import HTMLReportGenerator
        
        html_gen = HTMLReportGenerator()
        temp_html = output_file.replace('.pdf', '_temp.html')
        html_gen.generate_report(scan_results, temp_html)
        
        # Convert to PDF
        self.generate_from_html(temp_html, output_file)
        
        # Clean up temp file
        if os.path.exists(temp_html):
            os.remove(temp_html)
        
        return output_file
