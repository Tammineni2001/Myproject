from flask import Blueprint

csv_formatter_bp = Blueprint('csv_formatter_bp', __name__)

from csv_formatter.views import FormatCSVView

csv_formatter_bp.add_url_rule('/format_csv', view_func=FormatCSVView.as_view('format_csv'))
