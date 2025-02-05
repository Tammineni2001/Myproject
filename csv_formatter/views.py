from flask import request, jsonify
from flask.views import MethodView
import pandas as pd
import io

class FormatCSVView(MethodView):
    def post(self):
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        column_name = request.form.get('column_name')
        new_format = request.form.get('new_format')

        if not column_name or not new_format:
            return jsonify({'error': 'Column name and format are required'}), 400

        try:
            df = pd.read_csv(io.StringIO(file.stream.read().decode('utf-8')))

            if column_name not in df.columns:
                return jsonify({'error': f'Column "{column_name}" not found in CSV'}), 400

            df[column_name] = df[column_name].astype(str).apply(lambda x: new_format.format(x))

            formatted_csv = df.to_csv(index=False)
            return jsonify({'formatted_csv': formatted_csv})

        except Exception as e:
            return jsonify({'error': str(e)}), 500
