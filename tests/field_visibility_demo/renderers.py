import csv

from rest_framework.renderers import BaseRenderer

from .visibility import FieldVisibility


class CSVCasesRenderer(BaseRenderer):
    """
    CSV export.

    Columns are taken from the visibility policy for the caller, so an export
    can never contain a field that the JSON representation would have hidden.
    Values are read off the *serialized* rows, guaranteeing the export and the
    API response are produced from the same visibility-filtered data.
    """

    media_type = 'text/csv'
    format = 'csv'
    charset = 'utf-8'

    def render(self, data, accepted_media_type=None, renderer_context=None):
        renderer_context = renderer_context or {}
        request = renderer_context.get('request')
        visibility = FieldVisibility.from_request(request)
        columns = list(visibility.visible_fields())

        if isinstance(data, dict) and 'results' in data:
            rows = data['results']
        elif isinstance(data, list):
            rows = data
        else:
            rows = []

        import io
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, '') for key in columns})
        return buffer.getvalue()
