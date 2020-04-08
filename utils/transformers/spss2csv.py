import json
import os

import click
import pandas as pd
import pyreadstat


def parse_metadata(filename):
    data = {}
    _, meta = pyreadstat.read_sav(filename)
    data['column_names'] = meta.column_names
    data['column_labels'] = meta.column_labels
    data['column_names_to_labels'] = meta.column_names_to_labels
    data['number_rows'] = meta.number_rows
    data['number_columns'] = meta.number_columns
    data['file_label'] = meta.file_label
    data['notes'] = meta.notes
    data['variable_value_labels'] = meta.variable_value_labels
    data['value_labels'] = meta.value_labels
    data['variable_to_label'] = meta.variable_to_label
    data['original_variable_types'] = meta.original_variable_types
    data['table_name'] = meta.table_name
    data['missing_user_values'] = meta.missing_user_values
    data['variable_alignment'] = meta.variable_alignment
    data['variable_storage_width'] = meta.variable_storage_width
    data['variable_display_width'] = meta.variable_display_width

    return data


@click.command()
@click.argument('filename', type=click.Path(exists=True))
@click.option('--sep', default=';', help='The delimiter to be used')
@click.option('--encoding', default='utf-8', help='Encoding of output file')
@click.option('--metadata', is_flag=True)
def convert(filename, sep, encoding, metadata):
    """A simple CLI for converting spss to csv and
    optionally extracting metadata to json"""

    basename = os.path.basename(filename)
    name = os.path.splitext(basename)
    df = pd.read_spss(filename)
    df.to_csv(f'{name[0]}.csv', sep=sep, encoding=encoding)
    if metadata:
        with open(f'{name[0]}_meta.json', 'w') as f:
            f.write(json.dumps(parse_metadata(filename)))


if __name__ == "__main__":
    convert()
