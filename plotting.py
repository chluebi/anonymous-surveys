import json
import os

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio

# changing template
plotly_template = pio.templates["plotly_dark"]

pio.templates["plotly_dark_custom"] = pio.templates["plotly_dark"]
pio.templates["plotly_dark_custom"].update({'layout': {
    # transparent background
    'paper_bgcolor': 'rgba(39, 39, 52, 255)',
    'plot_bgcolor': 'rgba(39, 39, 52, 255)'
}})


def update_plots(schema):
    name = schema['folder']
    file = f'data/{name}/results.json'

    with open(file, 'r') as f:
        results = json.load(f)

    plot_folder = f'data/{name}/plots'
    if not os.path.exists(plot_folder):
        os.mkdir(plot_folder)

    with open(f'{plot_folder}/all.html', 'w+') as f:
        f.write('')

    for i, question in enumerate(schema['questions']):
        choices = {}
        div_string = ''

        if question['type'] == 'multiple-choice':
            choices = {choice:0 for choice in question['options']['choices']}
            choices['No Answer'] = 0

            for result in results['results']:
                if result[i] == '':
                    choices['No Answer'] += 1
                else:
                    choices[result[i]] += 1

        elif question['type'] == 'text':
            choices = {'Answered':0, 'No Answer':0}

            for result in results['results']:
                if result[i] == '':
                    choices['No Answer'] += 1
                else:
                    choices['Answered'] += 1

        df = pd.DataFrame({'choice':list(choices.keys()), 'count':list(choices.values())})
        
        fig = px.bar(df, y='count', x='choice', title=question['text'], 
                        labels=list(choices.keys()),
                        category_orders={'choice':list(choices.keys())},
                        color='choice',
                        color_discrete_sequence=px.colors.sequential.Burgyl,
                        template='plotly_dark_custom')

        file_name = f'{plot_folder}/{i}.html'
        # div
        fig.write_html(file_name, 
                        include_plotlyjs=False,
                        full_html=False)
        
        with open(file_name, 'r') as f:
            div_string = f.read()
        
        # stand-alone file
        fig.write_html(file_name, 
                        include_plotlyjs='cdn',
                        full_html=True)
        
        with open(f'{plot_folder}/all.html', 'a') as f:
            f.write(div_string + '\n')