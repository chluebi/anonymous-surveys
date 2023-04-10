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
            if question['options']['textother']:
                choices['Other'] = 0
            choices['No Answer'] = 0

            for result in results['results']:
                if result[i] == '':
                    choices['No Answer'] += 1
                elif result[i] in question['options']['choices']:
                    choices[result[i]] += 1
                else:
                    choices['Other'] += 1

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

    additional_plots = schema['additional-plots']

    for i, plot in enumerate(additional_plots, len(schema['questions'])):
        df = pd.DataFrame(results['results'], columns=[q['text'] for q in schema['questions']])

        if plot['type'] == '2d-heatmap':
            df = df[[plot['questions'][0], plot['questions'][1]]]
            df['count'] = 1

            qx = [q for q in schema['questions'] if plot['questions'][0] == q['text']][0]
            qy = [q for q in schema['questions'] if plot['questions'][1] == q['text']][0]

            # getting the cross product of all options
            dfqx = pd.DataFrame({plot['questions'][0]:qx['options']['choices']})
            dfqy = pd.DataFrame({plot['questions'][1]:qy['options']['choices']})

            df_empty = dfqx.merge(dfqy, how='cross')
            df_empty['count'] = 0

            df = pd.concat([df, df_empty])

            fig = px.density_heatmap(df, 
                        x=plot['questions'][0],
                        y=plot['questions'][1],
                        z='count',
                        title=plot['questions'][0] + ' vs. ' + plot['questions'][1], 
                        category_orders={
                            plot['questions'][0]:qx['options']['choices'][::-1],
                            plot['questions'][1]:qy['options']['choices']
                        },
                        color_continuous_scale=px.colors.sequential.Burgyl,
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


    correlation_plots = []

    if schema['correlate-plots']:
        for q1 in schema['questions']:
            for q2 in schema['questions']:
                if q1['type'] == q2['type'] == 'multiple-choice' and q1['text'] != q2['text']:
                    correlation_plots.append({
                        'type':'2d-heatmap',
                        'questions':[q1['text'], q2['text']]
                    })

    for plot in correlation_plots:
        df = pd.DataFrame(results['results'], columns=[q['text'] for q in schema['questions']])

        if plot['type'] == '2d-heatmap':
            df = df[[plot['questions'][0], plot['questions'][1]]]
            df['count'] = 1

            qx = [q for q in schema['questions'] if plot['questions'][0] == q['text']][0]
            qy = [q for q in schema['questions'] if plot['questions'][1] == q['text']][0]

            qx_index = schema['questions'].index(qx)
            qy_index = schema['questions'].index(qy)

            # getting the cross product of all options
            dfqx = pd.DataFrame({plot['questions'][0]:qx['options']['choices']})
            dfqy = pd.DataFrame({plot['questions'][1]:qy['options']['choices']})

            df_empty = dfqx.merge(dfqy, how='cross')
            df_empty['count'] = 0

            df = pd.concat([df, df_empty])

            fig = px.density_heatmap(df, 
                        x=plot['questions'][0],
                        y=plot['questions'][1],
                        z='count',
                        title=plot['questions'][0] + ' vs. ' + plot['questions'][1], 
                        category_orders={
                            plot['questions'][0]:qx['options']['choices'][::-1],
                            plot['questions'][1]:qy['options']['choices']
                        },
                        color_continuous_scale=px.colors.sequential.Burgyl,
                        template='plotly_dark_custom')
            
            file_name = f'{plot_folder}/{qx_index}v{qy_index}.html'
            
            # stand-alone file only
            fig.write_html(file_name, 
                            include_plotlyjs='cdn',
                            full_html=True)