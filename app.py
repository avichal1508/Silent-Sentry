import pandas as pd
import plotly.express as px
import plotly.io as pio
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from wordcloud import WordCloud
import io
import base64
from functools import wraps
import pickle 

# Load and clean dataset
df = pd.read_json("dataset.jsonl")  
with open("payload_model.pkl", "rb") as f:
    model=pickle.load(f)
with open("vectorizer.pkl", "rb") as f:
    vectorizer=pickle.load(f)
with open("label_encoder.pkl", "rb") as f:
    label_encoder=pickle.load(f)
# Data cleaning logic
missing_percentages = (df.isnull().sum() / len(df)) * 100
cols_to_drop = missing_percentages[missing_percentages > 70].index
df_cleaned = df.drop(columns=cols_to_drop)

for col in df_cleaned.columns:
    if df_cleaned[col].isnull().any():
        if pd.api.types.is_numeric_dtype(df_cleaned[col]):
            median_value = df_cleaned[col].median()
            df_cleaned[col].fillna(median_value, inplace=True)
        else:
            df_cleaned[col].fillna("Unknown", inplace=True)

app = Flask(__name__)
app.secret_key = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

with app.app_context(): 
    db.create_all()

@app.context_processor
def inject_kpis():
    total_attacks = len(df)
    unique_types = df['type'].nunique() if 'type' in df.columns else 0
    severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    # Handle numeric conversion of severity for stats
    df_temp = df.copy()
    df_temp['severity_num'] = df_temp['severity'].map(severity_map).fillna(0)
    avg_sev_score = df_temp['severity_num'].mean()
    return dict(
        total_attacks=f"{total_attacks:,}",
        unique_types=unique_types,
        avg_severity=f"{avg_sev_score:.2f}",
        uptime="99.9%"
    )

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not name or len(name.strip())<2:
            flash('Name must be at least 2 characters long.', 'error')
            return redirect(url_for('register'))
        
        if not email or '@' not in email:
            flash('Please enter a valid email address.', 'error')
            return redirect(url_for('register'))
        
        if len(password)<8 or not any(char.isdigit() for char in password)\
              or not any(char.isalpha() for char in password) or not any(not char.isalnum()\
                                                                          for char in password):
            flash('Password must be at least 8 characters long and contain letters, numbers, and special characters.', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please log in.', 'error')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(name=name.strip(), email=email.strip(), password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
            return redirect(url_for('register'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            flash('Login successful!', 'success')
            return redirect(url_for('attack_frequency_severity'))
        else:
            flash('Invalid email or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please sign in to access dashboard pages.', 'error')
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapped_view

@app.route('/upload')
def upload():
    return render_template('upload.html')
        
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/Attack_Frequency_Severity')
@login_required
def attack_frequency_severity():
    severity_options = ['critical', 'high', 'medium', 'low']
    attack_options = sorted(df['type'].dropna().unique().tolist())

    severity1 = request.args.get('severity1', 'all')
    attack2 = request.args.get('attack2', 'all')
    attack3 = request.args.get('attack3', 'all')
    attack4 = request.args.get('attack4', 'all')
    severity5 = request.args.get('severity5', 'all')

    df_bar = df[df['severity'] == severity1] if severity1 != 'all' else df
    df_stacked = df[df['type'] == attack2] if attack2 != 'all' else df
    df_pie = df[df['type'] == attack3] if attack3 != 'all' else df
    df_treemap = df[df['type'] == attack4] if attack4 != 'all' else df
    df_donut = df[df['severity'] == severity5] if severity5 != 'all' else df

    fig_bar = px.histogram(df_bar, x='type', title="Count of Attacks by Type")
    bar_html = pio.to_html(fig_bar, full_html=False)
    fig_stacked = px.histogram(df_stacked, x='type', color='severity', title="Attack Type vs Severity", barmode='stack')
    stacked_html = pio.to_html(fig_stacked, full_html=False)
    fig_pie = px.pie(df_pie, names='severity', title="Severity Distribution")
    pie_html = pio.to_html(fig_pie, full_html=False)
    fig_treemap = px.treemap(df_treemap, path=['type','context'], title="Attack Type & Context Treemap")
    treemap_html = pio.to_html(fig_treemap, full_html=False)
    fig_donut = px.pie(df_donut, names='type', hole=0.4, title="Attack Type Distribution (Donut Chart)")
    donut_html = pio.to_html(fig_donut, full_html=False)
    return render_template(
        "Attack_Frequency_Severity.html",
        bar_html=bar_html,
        stacked_html=stacked_html,
        pie_html=pie_html,
        treemap_html=treemap_html,
        donut_html=donut_html,
        severity_options=severity_options,
        attack_options=attack_options,
        severity1=severity1,
        attack2=attack2,
        attack3=attack3,
        attack4=attack4,
        severity5=severity5,
    )

@app.route("/Sequential_Escalation")
@login_required
def sequential_escalation():
    severity_options = ['critical', 'high', 'medium', 'low']
    attack_options = sorted(df['type'].dropna().unique().tolist())

    attack1 = request.args.get('attack1', 'all')
    attack2 = request.args.get('attack2', 'all')
    severity3 = request.args.get('severity3', 'all')
    severity4 = request.args.get('severity4', 'all')
    attack5 = request.args.get('attack5', 'all')

    df_timeline = df[df['type'] == attack1] if attack1 != 'all' else df
    df_step = df[df['type'] == attack2] if attack2 != 'all' else df
    df_scatter = df[df['severity'] == severity3] if severity3 != 'all' else df
    df_box = df[df['severity'] == severity4] if severity4 != 'all' else df
    df_heatmap = df[df['type'] == attack5] if attack5 != 'all' else df

    fig_timeline = px.line(df_timeline, x='id', y='severity', title="Severity Progression over Attack IDs")
    timeline_html = pio.to_html(fig_timeline, full_html=False)
    fig_step = px.line(df_step, x='id', y='severity', title="Escalation Path (Step Chart)")
    fig_step.update_traces(line_shape="hv")
    step_html = pio.to_html(fig_step, full_html=False)
    fig_scatter = px.scatter(df_scatter, x='id', y='severity', color='type', title="Severity Progression (Scatter Plot)")
    scatter_html = pio.to_html(fig_scatter, full_html=False)
    fig_box = px.box(df_box, x='severity', y='id', title="Severity Distribution across IDs")
    box_html = pio.to_html(fig_box, full_html=False)
    freq = df_heatmap.groupby(['id','severity']).size().reset_index(name='count')
    fig_heatmap = px.density_heatmap(freq, x='id', y='severity', z='count', color_continuous_scale="Viridis", title="ID vs Severity Frequency Heatmap")
    heatmap_html = pio.to_html(fig_heatmap, full_html=False)
    return render_template(
        "Sequential_Escalation.html",
        timeline_html=timeline_html,
        step_html=step_html,
        scatter_html=scatter_html,
        box_html=box_html,
        heatmap_html=heatmap_html,
        severity_options=severity_options,
        attack_options=attack_options,
        attack1=attack1,
        attack2=attack2,
        severity3=severity3,
        severity4=severity4,
        attack5=attack5,
    )

@app.route('/Payload_Analysis_Page')
@login_required
def payload_analysis():
    severity_options = ['critical', 'high', 'medium', 'low']
    attack_options = sorted(df['type'].dropna().unique().tolist())

    severity1 = request.args.get('severity1', 'all')
    attack1 = request.args.get('attack1', 'all')
    severity2 = request.args.get('severity2', 'all')
    attack3 = request.args.get('attack3', 'all')
    attack4 = request.args.get('attack4', 'all')
    severity5 = request.args.get('severity5', 'all')

    df_payload = df.copy()
    df_payload['payload_length'] = df_payload['payload'].apply(lambda x: len(str(x)))

    df1 = df_payload
    if severity1 != 'all':
        df1 = df1[df1['severity'] == severity1]
    if attack1 != 'all':
        df1 = df1[df1['type'] == attack1]

    df2 = df_payload[df_payload['severity'] == severity2] if severity2 != 'all' else df_payload
    df3 = df_payload[df_payload['type'] == attack3] if attack3 != 'all' else df_payload
    df4 = df_payload[df_payload['type'] == attack4] if attack4 != 'all' else df_payload
    df5 = df_payload[df_payload['severity'] == severity5] if severity5 != 'all' else df_payload

    fig1 = px.box(df1, x="severity", y="payload_length", color="severity", title="Payload Length vs Severity (Box Plot)")
    fig2 = px.violin(df2, x="severity", y="payload_length", color="severity", box=True, title="Payload Length Distribution by Severity (Violin Plot)")
    fig3 = px.histogram(df3, x="payload_length", nbins=30, title="Payload Length Frequency (Histogram)")
    top_payloads = df4['payload'].value_counts().nlargest(10).reset_index()
    top_payloads.columns = ['payload', 'count']
    fig4 = px.bar(top_payloads, x='payload', y='count', title="Top Payload Frequency")
    fig5 = px.line(df5, x="id", y="payload_length", title="Payload Length vs ID")
    graph1 = pio.to_html(fig1, full_html=False)
    graph2 = pio.to_html(fig2, full_html=False)
    graph3 = pio.to_html(fig3, full_html=False)
    graph4 = pio.to_html(fig4, full_html=False)
    graph5 = pio.to_html(fig5, full_html=False)
    return render_template(
        "payload_analysis_page.html",
        graph1=graph1,
        graph2=graph2,
        graph3=graph3,
        graph4=graph4,
        graph5=graph5,
        severity_options=severity_options,
        attack_options=attack_options,
        severity1=severity1,
        attack1=attack1,
        severity2=severity2,
        attack3=attack3,
        attack4=attack4,
        severity5=severity5,
    )

@app.route('/Threat_Score_Page')
@login_required
def threat_score():
    severity_options = ['critical', 'high', 'medium', 'low']
    attack_options = sorted(df['type'].dropna().unique().tolist())

    severity1 = request.args.get('severity1', 'all')
    attack1 = request.args.get('attack1', 'all')
    attack2 = request.args.get('attack2', 'all')
    attack3 = request.args.get('attack3', 'all')
    severity4 = request.args.get('severity4', 'all')
    attack4 = request.args.get('attack4', 'all')
    severity5 = request.args.get('severity5', 'all')

    severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    df_work = df.copy()
    df_work['severity_score'] = df_work['severity'].map(severity_map).fillna(0)

    df1 = df_work
    if severity1 != 'all':
        df1 = df1[df1['severity'] == severity1]
    if attack1 != 'all':
        df1 = df1[df1['type'] == attack1]

    df2 = df_work[df_work['type'] == attack2] if attack2 != 'all' else df_work
    df3 = df_work[df_work['type'] == attack3] if attack3 != 'all' else df_work

    df4 = df_work
    if attack4 != 'all':
        df4 = df4[df4['type'] == attack4]
    if severity4 != 'all':
        df4 = df4[df4['severity'] == severity4]

    df5 = df_work[df_work['severity'] == severity5] if severity5 != 'all' else df_work

    type_avg = df1.groupby('type', as_index=False)['severity_score'].mean()
    context_avg = df2.groupby(['type', 'context'], as_index=False)['severity_score'].mean()
    pivot = context_avg.pivot(index='type', columns='context', values='severity_score').fillna(0)
    severity_avg = df3.groupby('severity', as_index=False)['severity_score'].mean()
    line_df = df4.reset_index().rename(columns={'index': 'record_index'})
    sunburst_df = df5

    fig_radar = px.line_polar(type_avg, r='severity_score', theta='type', line_close=True, markers=True, title='Threat Score Page - Attack Type vs Average Severity')
    radar_html = pio.to_html(fig_radar, full_html=False)
    fig_heatmap = px.imshow(pivot, labels={'x': 'Context', 'y': 'Attack Type', 'color': 'Avg Severity Score'}, x=pivot.columns, y=pivot.index, color_continuous_scale='Viridis', text_auto=True)
    heatmap_html = pio.to_html(fig_heatmap, full_html=False)
    fig_bar = px.bar(severity_avg, x='severity', y='severity_score', title='Average Threat Score by Severity', labels={'severity_score': 'Average Severity Score', 'severity': 'Severity'})
    bar_html = pio.to_html(fig_bar, full_html=False)
    fig_line = px.line(line_df, x='record_index', y='severity_score', title='Threat Severity over Records', labels={'record_index': 'Record Index', 'severity_score': 'Severity Score'})
    line_html = pio.to_html(fig_line, full_html=False)
    fig_sunburst = px.sunburst(
        sunburst_df,
        path=['severity', 'type'],
        title='Detailed Threat Hierarchy (Severity > Type)',
        color='severity',
        color_discrete_map={'low':'#10b981', 'medium':'#f59e0b', 'high':'#ef4444', 'critical':'#7f1d1d'},
        template='plotly_dark'
    )
    fig_sunburst.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font_color='#94a3b8',
        margin=dict(t=50, l=0, r=0, b=0)
    )
    sunburst_html = pio.to_html(fig_sunburst, full_html=False)
    return render_template(
        'threat_score_page.html',
        radar_html=radar_html,
        heatmap_html=heatmap_html,
        bar_html=bar_html,
        line_html=line_html,
        sunburst_html=sunburst_html,
        severity_options=severity_options,
        attack_options=attack_options,
        severity1=severity1,
        attack1=attack1,
        attack2=attack2,
        attack3=attack3,
        severity4=severity4,
        attack4=attack4,
        severity5=severity5,
    )



if __name__ == '__main__':
    app.run(debug=True)