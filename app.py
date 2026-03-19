from flask import Flask, request, render_template_string

app = Flask(__name__)

HTML = '''
<!DOCTYPE html>
<html>
<head>
<title>Sentinel Simple</title>
<style>
body {font-family: Arial; background:#0f172a; color:white; padding:20px;}
textarea {width:100%; height:150px;}
button {padding:10px 20px; margin-top:10px;}
.card {background:#1e293b; padding:15px; margin-top:15px; border-radius:10px;}
</style>
</head>
<body>

<h2>Sentinel Verify (Simple)</h2>

<form method="post">
<textarea name="targets" placeholder="Enter targets..."></textarea><br>
<button type="submit">Scan</button>
</form>

{% if results %}
<h3>Results</h3>
{% for r in results %}
<div class="card">
<b>{{r}}</b><br>
Detected: Phone / OTP (demo)
</div>
{% endfor %}
{% endif %}

</body>
</html>
'''

@app.route('/', methods=['GET','POST'])
def index():
    results = []
    if request.method == 'POST':
        data = request.form.get('targets','')
        results = [x.strip() for x in data.split('\n') if x.strip()]
    return render_template_string(HTML, results=results)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
