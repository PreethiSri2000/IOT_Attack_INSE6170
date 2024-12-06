import os
from django.conf import settings
from django.core.management import execute_from_command_line
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.db import models
from django.forms import ModelForm
from django.urls import path

# Django Settings
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
settings.configure(
    DEBUG=True,
    SECRET_KEY='single_file_secret_key',
    ROOT_URLCONF=__name__,
    ALLOWED_HOSTS=['*'],
    INSTALLED_APPS=[
        'django.contrib.contenttypes',
        'django.contrib.staticfiles',
    ],
    DATABASES={
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
        }
    },
    STATIC_URL='/static/',
    TEMPLATES=[{
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
    }],
    MEDIA_URL='/media/',
    MEDIA_ROOT=os.path.join(BASE_DIR, 'media'),
)

# Models
from django.apps import AppConfig


class SingleFileAppConfig(AppConfig):
    name = 'single_file_app'


class FileRecord(models.Model):
    mac = models.CharField(max_length=17)
    filename = models.CharField(max_length=255, primary_key=True)
    summary = models.TextField()
    time = models.DateTimeField()

    def __str__(self):
        return self.filename


# Forms
class EditFileNameForm(ModelForm):
    class Meta:
        model = FileRecord
        fields = ['filename']


# Views
def history_view(request, mac):
    files = FileRecord.objects.filter(mac=mac).order_by('-time')
    return render(request, 'history.html', {'files': files})


def edit_file(request, filename):
    file = get_object_or_404(FileRecord, filename=filename)
    if request.method == 'POST':
        form = EditFileNameForm(request.POST, instance=file)
        if form.is_valid():
            form.save()
            return redirect('history', mac=file.mac)
    else:
        form = EditFileNameForm(instance=file)
    return render(request, 'edit_file.html', {'form': form, 'file': file})


def delete_file(request, filename):
    file = get_object_or_404(FileRecord, filename=filename)
    try:
        os.remove(os.path.join(settings.MEDIA_ROOT, 'packet-captures', file.filename))
        file.delete()
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    return redirect('history', mac=file.mac)


def download_file(request, filename):
    file_path = os.path.join(settings.MEDIA_ROOT, 'packet-captures', filename)
    if os.path.exists(file_path):
        with open(file_path, 'rb') as file:
            response = HttpResponse(file.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
    else:
        return JsonResponse({'error': 'File not found'}, status=404)


# URL Patterns
urlpatterns = [
    path('<str:mac>/', history_view, name='history'),
    path('edit/<str:filename>/', edit_file, name='edit_file'),
    path('delete/<str:filename>/', delete_file, name='delete_file'),
    path('download/<str:filename>/', download_file, name='download_file'),
]

# Templates
os.makedirs('templates', exist_ok=True)
if not os.path.exists('templates/history.html'):
    with open('templates/history.html', 'w') as f:
        f.write("""
<!DOCTYPE html>
<html>
<head>
    <title>History</title>
</head>
<body>
    <h1>Files for MAC: {{ files.0.mac }}</h1>
    <table border="1">
        <tr>
            <th>Time</th>
            <th>Filename</th>
            <th>Summary</th>
            <th>Actions</th>
        </tr>
        {% for file in files %}
        <tr>
            <td>{{ file.time }}</td>
            <td>{{ file.filename }}</td>
            <td>{{ file.summary }}</td>
            <td>
                <a href="{% url 'edit_file' file.filename %}">Edit</a>
                <a href="{% url 'delete_file' file.filename %}">Delete</a>
                <a href="{% url 'download_file' file.filename %}">Download</a>
            </td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
""")
if not os.path.exists('templates/edit_file.html'):
    with open('templates/edit_file.html', 'w') as f:
        f.write("""
<!DOCTYPE html>
<html>
<head>
    <title>Edit File</title>
</head>
<body>
    <h1>Edit File: {{ file.filename }}</h1>
    <form method="post">
        {% csrf_token %}
        {{ form.as_p }}
        <button type="submit">Save</button>
    </form>
</body>
</html>
""")

# Run Server
if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', __name__)
    execute_from_command_line(['manage.py', 'migrate'])
    execute_from_command_line(['manage.py', 'runserver'])
