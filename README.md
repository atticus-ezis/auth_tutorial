# Django Hybrid Auth Cookiecutter

This repository is a Cookiecutter template that scaffolds a Django project preconfigured with hybrid JWT/cookie authentication, dj-rest-auth, and django-allauth integrations.

## Getting Started

1. Install Cookiecutter if you do not have it yet:

   ```bash
   pipx install cookiecutter
   ```

2. Generate a new project from this template:
   form your project directory...

   ```bash
   cookiecutter gh:/atticus-ezis/django_hybird_auth_cookiecutter.git
   or
   cookiecutter https://github.com/atticus-ezis/django_hybird_auth_cookiecutter.git
   ```

3. Answer the prompts to customise project metadata such as the project name, author information, secret key, and frontend domain.

4. Run 'uv sync' in terminal
5. Activate the '.venv' uv creates
6. run 'python manage.py migrate'
7. run 'pytest' to generate the user authentication testcases.
8. start server 'python manage.py runserver'
9. View APIs at
   http://127.0.0.1:8000/api/docs/
   or
   http://127.0.0.1:8000/api/redoc/

## Template Structure

- `cookiecutter.json` – default context values and prompts.
- `{{cookiecutter.project_slug}}/` – Django project skeleton rendered with your answers.
  - `manage.py`, `pyproject.toml`, and pytest configuration.
  - `{{cookiecutter.project_slug}}/` – Django settings, URLs, and ASGI/WSGI entrypoints.
  - `users/` – pluggable authentication app with API endpoints, mixins, and tests.

## Features

- `API Documentation with Swagger`
- `Error logging`
- `pe-commit formatting with ruff`
- `pytests included`

## Next Steps

- Update the generated project's dependency pins or settings to match your deployment environment.
- Replace placeholder secrets before deploying to production.
- Add optional hooks in `hooks/` if you want to automate post-generation tasks such as virtualenv creation or git initialisation.

Happy building!
