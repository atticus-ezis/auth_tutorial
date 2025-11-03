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
   cookiecutter gh:/atticus-ezis/auth_tutorial.git
   or
   cookiecutter https://github.com/atticus-ezis/auth_tutorial.git
   ```

3. Answer the prompts to customise project metadata such as the project name, author information, secret key, and frontend domain.

4. Run 'uv sync' in terminal
5. Activate the '.venv' uv creates
6. run 'pytest' inside .venv to generate the user authentication testcases.

## Template Structure

- `cookiecutter.json` – default context values and prompts.
- `{{cookiecutter.project_slug}}/` – Django project skeleton rendered with your answers.
  - `manage.py`, `pyproject.toml`, and pytest configuration.
  - `{{cookiecutter.project_slug}}/` – Django settings, URLs, and ASGI/WSGI entrypoints.
  - `users/` – pluggable authentication app with API endpoints, mixins, and tests.

## Next Steps

- Update the generated project's dependency pins or settings to match your deployment environment.
- Replace placeholder secrets before deploying to production.
- Add optional hooks in `hooks/` if you want to automate post-generation tasks such as virtualenv creation or git initialisation.

Happy building!
