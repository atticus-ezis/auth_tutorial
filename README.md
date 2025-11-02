# Django Hybrid Auth Cookiecutter

This repository is a Cookiecutter template that scaffolds a Django project preconfigured with hybrid JWT/cookie authentication, dj-rest-auth, and django-allauth integrations.

## Getting Started

1. Install Cookiecutter if you do not have it yet:

   ```bash
   pip install cookiecutter
   ```

2. Generate a new project from this template:

   ```bash
   cookiecutter /path/to/this/repository
   ```

   You can also use the repository URL if it is published remotely.

3. Answer the prompts to customise project metadata such as the project name, author information, secret key, and frontend domain.

4. Move into the generated project directory and follow the instructions in its `README.md` to install dependencies, run migrations, and start the development server.

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
