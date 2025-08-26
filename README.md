🚀 Jira Clone - Agile Project Management Tool

A full-stack web app inspired by Jira, built with Flask + Vanilla JavaScript, designed to help teams plan, track, and manage projects with an Agile workflow.

This tool supports Epics → Stories → Tasks, along with Teams, Sprints, and Role-based permissions, making it a lightweight Jira alternative for learning and small teams.

✨ Key Features

✅ User Authentication – Secure sign-up & login with JWT
✅ Role-Based Access Control – Admin, Manager, and Developer roles with tailored permissions
✅ Project Management – Create, view, and organize multiple projects
✅ Work Hierarchy

Epics → High-level features

Stories → User-focused functionality inside Epics

Tasks → Actionable steps for completing Stories
✅ Teams & Sprints – Build teams, assign members, and plan sprints
✅ Interactive UI – Clean, modern interface with modals & dynamic project views


🛠 Tech Stack

Backend

Flask + Flask-RESTful

PostgreSQL + SQLAlchemy ORM

Flask-JWT-Extended (JWT Auth)

Flask-Migrate (DB migrations)

Flask-Cors (CORS handling)

Frontend

Jinja2 Templates

Vanilla JavaScript (ES6+)

CSS (minimal, modern design)

📂 Project Structure
.
├── app.py              # Main Flask app (models, routes, config)
├── seed.py             # Seed script to populate DB with sample data
├── requirements.txt    # Python dependencies
└── templates/
    ├── base.html       # Navigation
    ├── layout.html     # Authenticated layout (sidebar, etc.)
    ├── home.html       # Landing page
    ├── login.html      # User login
    ├── signup.html     # User signup
    ├── dashboard.html  # User dashboard
    ├── projects.html   # List of projects
    ├── project_detail.html # Backlog + Board
    └── (teams, sprints, profile, etc.)
