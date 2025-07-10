from app import db, User, Role, UserRoles, UserProfile, Team, Project, TeamProject, TeamMembers, Tasks, Sprints, Ticket
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
from faker import Faker
import random

fake = Faker()
def seed_roles():
    roles = ["admin", "manager", "developer"]
    for r in roles:
        if not Role.query.filter_by(roles=r).first():
            db.session.add(Role(roles=r))
    db.session.commit()

def get_role_id(role_name):
    role = Role.query.filter_by(roles=role_name).first()
    return role.id if role else None

def create_user(email, password, role_name, name=None):
    user = User(email=email, password=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()

    role_id = get_role_id(role_name)
    db.session.add(UserRoles(user_id=user.id, role_id=role_id))
    db.session.add(UserProfile(user_id=user.id, name=name or fake.name(), phone=fake.msisdn()[:10], status=True))
    db.session.commit()
    return user

def create_team(name):
    team = Team(name=name)
    db.session.add(team)
    db.session.commit()
    return team

def create_project(name, desc, creator_id, status):
    project = Project(
        name=name,
        description=desc,
        created_by=creator_id,
        deadline=datetime.now() + timedelta(days=random.randint(10, 30)),
        status=status
    )
    db.session.add(project)
    db.session.commit()
    return project

def assign_team_to_project(team_id, project_id):
    link = TeamProject(team_id=team_id, project_id=project_id)
    db.session.add(link)
    db.session.commit()

def assign_member_to_team(user_id, team_id):
    member = TeamMembers(user_id=user_id, team_id=team_id)
    db.session.add(member)
    db.session.commit()

def create_task(task_name, project_id, team_id, assigned_by):
    task = Tasks(
        task=task_name,
        project_id=project_id,
        team_id=team_id,
        due_date=datetime.now() + timedelta(days=7),
        assigned_by=assigned_by,
        status=random.choice([True, False])
    )
    db.session.add(task)
    db.session.commit()

def create_sprint(sprint_name, project_id):
    sprint = Sprints(
        sprint=sprint_name,
        project_id=project_id,
        due=datetime.now() + timedelta(days=14),
        status=random.choice([True, False])
    )
    db.session.add(sprint)
    db.session.commit()

def create_ticket(project_id, assignee_id):
    ticket = Ticket(
        title=fake.sentence(),
        priority=random.choice(["High", "Medium", "Low"]),
        status=random.choice([True, False]),
        due_date=datetime.now() + timedelta(days=7),
        project_id=project_id,
        assignee_id=assignee_id
    )
    db.session.add(ticket)
    db.session.commit()

def run():
    db.drop_all()
    db.create_all()

    print("✅ Seeding started...")
    seed_roles() 
    # Create Users
    admin = create_user("admin@example.com", "admin123", "admin", "Admin User")

    managers = []
    for i in range(3):
        managers.append(create_user(f"manager{i}@example.com", "pass123", "manager"))

    developers = [create_user(f"dev{i}@example.com", "pass123", "developer") for i in range(6)]

    # Create Teams
    teams = [create_team(f"Team {i+1}") for i in range(3)]

    # Assign Managers + Developers to Teams
    for i, team in enumerate(teams):
        assign_member_to_team(managers[i].id, team.id)
        assign_member_to_team(developers[i*2].id, team.id)
        assign_member_to_team(developers[i*2+1].id, team.id)

    # Create Projects, Tasks, Sprints, and Tickets
    for i, team in enumerate(teams):
        for j in range(2):  # 2 projects per team
            project = create_project(
                name=f"Project {i+1}-{j+1}",
                desc=fake.text(),
                creator_id=managers[i].id,
                status=bool(j % 2)  # alternate between completed/incomplete
            )
            assign_team_to_project(team.id, project.id)

            # Create sprints and tasks
            for k in range(2):
                create_sprint(f"Sprint {k+1} for {project.name}", project.id)
                create_task(f"Task {k+1} for {project.name}", project.id, team.id, managers[i].id)

            # Assign tickets to team devs
            create_ticket(project.id, developers[i*2].id)
            create_ticket(project.id, developers[i*2+1].id)

    print("✅ Seeding complete.")

if __name__ == "__main__":
    from app import app
    with app.app_context():
        run()