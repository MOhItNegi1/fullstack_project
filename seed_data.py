from app import db, User, Role, UserRoles, UserProfile, Team, Epic, TeamEpic, TeamMembers, Task, Sprints, Story, StoryDiscussion, Notifications
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
from faker import Faker
import random

fake = Faker()

def seed_roles():
    """Seeds the database with default user roles if they don't already exist."""
    roles = ["admin", "manager", "developer"]
    for r in roles:
        if not Role.query.filter_by(roles=r).first():
            db.session.add(Role(roles=r))
    db.session.commit()

def get_role_id(role_name):
    """Retrieves the ID of a role by its name."""
    role = Role.query.filter_by(roles=role_name).first()
    return role.id if role else None

def create_user(email, password, role_name, name=None):
    """Creates a new user, assigns a role, and creates a user profile."""
    user = User(email=email, password=generate_password_hash(password))
    db.session.add(user)
    db.session.flush() # Use flush to get user.id before profile and role creation

    role_id = get_role_id(role_name)
    if not role_id:
        print(f"Warning: Role '{role_name}' not found. User {email} might not have a role.")
        # Optionally, handle this by creating the role or raising an error
        # For now, we'll proceed without assigning if role_id is None
    else:
        db.session.add(UserRoles(user_id=user.id, role_id=role_id))

    # Ensure a name is provided for the UserProfile
    profile_name = name if name else fake.name()
    db.session.add(UserProfile(user_id=user.id, name=profile_name, phone=fake.msisdn()[:10], status=True))
    db.session.commit()
    return user

def create_team(name):
    """Creates a new team."""
    team = Team(name=name)
    db.session.add(team)
    db.session.commit()
    return team

def create_epic(name, desc, creator_id, status_str):
    """Creates a new Epic (formerly Project)."""
    epic = Epic(
        name=name,
        description=desc,
        created_by=creator_id,
        deadline=datetime.utcnow() + timedelta(days=random.randint(10, 30)), # Use UTC for consistency
        status=status_str
    )
    db.session.add(epic)
    db.session.commit()
    return epic

def assign_team_to_epic(team_id, epic_id):
    """Assigns a team to an Epic (formerly Project)."""
    link = TeamEpic(team_id=team_id, epic_id=epic_id)
    db.session.add(link)
    db.session.commit()

def assign_member_to_team(user_id, team_id):
    """Adds a user as a member to a team."""
    member = TeamMembers(user_id=user_id, team_id=team_id)
    db.session.add(member)
    db.session.commit()

def create_story(epic_id, assignee_id, sprint_id=None):
    """Creates a new Story (formerly Ticket), linking it to an Epic and optionally a Sprint."""
    story = Story(
        title=fake.sentence(nb_words=random.randint(3, 8)).replace('.', ''), # Ensure no period at end
        priority=random.choice(["High", "Medium", "Low"]),
        status=random.choice(["To Do", "In Progress", "Done", "Blocked"]),
        due_date=datetime.utcnow() + timedelta(days=random.randint(3, 10)),
        epic_id=epic_id,
        assignee_id=assignee_id,
        sprint_id=sprint_id # Assign sprint_id here
    )
    db.session.add(story)
    db.session.commit()
    return story

def create_task(story_id, assigned_by_id, assignee_id=None):
    """Creates a new Task, linking it to a Story."""
    task = Task(
        title=fake.word().capitalize() + " " + fake.word() + " " + random.choice(["implementation", "testing", "design", "review"]), # Renamed 'task' column to 'title'
        story_id=story_id,
        due_date=datetime.utcnow() + timedelta(days=random.randint(1, 5)),
        assigned_by=assigned_by_id,
        assignee_id=assignee_id, # Can be None if unassigned
        status=random.choice(["To Do", "In Progress", "Done"])
    )
    db.session.add(task)
    db.session.commit()
    return task

def create_sprint(sprint_name, epic_id):
    """Creates a new Sprint, linking it to an Epic."""
    sprint = Sprints(
        sprint=sprint_name,
        epic_id=epic_id,
        due=datetime.utcnow() + timedelta(days=random.randint(7, 21)),
        status=random.choice(["Planned", "Active", "Completed"])
    )
    db.session.add(sprint)
    db.session.commit()
    return sprint

def run_seeding():
    """Executes the full database seeding process."""
    # WARNING: This will delete all existing data in your database!
    # Ensure your database is empty or you've backed it up before running this.
    try:
        db.drop_all()
        db.create_all()
    except Exception as e:
        print(f"Error during db.drop_all() or db.create_all(): {e}")
        print("Please ensure your PostgreSQL database is empty and no other connections are active.")
        print("You might need to manually drop and recreate the 'jira' database if issues persist.")
        return # Exit if initial setup fails

    print("✅ Seeding started...")
    
    seed_roles()
    
    # Create Users
    admin = create_user("admin@example.com", "admin123", "admin", "Admin User")

    managers = []
    for i in range(3):
        managers.append(create_user(f"manager{i+1}@example.com", "pass123", "manager", name=f"Manager {i+1}"))

    developers = [create_user(f"dev{i+1}@example.com", "pass123", "developer", name=f"Developer {i+1}") for i in range(6)]

    # Create Teams
    teams = [create_team(f"Team {i+1}") for i in range(3)]

    # Assign Managers + Developers to Teams
    for i, team in enumerate(teams):
        # Assign one manager per team (round-robin)
        assign_member_to_team(managers[i % len(managers)].id, team.id)
        # Assign two developers per team (ensure unique assignment for this loop)
        assign_member_to_team(developers[i*2].id, team.id)
        if (i*2 + 1) < len(developers): # Ensure index is within bounds
            assign_member_to_team(developers[i*2+1].id, team.id)

    # Create Epics, Stories, Tasks, and Sprints
    for i, team in enumerate(teams):
        for j in range(random.randint(1, 3)):  # 1-3 epics per team
            epic_status = random.choice(["To Do", "In Progress", "Done"])
            epic = create_epic(
                name=f"Epic {i+1}-{j+1} for {team.name}",
                desc=fake.paragraph(nb_sentences=3),
                creator_id=managers[i % len(managers)].id, # Creator is a manager
                status_str=epic_status
            )
            assign_team_to_epic(team.id, epic.id)

            # Create sprints for the epic
            created_sprints = []
            for k in range(random.randint(1, 2)): # 1-2 sprints per epic
                sprint = create_sprint(f"Sprint {k+1} for {epic.name}", epic.id)
                created_sprints.append(sprint)

            # Create stories and tasks for each epic
            for l in range(random.randint(3, 5)): # 3-5 stories per epic
                # Assign story to a random sprint created for this epic, or None if no sprints
                assigned_sprint_id = random.choice(created_sprints).id if created_sprints else None
                
                story_assignee = random.choice(developers) # Random developer for story
                story = create_story(
                    epic_id=epic.id,
                    assignee_id=story_assignee.id,
                    sprint_id=assigned_sprint_id
                )
                
                # Create tasks for each story
                for m in range(random.randint(1, 3)): # 1-3 tasks per story
                    task_assignee = random.choice(developers) # Random developer for task
                    create_task(
                        story_id=story.id,
                        assigned_by_id=managers[i % len(managers)].id, # Manager assigns task
                        assignee_id=task_assignee.id # Assign task to a random developer
                    )
    
    # Add some sample notifications for the admin user
    # Note: create_notification is imported directly from app in this consolidated file setup
    from app import create_notification
    create_notification(admin.id, "System Alert", "Welcome to your new Jira-like system! Explore Epics, Stories, and Tasks.")
    create_notification(admin.id, "New Feature", "Dashboard now shows Epic and Story counts.")
    
    print("✅ Seeding complete.")

if __name__ == "__main__":
    from app import app # Import the app instance from app.py
    with app.app_context():
        run_seeding()
