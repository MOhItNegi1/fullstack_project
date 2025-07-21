from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime ,timedelta
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:12345@localhost:5432/jira'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'super-secret'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key' 

db = SQLAlchemy(app)
migrate = Migrate(app, db)
api = Api(app)
jwt = JWTManager(app)

# --------------------------------------------------------------MIXIN--------------------------------------------------------------------------------------------------------------
class TimestampMixin:
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# -------------------------------------------------------------SCHEMA---------------------------------------------------------------------------------------------------------------

class User(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    profile = db.relationship('UserProfile', backref='user', uselist=False, cascade="all, delete-orphan")
    epics_created = db.relationship('Epic', backref='creator', lazy=True, foreign_keys='Epic.created_by')
    stories_assigned = db.relationship('Story', backref='assignee', lazy=True, foreign_keys='Story.assignee_id')
    tasks_assigned_to = db.relationship('Task', backref='assignee', lazy=True, foreign_keys='Task.assignee_id')
    tasks_assigned_by = db.relationship('Task', backref='assigner', lazy=True, foreign_keys='Task.assigned_by')


class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(10))
    status = db.Column(db.Boolean, default=False)


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    roles = db.Column(db.String(50), nullable=False, unique=True)


class UserRoles(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)

    role = db.relationship('Role', backref='user_roles')
    user = db.relationship('User', backref='roles_assigned')


# Renamed Project to Epic
class Epic(TimestampMixin, db.Model):
    __tablename__ = 'epic'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='To Do', nullable=False)
    deadline = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))

    stories = db.relationship('Story', backref='epic', lazy=True, cascade="all, delete-orphan")


# Renamed Ticket to Story
class Story(TimestampMixin, db.Model):
    __tablename__ = 'story'
    id = db.Column(db.Integer, primary_key=True)
    epic_id = db.Column(db.Integer, db.ForeignKey('epic.id'), nullable=False)
    title = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='To Do', nullable=False)
    priority = db.Column(db.String(10), nullable=False)
    due_date = db.Column(db.DateTime, nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    sprint_id = db.Column(db.Integer, db.ForeignKey('sprints.id'), nullable=True) # NEW: Link to Sprints

    tasks = db.relationship('Task', backref='story', lazy=True, cascade="all, delete-orphan")
    discussions = db.relationship('StoryDiscussion', backref='story_discussion', lazy=True, cascade="all, delete-orphan")

    __table_args__ = (db.UniqueConstraint('epic_id', 'title', name='_epic_story_uc'),)



class Task(TimestampMixin, db.Model):
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)
    title = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='To Do', nullable=False)
    due_date = db.Column(db.DateTime, nullable=False)
    assigned_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    __table_args__ = (db.UniqueConstraint('story_id', 'title', name='_story_task_uc'),)



class StoryDiscussion(TimestampMixin, db.Model):
    __tablename__ = 'story_discussion'
    id = db.Column(db.Integer, primary_key=True)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)

    user = db.relationship('User', backref='story_discussions')


class Sprints(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sprint = db.Column(db.Text, nullable=False)
    epic_id = db.Column(db.Integer, db.ForeignKey('epic.id'), nullable=False)
    due = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(50), default='Planned', nullable=False)

    epic = db.relationship('Epic', backref='sprints')
  
    stories_in_sprint = db.relationship('Story', backref='sprint_assigned', lazy=True, foreign_keys='Story.sprint_id')


class Notifications(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref='notifications')


class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    members = db.relationship('TeamMembers', backref='team', lazy=True, cascade="all, delete-orphan")
  
    epics = db.relationship('TeamEpic', back_populates='team_obj', lazy=True, cascade="all, delete-orphan")


class TeamEpic(db.Model):
    __tablename__ = 'team_epic'
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    epic_id = db.Column(db.Integer, db.ForeignKey('epic.id'), nullable=False)

  
    team_obj = db.relationship('Team', back_populates='epics')

    epic = db.relationship('Epic', backref='team_assignments')

class TeamMembers(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)

    user = db.relationship('User', backref='team_memberships')


# ---------------------------------------------------------------------------------HELPER FUNCTIONS-----------------------------------------------------------------------------------------------
def get_user_role(user_id):
    user_roles = UserRoles.query.filter_by(user_id=user_id).all()
    return [ur.role.roles for ur in user_roles]

def create_notification(user_id, notif_type, content):
    notification = Notifications(
        user_id=user_id,
        type=notif_type,
        content=content,
        is_read=False
    )
    db.session.add(notification)
    db.session.commit()

def role_required(allowed_roles):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user_roles = get_user_role(current_user_id)
            if not any(role in allowed_roles for role in user_roles):
                return {"message": "Unauthorized: Insufficient role"}, 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper

def seed_notifications(user_id):
    sample_notifications = [
        {"type": "Story Assigned", "content": "You have been assigned a new story."},
        {"type": "Task Completed", "content": "A task you were assigned has been marked as complete."},
        {"type": "New Epic", "content": "A new epic has been created."},
        {"type": "Role Approved", "content": "Your requested role has been approved by the admin."},
        {"type": "Comment Added", "content": "A new comment has been added to your story discussion."},
        {"type": "Sprint Deadline", "content": "A sprint is approaching its deadline. Please review your pending tasks."},
        {"type": "Team Invitation", "content": "You have been added to a new team."},
        {"type": "Epic Deleted", "content": "An epic you were part of has been deleted."},
        {"type": "Overdue Task", "content": "You have a task that is overdue."}
    ]
    for notif in sample_notifications:
        db.session.add(
            Notifications(
                user_id=user_id,
                type=notif["type"],
                content=notif["content"],
                is_read=False
            )
        )
    db.session.commit()

# ---------------------------------------------------------------------------------API ENDPOINTS-----------------------------------------------------------------------------------------------

class Register(Resource):
    def post(self):
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
        name = data.get('name') # Get name for UserProfile

        if not email or not password or not role:
            return {"message": "Email, password, and role are required"}, 400

        if User.query.filter_by(email=email).first():
            return {"message": "User with this email already exists"}, 400

        role_obj = Role.query.filter_by(roles=role).first()
        if not role_obj:
            return {"message": f"Role '{role}' does not exist"}, 400

        hashed_password = generate_password_hash(password)
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.flush() # Flush to get user.id before commit

        user_role = UserRoles(user_id=new_user.id, role_id=role_obj.id)
        db.session.add(user_role)

        profile = UserProfile(user_id=new_user.id, name=name)
        db.session.add(profile)
        db.session.commit()

        return {"message": "Registered Successfully!"}, 201

class Login(Resource):
    def post(self):
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            return {"message": "Invalid credentials"}, 401

        user_roles = [ur.role.roles for ur in user.roles_assigned] 
        if role not in user_roles:
            return {"message": "Invalid role for this user"}, 401

        access_token = create_access_token(identity=str(user.id))
        return {
            "access_token": access_token,
            "user": {"id": user.id, "email": user.email, "roles": user_roles}
        }, 200

class EpicCreate(Resource):
    @jwt_required()
    def post(self):
        current_user_id = get_jwt_identity()
        data = request.get_json()
        try:
            epic = Epic(
                name=data.get('name'),
                description=data.get('description'),
                deadline=datetime.strptime(data.get('deadline'), '%Y-%m-%d'),
                created_by=current_user_id,
                status='To Do'
            )
            db.session.add(epic)
            db.session.commit()
            create_notification(current_user_id, "Epic Created", f"New epic '{epic.name}' has been created.")
            return {"message": "Epic created successfully", "id": epic.id}, 201
        except Exception as e:
            db.session.rollback()
            return {"message": f"Error creating epic: {str(e)}"}, 400

class EpicList(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user_roles = get_user_role(current_user_id)

        if "admin" in user_roles or "manager" in user_roles:
            epics = Epic.query.all()
        else:
            team_memberships = TeamMembers.query.filter_by(user_id=current_user_id).all()
            team_ids = [tm.team_id for tm in team_memberships]

            epic_ids = (
                db.session.query(TeamEpic.epic_id)
                .filter(TeamEpic.team_id.in_(team_ids))
                .distinct()
                .all()
            )
            epic_ids = [eid[0] for eid in epic_ids]
            epics = Epic.query.filter(Epic.id.in_(epic_ids)).all()

        result = [
            {
                "id": e.id,
                "name": e.name,
                "description": e.description,
                "deadline": e.deadline.strftime('%Y-%m-%d'),
                "status": e.status
            }
            for e in epics
        ]
        return jsonify(result)

class EpicDetail(Resource):
    @jwt_required()
    def get(self, id):
        epic = Epic.query.get_or_404(id)
        return {
            "id": epic.id,
            "name": epic.name,
            "description": epic.description,
            "deadline": epic.deadline.strftime('%Y-%m-%d'),
            "status": epic.status
        }

    @role_required(["manager","admin"])
    @jwt_required()
    def put(self, id):
        epic = Epic.query.get_or_404(id)
        data = request.get_json()
        epic.name = data.get('name', epic.name)
        epic.description = data.get('description', epic.description)
        epic.deadline = datetime.strptime(data.get('deadline', epic.deadline.strftime('%Y-%m-%d')), '%Y-%m-%d')
        epic.status = data.get('status', epic.status)
        db.session.commit()
        create_notification(get_jwt_identity(), "Epic Updated", f"Epic '{epic.name}' has been updated.")
        return {"message": "Epic updated successfully"}

    @role_required(["manager","admin"])
    @jwt_required()
    def delete(self, id):
        epic = Epic.query.get_or_404(id)
        db.session.delete(epic)
        db.session.commit()
        create_notification(get_jwt_identity(), "Epic Deleted", f"Epic '{epic.name}' has been deleted.")
        return {"message": "Epic deleted successfully"}

# STORY (formerly Ticket) Resources
class StoryCreate(Resource):
    @jwt_required()
    @role_required(["manager", "admin"])
    def post(self):
        data = request.get_json()
        try:
            story = Story(
                title=data['title'],
                priority=data['priority'],
                due_date=datetime.strptime(data['due_date'], '%Y-%m-%d'),
                epic_id=data['epic_id'],
                assignee_id=data['assignee_id'],
                status='To Do'
            )
            db.session.add(story)
            db.session.commit()
            create_notification(data['assignee_id'], "Story Assigned", f"You have been assigned a new story: '{story.title}'.")
            return {"message": "Story created successfully", "id": story.id}, 201
        except Exception as e:
            db.session.rollback()
            return {"message": f"Error creating story: {str(e)}"}, 400


class StoryList(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user_roles = get_user_role(current_user_id)

        if "admin" in user_roles or "manager" in user_roles:
            stories = Story.query.all()
        else:
            team_ids = [tm.team_id for tm in TeamMembers.query.filter_by(user_id=current_user_id).all()]
            epic_ids = db.session.query(TeamEpic.epic_id) \
                .filter(TeamEpic.team_id.in_(team_ids)).distinct().all()
            epic_ids = [eid[0] for eid in epic_ids]

            stories = Story.query.filter(
                (Story.epic_id.in_(epic_ids)) |
                (Story.assignee_id == current_user_id)
            ).all()

        result = [
            {
                "id": s.id,
                "title": s.title,
                "priority": s.priority,
                "status": s.status,
                "due_date": s.due_date.strftime('%Y-%m-%d'),
                "epic_id": s.epic_id,
                "assignee_id": s.assignee_id,
                "epic_name": s.epic.name if s.epic else None,
                "assignee_name": s.assignee.profile.name if s.assignee and s.assignee.profile else s.assignee.email if s.assignee else None
            }
            for s in stories
        ]
        return jsonify(result)

class StoryDetail(Resource):
    @jwt_required()
    def get(self, id):
        story = Story.query.get_or_404(id)
        return {
            "id": story.id,
            "title": story.title,
            "priority": story.priority,
            "status": story.status,
            "due_date": story.due_date.strftime('%Y-%m-%d'),
            "epic_id": story.epic_id,
            "assignee_id": story.assignee_id,
            "epic_name": story.epic.name if story.epic else None,
            "assignee_name": story.assignee.profile.name if story.assignee and story.assignee.profile else story.assignee.email if story.assignee else None
        }

    @jwt_required()
    def put(self, id):
        story = Story.query.get_or_404(id)
        data = request.get_json()
        story.title = data.get('title', story.title)
        story.priority = data.get('priority', story.priority)
        story.status = data.get('status', story.status)
        story.due_date = datetime.strptime(data.get('due_date', story.due_date.strftime('%Y-%m-%d')), '%Y-%m-%d')
        story.epic_id = data.get('epic_id', story.epic_id)
        story.assignee_id = data.get('assignee_id', story.assignee_id)
        db.session.commit()
        create_notification(story.assignee_id, "Story Updated", f"Story '{story.title}' has been updated.")
        return {"message": "Story updated successfully"}

    @jwt_required()
    def delete(self, id):
        story = Story.query.get_or_404(id)
        current_user_id = get_jwt_identity()
        user_roles = get_user_role(current_user_id)
        if story.assignee_id == int(current_user_id) or "manager" in user_roles or "admin" in user_roles:
            db.session.delete(story)
            db.session.commit()
            create_notification(current_user_id, "Story Deleted", f"Story '{story.title}' has been deleted.")
            return {"message": "Story deleted successfully"}
        else:
            return {"message": "Not allowed to delete this story"}, 403

# TASK (formerly Tasks) Resources
class TaskCreate(Resource):
 
    @jwt_required()
    @role_required(["admin", "manager"])
    def post(self):
        data = request.get_json()
        try:
            task = Task(
                title=data['title'],
                story_id=data['story_id'],
                due_date=datetime.strptime(data['due_date'], '%Y-%m-%d'),
                assigned_by=get_jwt_identity(),
                assignee_id=data.get('assignee_id'),
                status='To Do'
            )
            db.session.add(task)
            db.session.commit()
            if task.assignee_id:
                create_notification(task.assignee_id, "Task Assigned", f"You have been assigned a new task: '{task.title}'.")
            return {"message": "Task created successfully", "id": task.id}, 201
        except Exception as e:
            db.session.rollback()
            return {"message": f"Error creating task: {str(e)}"}, 400

class TaskList(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user_roles = get_user_role(current_user_id)

        if "admin" in user_roles or "manager" in user_roles:
            tasks = Task.query.all()
        else:
            team_ids = [tm.team_id for tm in TeamMembers.query.filter_by(user_id=current_user_id).all()]
            epic_ids = db.session.query(TeamEpic.epic_id) \
                                 .filter(TeamEpic.team_id.in_(team_ids)).distinct().all()
            epic_ids = [eid[0] for eid in epic_ids]

            stories_in_teams = db.session.query(Story.id)\
                                 .filter(Story.epic_id.in_(epic_ids)).distinct().all()
            story_ids_in_teams = [sid[0] for sid in stories_in_teams]

            tasks = Task.query.filter(
                (Task.assignee_id == int(current_user_id)) |
                (Task.story_id.in_(story_ids_in_teams))
            ).all()

        return [{
            "id": t.id,
            "title": t.title,
            "story_id": t.story_id,
            "status": t.status,
            "due_date": t.due_date.strftime('%Y-%m-%d'),
            "assigned_by": t.assigned_by,
            "assignee_id": t.assignee_id,
            "story_title": t.story.title if t.story else None,
            "assigned_by_name": t.assigner.profile.name if t.assigner and t.assigner.profile else t.assigner.email if t.assigner else None,
            "assignee_name": t.assignee.profile.name if t.assignee and t.assignee.profile else t.assignee.email if t.assignee else None
        } for t in tasks], 200

class TaskDetail(Resource):
    @jwt_required() # This must be the first decorator applied (closest to def)
    def get(self, id):
        task = Task.query.get_or_404(id)
        return {
            "id": task.id,
            "title": task.title,
            "story_id": task.story_id,
            "status": task.status,
            "due_date": task.due_date.strftime('%Y-%m-%d'),
            "assigned_by": task.assigned_by,
            "assignee_id": task.assignee_id,
            "story_title": task.story.title if task.story else None,
            "assigned_by_name": task.assigner.profile.name if task.assigner and task.assigner.profile else task.assigner.email if task.assigner else None,
            "assignee_name": task.assignee.profile.name if task.assignee and task.assignee.profile else task.assignee.email if task.assignee else None
        }

    @jwt_required() # This must be the first decorator applied
    @role_required(["manager", "admin"])
    def put(self, id):
        task = Task.query.get_or_404(id)
        data = request.get_json()
        current_user_id = get_jwt_identity()
        user_roles = get_user_role(current_user_id)

        if "admin" in user_roles or "manager" in user_roles:
            task.title = data.get('title', task.title)
            task.story_id = data.get('story_id', task.story_id)
            task.status = data.get('status', task.status)
            task.due_date = datetime.strptime(data.get('due_date', task.due_date.strftime('%Y-%m-%d')), '%Y-%m-%d')
            task.assignee_id = data.get('assignee_id', task.assignee_id)
        elif task.assignee_id == int(current_user_id):
            task.status = data.get('status', task.status)
            task.title = data.get('title', task.title)
        else:
            return {"message": "Not authorized to update this task"}, 403

        db.session.commit()
        create_notification(task.assignee_id, "Task Updated", f"Task '{task.title}' status changed to {task.status}.")
        return {"message": "Task updated successfully"}

    @jwt_required() # This must be the first decorator applied
    @role_required(["manager","admin"])
    def delete(self, id):
        task = Task.query.get_or_404(id)
        db.session.delete(task)
        db.session.commit()
        create_notification(get_jwt_identity(), "Task Deleted", f"Task '{task.title}' has been deleted.")
        return {"message": "Task deleted successfully"}

    
# discussion ke api, 
class StoryDiscussionList(Resource):
    @jwt_required()
    def get(self, story_id):
        discussions = StoryDiscussion.query.filter_by(story_id=story_id).order_by(StoryDiscussion.created_at.asc()).all()
        # This return statement is now more robust and will not crash if a user is missing.
        return [{
            "id": d.id,
            "user_id": d.user_id,
            "user_name": (d.user.profile.name if d.user.profile else d.user.email) if d.user else "Deleted User",
            "message": d.message,
            "created_at": d.created_at.strftime('%Y-%m-%d %H:%M')
        } for d in discussions], 200

class DiscussionCreate(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        try:
            discussion = StoryDiscussion(
                story_id=data['story_id'],
                user_id=get_jwt_identity(),
                message=data['message']
            )
            db.session.add(discussion)
            db.session.commit()
            
            # Improvement: Notifies the story's assignee, not just the commenter
            story = Story.query.get(data['story_id'])
            if story and story.assignee_id and story.assignee_id != int(get_jwt_identity()):
                 create_notification(story.assignee_id, "Comment Added", f"A new comment was added to story: '{story.title}'.")

            return {"message": "Comment added"}, 201
        except Exception as e:
            db.session.rollback()
            return {"message": f"Error adding comment: {str(e)}"}, 400


class DiscussionDetail(Resource):
    @jwt_required()
    def get(self, id):
        d = StoryDiscussion.query.get_or_404(id)
        return {
            "id": d.id,
            "story_id": d.story_id,
            "user_id": d.user_id,
            "message": d.message
        }

    @jwt_required()
    def put(self, id):
        d = StoryDiscussion.query.get_or_404(id)
        data = request.get_json()
        d.message = data.get('message', d.message)
        db.session.commit()
        create_notification(get_jwt_identity(), "Comment Updated", f"Comment {id} updated.")
        return {"message": "Comment updated"}

    @jwt_required()
    def delete(self, id):
        d = StoryDiscussion.query.get_or_404(id)
        db.session.delete(d)
        db.session.commit()
        create_notification(get_jwt_identity(), "Comment Deleted", f"Comment {id} deleted.")
        return {"message": "Comment deleted"}

# Sprint Resources
class SprintList(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user_roles = get_user_role(current_user_id)

        if "admin" in user_roles or "manager" in user_roles:
            sprints = Sprints.query.all()
        else:
            team_ids = [tm.team_id for tm in TeamMembers.query.filter_by(user_id=current_user_id).all()]
            epic_ids = db.session.query(TeamEpic.epic_id) \
                .filter(TeamEpic.team_id.in_(team_ids)).distinct().all()
            epic_ids = [eid[0] for eid in epic_ids]

            sprints = Sprints.query.filter(Sprints.epic_id.in_(epic_ids)).all()

        return [{
            "id": s.id,
            "sprint": s.sprint,
            "epic_id": s.epic_id,
            "due": s.due.strftime('%Y-%m-%d'),
            "status": s.status
        } for s in sprints], 200

class SprintCreate(Resource):
    @role_required(["admin", "manager"])
    @jwt_required()
    def post(self):
        data = request.get_json()
        try:
            sprint = Sprints(
                sprint=data['sprint'],
                epic_id=data['epic_id'],
                due=datetime.strptime(data['due'], '%Y-%m-%d'),
                status=data.get('status', 'Planned')
            )
            db.session.add(sprint)
            db.session.commit()
            create_notification(get_jwt_identity(), "Sprint Created", f"New sprint '{sprint.sprint}' created for epic {sprint.epic_id}.")
            return {"message": "Sprint created"}, 201
        except Exception as e:
            db.session.rollback()
            return {"message": f"Error creating sprint: {str(e)}"}, 400

class SprintDetail(Resource):
    @jwt_required()
    def get(self, id):
        s = Sprints.query.get_or_404(id)
        return {
            "id": s.id,
            "sprint": s.sprint,
            "epic_id": s.epic_id,
            "due": s.due.strftime('%Y-%m-%d'),
            "status": s.status
        }

    @role_required(["manager","admin"])
    @jwt_required()
    def put(self, id):
        s = Sprints.query.get_or_404(id)
        data = request.get_json()
        s.sprint = data.get('sprint', s.sprint)
        s.epic_id = data.get('epic_id', s.epic_id)
        s.due = datetime.strptime(data.get('due', s.due.strftime('%Y-%m-%d')), '%Y-%m-%d')
        s.status = data.get('status', s.status)
        db.session.commit()
        create_notification(get_jwt_identity(), "Sprint Updated", f"Sprint '{s.sprint}' updated.")
        return {"message": "Sprint updated"}

    @role_required(["manager","admin"])
    @jwt_required()
    def delete(self, id):
        s = Sprints.query.get_or_404(id)
        db.session.delete(s)
        db.session.commit()
        create_notification(get_jwt_identity(), "Sprint Deleted", f"Sprint '{s.sprint}' deleted.")
        return {"message": "Sprint deleted"}

# Search Resource
class Search(Resource):
    @jwt_required()
    def get(self, text):
        current_user_id = get_jwt_identity()
        user_roles = get_user_role(current_user_id)

        results = {
            "epics": [],
            "stories": [],
            "tasks": [],
            "sprints": []
        }

        # Determine filter scope
        if "admin" in user_roles or "manager" in user_roles:
            epic_ids_scope = None
            team_ids_scope = None
        else:
            team_ids_scope = [tm.team_id for tm in TeamMembers.query.filter_by(user_id=current_user_id).all()]
            if not team_ids_scope:
                return results, 200
            epic_ids_scope = db.session.query(TeamEpic.epic_id) \
                .filter(TeamEpic.team_id.in_(team_ids_scope)).distinct().all()
            epic_ids_scope = [eid[0] for eid in epic_ids_scope]

        # Epics
        if epic_ids_scope is None:
            epics = Epic.query.filter(
                (Epic.name.ilike(f"%{text}%")) |
                (Epic.description.ilike(f"%{text}%"))
            ).all()
        else:
            epics = Epic.query.filter(
                Epic.id.in_(epic_ids_scope),
                (Epic.name.ilike(f"%{text}%")) |
                (Epic.description.ilike(f"%{text}%"))
            ).all()

        results["epics"] = [{
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "deadline": p.deadline.strftime('%Y-%m-%d')
        } for p in epics]

        # Stories (formerly Tickets)
        if epic_ids_scope is None:
            stories = Story.query.filter(Story.title.ilike(f"%{text}%")).all()
        else:
            stories = Story.query.filter(
                Story.epic_id.in_(epic_ids_scope),
                Story.title.ilike(f"%{text}%")
            ).all()

        results["stories"] = [{
            "id": t.id,
            "title": t.title,
            "priority": t.priority,
            "status": t.status,
            "due_date": t.due_date.strftime('%Y-%m-%d'),
            "epic_id": t.epic_id
        } for t in stories]

        # Tasks
        if epic_ids_scope is None: # Admin/Manager - all tasks
            tasks = Task.query.filter(Task.title.ilike(f"%{text}%")).all()
        else: # Developer - tasks related to their stories/epics
             # Need to find stories associated with the current user's team's epics
            stories_in_scope_ids = db.session.query(Story.id).filter(Story.epic_id.in_(epic_ids_scope)).all()
            stories_in_scope_ids = [sid[0] for sid in stories_in_scope_ids]

            tasks = Task.query.filter(
                (Task.story_id.in_(stories_in_scope_ids)) &
                (Task.title.ilike(f"%{text}%"))
            ).all()

        results["tasks"] = [{
            "id": t.id,
            "title": t.title,
            "status": t.status,
            "due_date": t.due_date.strftime('%Y-%m-%d'),
            "story_id": t.story_id
        } for t in tasks]


        # Sprints
        if epic_ids_scope is None:
            sprints = Sprints.query.filter(Sprints.sprint.ilike(f"%{text}%")).all()
        else:
            sprints = Sprints.query.filter(
                Sprints.epic_id.in_(epic_ids_scope),
                Sprints.sprint.ilike(f"%{text}%")
            ).all()

        results["sprints"] = [{
            "id": s.id,
            "sprint": s.sprint,
            "status": s.status,
            "due": s.due.strftime('%Y-%m-%d'),
            "epic_id": s.epic_id
        } for s in sprints]

        return results, 200

# User Profile and All Users (new)
class ProfileResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user = User.query.filter_by(id=current_user_id).first()
        if not user or not user.profile:
            return {"message": "User not found or profile missing"}, 404

        roles = [r.role.roles for r in user.roles_assigned]

        return {
            "email": user.email,
            "name": user.profile.name,
            "phone": user.profile.phone,
            "availability": user.profile.status,
            "roles": roles
        }, 200

    @jwt_required()
    def put(self):
        current_user_id = get_jwt_identity()
        data = request.get_json()

        profile = UserProfile.query.filter_by(user_id=current_user_id).first()
        if not profile:
            return {"message": "Profile not found"}, 404

        profile.name = data.get("name", profile.name)
        profile.phone = data.get("phone", profile.phone)
        profile.status = data.get("availability", profile.status) # Frontend sends 'availability'

        db.session.commit()
        return {"message": "Profile updated"}, 200

class AllUsersResource(Resource): # resource to get all users for dropdowns
    @jwt_required()
    def get(self):
        users = User.query.all()
        return jsonify([
            {
                "id": u.id,
                "email": u.email,
                "name": u.profile.name if u.profile else u.email # Return name if available, else email
            } for u in users
        ])


# Epic Summary (formerly Project Summary)
class EpicSummary(Resource):
    @jwt_required()
    def get(self, id):
        epic = Epic.query.get_or_404(id)

        name = epic.name
        description = epic.description
        deadline = epic.deadline.strftime('%Y-%m-%d')
        status = epic.status

        team_ids = [tp.team_id for tp in TeamEpic.query.filter_by(epic_id=id).all()]
        member_ids = db.session.query(TeamMembers.user_id).filter(TeamMembers.team_id.in_(team_ids)).distinct()
        members = db.session.query(UserProfile.name).filter(UserProfile.user_id.in_(member_ids)).all()
        team_member_names = [m.name for m in members if m.name]

        # Story (formerly Ticket) status counts
        story_stats = db.session.query(Story.status, db.func.count(Story.id))\
                          .filter_by(epic_id=id)\
                          .group_by(Story.status).all()
        story_counts = {"To Do": 0, "In Progress": 0, "Done": 0, "Blocked": 0, "Review": 0} # Example statuses
        for status_val, count in story_stats:
            if status_val in story_counts:
                story_counts[status_val] += count
            else: # Handle unexpected statuses
                story_counts["To Do"] += count

        # Task trend chart (based on tasks linked to stories in this epic)
        task_query = db.session.query(
            db.func.date(Task.created_at),
            Task.status,
            db.func.count(Task.id)
        ).join(Story, Story.id == Task.story_id)\
         .filter(Story.epic_id == id)\
         .group_by(db.func.date(Task.created_at), Task.status).all()

        task_date_map = {}
        for date, status_val, count in task_query:
            date_str = date.strftime('%Y-%m-%d')
            if date_str not in task_date_map:
                task_date_map[date_str] = {"created": 0, "completed": 0}
            if status_val == "Done":
                task_date_map[date_str]["completed"] += count
            else:
                task_date_map[date_str]["created"] += count

        task_dates = sorted(task_date_map.keys())
        tasks_created = [task_date_map[d]["created"] for d in task_dates]
        tasks_completed = [task_date_map[d]["completed"] for d in task_dates]

        # Activity log (notifications related to this epic or its stories/tasks)
        activity_log_raw = Notifications.query.filter(
            (Notifications.content.ilike(f"%epic {epic.name}%")) |
            (Notifications.content.ilike(f"%epic {epic.id}%")) |
            (Notifications.type.ilike("%story%") & Notifications.content.ilike(f"%{epic.name}%")) # Simplified for demo
        ).order_by(Notifications.id.desc()).limit(10).all()

        activity_log = [{
            "content": n.content,
            "type": n.type,
            "timestamp": n.created_at.strftime('%Y-%m-%d %H:%M')
        } for n in activity_log_raw]


        return {
            "id": epic.id,
            "name": name,
            "description": description,
            "deadline": deadline,
            "status": status,
            "team_members": team_member_names,
            "story_counts": story_counts,
            "task_dates": task_dates,
            "tasks_created": tasks_created,
            "tasks_completed": tasks_completed,
            "activities": [f"[{a['timestamp']}] {a['type']} - {a['content']}" for a in activity_log]
        }, 200

# Team Resources
class TeamCreate(Resource):
    @jwt_required()
    @role_required(["admin"])
    def post(self):
        data = request.get_json()
        try:
            team = Team(name=data['name'])
            db.session.add(team)
            db.session.flush()

            for uid in data.get('member_ids', []):
                db.session.add(TeamMembers(user_id=uid, team_id=team.id))
                create_notification(uid, "Team Invitation", f"You have been added to team {team.name}")

            db.session.commit()
            return {"message": "Team created successfully", "team_id": team.id}, 201
        except Exception as e:
            db.session.rollback()
            return {"message": f"Error creating team: {str(e)}"}, 400


class TeamList(Resource):
    @jwt_required()
    def get(self):
        try:
            current_user_id = get_jwt_identity()
            user_roles = get_user_role(current_user_id)

            if "admin" in user_roles or "manager" in user_roles:
                teams = Team.query.all()
            else:
                # Developers only see teams they are part of
                teams = [tm.team for tm in TeamMembers.query.filter_by(user_id=current_user_id).all() if tm.team]

            users = User.query.all() # Fetch all users for dropdowns
            epics = Epic.query.all() # Fetch all epics for dropdowns

            team_data = []
            for team in teams:
                # MODIFIED: Ensure members list includes ID and Name
                members_list_for_frontend = [
                    {
                        "id": member.user.id,
                        "name": member.user.profile.name if member.user and member.user.profile else member.user.email
                    }
                    for member in team.members
                    if member.user # Ensure user object exists
                ]
                
                epic_names = [
                    tp.epic.name
                    for tp in team.epics
                    if tp.epic and tp.epic.name
                ]
                team_data.append({
                    "id": team.id,
                    "name": team.name,
                    "members": members_list_for_frontend, # Now a list of dicts {id, name}
                    "epics": epic_names
                })

            user_data = [
                {
                    "id": user.id,
                    "name": user.profile.name if user.profile else user.email
                }
                for user in users
            ]

            epic_data = [
                {
                    "id": e.id,
                    "name": e.name
                }
                for e in epics
            ]

            return {
                "teams": team_data,
                "users": user_data,
                "epics": epic_data
            }, 200
        except Exception as e:
            print("Error in TeamList:", str(e))
            return {"message": "Internal server error"}, 500

class AddTeamMembers(Resource):
    @jwt_required()
    @role_required(["admin", "manager"])
    def put(self, id):
        data = request.get_json()
        team = Team.query.get_or_404(id)
        new_ids = data.get("member_ids", [])

        for uid in new_ids:
            if not TeamMembers.query.filter_by(user_id=uid, team_id=team.id).first():
                db.session.add(TeamMembers(user_id=uid, team_id=team.id))
                create_notification(uid, "Team Invitation", f"You've been added to team {team.name}")

        db.session.commit()
        return {"message": "Team members updated successfully"}, 200

class RemoveTeamMember(Resource): # NEW RESOURCE
    @jwt_required()
    @role_required(["admin", "manager"])
    def delete(self, team_id, user_id): # team_id and user_id in URL
        team_member = TeamMembers.query.filter_by(team_id=team_id, user_id=user_id).first()
        if not team_member:
            return {"message": "Team member not found in this team."}, 404
        
        try:
            db.session.delete(team_member)
            db.session.commit()
            # Optional: Notify the removed user
            create_notification(user_id, "Team Removal", f"You have been removed from team {team_member.team.name}.")
            return {"message": "Team member removed successfully."}, 200
        except Exception as e:
            db.session.rollback()
            return {"message": f"Failed to remove team member: {str(e)}"}, 500

class AssignTeamToEpic(Resource): # Changed from AssignTeamToProject
    @jwt_required()
    @role_required(["admin", "manager"])
    def post(self, id):
        data = request.get_json()
        epic_id = data.get("epic_id") # Changed from project_id
        if not Epic.query.get(epic_id): # Changed from Project.query.get
            return {"message": "Epic not found"}, 404

        if TeamEpic.query.filter_by(team_id=id, epic_id=epic_id).first(): # Changed from TeamProject
            return {"message": "Team already assigned to this epic"}, 400

        tp = TeamEpic(team_id=id, epic_id=epic_id) # Changed from TeamProject
        db.session.add(tp)
        db.session.commit()
        return {"message": "Team assigned to epic"}, 201

class DeleteTeam(Resource):
    @jwt_required()
    @role_required(["admin", "manager"])
    def delete(self, id):
        team = Team.query.get_or_404(id)

        TeamMembers.query.filter_by(team_id=team.id).delete()
        TeamEpic.query.filter_by(team_id=team.id).delete() # Changed from TeamProject
        # Tasks.query.filter_by(team_id=team.id).delete() # Removed as Task is not directly linked to Team anymore

        db.session.delete(team)
        db.session.commit()

        return {"message": "Team deleted successfully"}, 200

# Notification Resources (if you want CRUD for them)
class NotificationsList(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        notifications = Notifications.query.filter_by(user_id=current_user_id).order_by(Notifications.created_at.desc()).all()
        return [{
            "id": n.id,
            "type": n.type,
            "content": n.content,
            "is_read": n.is_read,
            "created_at": n.created_at.strftime('%Y-%m-%d %H:%M')
        } for n in notifications], 200

class NotificationDetail(Resource):
    @jwt_required()
    def put(self, id):
        notification = Notifications.query.get_or_404(id)
        current_user_id = get_jwt_identity()
        if notification.user_id != int(current_user_id):
            return {"message": "Unauthorized to update this notification"}, 403
        
        data = request.get_json()
        notification.is_read = data.get('is_read', notification.is_read)
        db.session.commit()
        return {"message": "Notification updated"}, 200

    @jwt_required()
    def delete(self, id):
        notification = Notifications.query.get_or_404(id)
        current_user_id = get_jwt_identity()
        if notification.user_id != int(current_user_id):
            return {"message": "Unauthorized to delete this notification"}, 403
        
        db.session.delete(notification)
        db.session.commit()
        return {"message": "Notification deleted"}, 200


class BoardSummaryResource(Resource):
        @jwt_required()
        def get(self):
            current_user_id = get_jwt_identity()
            user_roles = get_user_role(current_user_id)

            seven_days_ago = datetime.utcnow() - timedelta(days=7)
            seven_days_from_now = datetime.utcnow() + timedelta(days=7)

            # Determine IDs in scope based on user role
            epic_ids_in_scope = []
            story_ids_in_scope = []
            task_ids_in_scope = []
            user_ids_in_scope = [] # For notifications

            if "admin" in user_roles or "manager" in user_roles:
                # Admins/Managers see everything
                epic_ids_in_scope = [e.id for e in db.session.query(Epic.id).all()]
                story_ids_in_scope = [s.id for s in db.session.query(Story.id).all()]
                task_ids_in_scope = [t.id for t in db.session.query(Task.id).all()]
                user_ids_in_scope = [u.id for u in db.session.query(User.id).all()]
            else:
                # Developers see only what's related to their teams/epics
                team_ids = [tm.team_id for tm in TeamMembers.query.filter_by(user_id=current_user_id).all()]
                
                if team_ids: # Only proceed if user is in any team
                    epic_ids_in_scope = [eid[0] for eid in db.session.query(TeamEpic.epic_id)
                                         .filter(TeamEpic.team_id.in_(team_ids)).distinct().all()]
                    
                    if epic_ids_in_scope: # Only proceed if there are epics in scope
                        story_ids_in_scope = [sid[0] for sid in db.session.query(Story.id)
                                              .filter(Story.epic_id.in_(epic_ids_in_scope)).all()]
                        
                        if story_ids_in_scope: # Only proceed if there are stories in scope
                            task_ids_in_scope = [tid[0] for tid in db.session.query(Task.id)
                                                 .filter(Task.story_id.in_(story_ids_in_scope)).all()]
                
                user_ids_in_scope = [int(current_user_id)] # Developers only see their own notifications

            # Set filter lists: if original list is empty, use [-1] to ensure .in_() always has an argument
            # and effectively returns no results. This prevents SQL errors with empty IN () clauses.
            # This is the crucial part that was causing the error when lists were empty.
            epic_filter_ids = epic_ids_in_scope if epic_ids_in_scope else [-1]
            story_filter_ids = story_ids_in_scope if story_ids_in_scope else [-1]
            task_filter_ids = task_ids_in_scope if task_ids_in_scope else [-1]
            user_filter_ids = user_ids_in_scope if user_ids_in_scope else [-1]


            # --- Overall Counts (using IDs in scope) ---
            total_epics = Epic.query.filter(Epic.id.in_(epic_filter_ids)).count()
            total_stories = Story.query.filter(Story.id.in_(story_filter_ids)).count()
            total_tasks = Task.query.filter(Task.id.in_(task_filter_ids)).count()
            total_work_items = total_epics + total_stories + total_tasks

            # --- Top Metric Cards Data (using IDs in scope) ---
            completed_7_days = Story.query.filter(
                Story.id.in_(story_filter_ids),
                Story.status == 'Done',
                Story.updated_at >= seven_days_ago
            ).count()

            updated_7_days = Story.query.filter(Story.id.in_(story_filter_ids), Story.updated_at >= seven_days_ago).count() + \
                             Task.query.filter(Task.id.in_(task_filter_ids), Task.updated_at >= seven_days_ago).count() + \
                             Epic.query.filter(Epic.id.in_(epic_filter_ids), Epic.updated_at >= seven_days_ago).count()

            created_7_days = Story.query.filter(Story.id.in_(story_filter_ids), Story.created_at >= seven_days_ago).count() + \
                             Task.query.filter(Task.id.in_(task_filter_ids), Task.created_at >= seven_days_ago).count() + \
                             Epic.query.filter(Epic.id.in_(epic_filter_ids), Epic.created_at >= seven_days_ago).count()

            due_soon_7_days = Story.query.filter(
                Story.id.in_(story_filter_ids),
                Story.due_date >= datetime.utcnow(),
                Story.due_date <= seven_days_from_now,
                Story.status != 'Done'
            ).count() + \
            Task.query.filter(
                Task.id.in_(task_filter_ids),
                Task.due_date >= datetime.utcnow(),
                Task.due_date <= seven_days_from_now,
                Task.status != 'Done'
            ).count()

            # --- Overall Epic Status Counts (using IDs in scope) ---
            epic_status_stats = db.session.query(Epic.status, db.func.count(Epic.id))\
                                   .filter(Epic.id.in_(epic_filter_ids))\
                                   .group_by(Epic.status).all()
            epic_counts = {"To Do": 0, "In Progress": 0, "Done": 0}
            for status_val, count in epic_status_stats:
                if status_val in epic_counts:
                    epic_counts[status_val] += count
                else:
                    epic_counts["To Do"] += count

            # --- Overall Story Status Counts (using IDs in scope) ---
            story_status_stats = db.session.query(Story.status, db.func.count(Story.id))\
                                  .filter(Story.id.in_(story_filter_ids))\
                                  .group_by(Story.status).all()
            story_counts = {"To Do": 0, "In Progress": 0, "Done": 0, "Blocked": 0, "Review": 0}
            for status_val, count in story_status_stats:
                if status_val in story_counts:
                    story_counts[status_val] += count
                else:
                    story_counts["To Do"] += count

            # --- Overall Story Priority Counts (using IDs in scope) ---
            story_priority_stats = db.session.query(Story.priority, db.func.count(Story.id))\
                                   .filter(Story.id.in_(story_filter_ids))\
                                   .group_by(Story.priority).all()
            story_priority_counts = {"High": 0, "Medium": 0, "Low": 0}
            for priority_val, count in story_priority_stats:
                if priority_val in story_priority_counts:
                    story_priority_counts[priority_val] += count
                else:
                    story_priority_counts["Medium"] += count

            # --- Overall Task Status Counts (using IDs in scope) ---
            task_status_stats = db.session.query(Task.status, db.func.count(Task.id))\
                                   .filter(Task.id.in_(task_filter_ids))\
                                   .group_by(Task.status).all()
            task_counts = {"To Do": 0, "In Progress": 0, "Done": 0}
            for status_val, count in task_status_stats:
                if status_val in task_counts:
                    task_counts[status_val] += count
                else:
                    task_counts["To Do"] += count

            # --- Overall Stories Created vs Completed Trend (using IDs in scope) ---
            story_trend_query = db.session.query(
                db.func.date(Story.created_at),
                Story.status,
                db.func.count(Story.id)
            ).filter(Story.id.in_(story_filter_ids))\
             .group_by(db.func.date(Story.created_at), Story.status)\
             .order_by(db.func.date(Story.created_at)).all()

            story_date_map = {}
            for date, status_val, count in story_trend_query:
                date_str = date.strftime('%Y-%m-%d')
                if date_str not in story_date_map:
                    story_date_map[date_str] = {"created": 0, "completed": 0}
                
                story_date_map[date_str]["created"] += count 
                
                if status_val == "Done":
                    story_date_map[date_str]["completed"] += count

            all_dates = sorted(list(story_date_map.keys()))
            if all_dates:
                start_date = datetime.strptime(all_dates[0], '%Y-%m-%d').date()
                end_date = datetime.strptime(all_dates[-1], '%Y-%m-%d').date()
                current_date = start_date
                while current_date <= end_date:
                    date_str = current_date.strftime('%Y-%m-%d')
                    if date_str not in story_date_map:
                        story_date_map[date_str] = {"created": 0, "completed": 0}
                    current_date += timedelta(days=1)
            
            story_dates = sorted(story_date_map.keys())
            stories_created = [story_date_map[d]["created"] for d in story_dates]
            stories_completed = [story_date_map[d]["completed"] for d in story_dates]

            # --- Recent Activity (Enhanced) ---
            recent_notifications = db.session.query(Notifications).filter(Notifications.user_id.in_(user_filter_ids))\
                                   .order_by(Notifications.created_at.desc()).limit(10).all()
            
            activities = []
            for n in recent_notifications:
                user_name = n.user.profile.name if n.user and n.user.profile else n.user.email if n.user else 'Unknown'
                item_id = None
                item_type = None
                item_title = None

                import re
                match = re.search(r'(story|epic|task)\s*(\d+)', n.content, re.IGNORECASE)
                if match:
                    item_type = match.group(1).lower()
                    item_id = int(match.group(2))
                    if item_type == "story":
                        story_obj = Story.query.get(item_id)
                        if story_obj: item_title = story_obj.title
                    elif item_type == "epic":
                        epic_obj = Epic.query.get(item_id)
                        if epic_obj: item_title = epic_obj.name
                    elif item_type == "task":
                        task_obj = Task.query.get(item_id)
                        if task_obj: item_title = task_obj.title
                
                activities.append({
                    "user_name": user_name,
                    "content": n.content,
                    "timestamp": n.created_at.strftime('%Y-%m-%d %H:%M'),
                    "item_id": item_id,
                    "item_type": item_type,
                    "item_title": item_title
                })


            return {
                "completed_7_days": completed_7_days,
                "updated_7_days": updated_7_days,
                "created_7_days": created_7_days,
                "due_soon_7_days": due_soon_7_days,
                "total_work_items": total_work_items,
                "total_epics": total_epics,
                "total_stories": total_stories,
                "total_tasks": total_tasks,
                "story_counts": story_counts,
                "story_priority_counts": story_priority_counts,
                "epic_counts": epic_counts,
                "task_counts": task_counts,
                "story_dates": story_dates,
                "stories_created": stories_created,
                "stories_completed": stories_completed,
                "activities": activities
            }, 200

class AdminUserRoleChange(Resource):
    @jwt_required()
    @role_required(['admin'])
    def post(self):
        data = request.get_json()
        user_id_to_change = data.get('user_id')
        new_role_name = data.get('new_role')

        if not user_id_to_change or not new_role_name:
            return {'message': 'User ID and new role are required.'}, 400

        user = User.query.get(user_id_to_change)
        if not user:
            return {'message': 'User not found.'}, 404

        new_role = Role.query.filter_by(roles=new_role_name).first()
        if not new_role:
            return {'message': f'Role "{new_role_name}" does not exist.'}, 400
            
        # Remove all existing roles for the user
        UserRoles.query.filter_by(user_id=user_id_to_change).delete()
        
        # Add the new role
        new_user_role = UserRoles(user_id=user_id_to_change, role_id=new_role.id)
        db.session.add(new_user_role)
        db.session.commit()
        
        create_notification(user_id_to_change, "Role Changed", f"An administrator has changed your role to {new_role_name}.")
        
        return {'message': f"Successfully changed {user.email}'s role to {new_role_name}."}, 200

# ------------------------------------------------------------------------------API RESOURCES REGISTRATION----------------------------------------------------------------------------------------------
api.add_resource(Register, "/api/auth/register")
api.add_resource(Login, "/api/auth/login")

api.add_resource(EpicCreate, "/api/epics")
api.add_resource(EpicList, "/api/epics/all")
api.add_resource(EpicDetail, "/api/epics/<int:id>")
api.add_resource(EpicSummary, "/api/epics/<int:id>/summary")

api.add_resource(StoryCreate, "/api/stories")
api.add_resource(StoryList, "/api/stories/all")
api.add_resource(StoryDetail, "/api/stories/<int:id>")

api.add_resource(TaskCreate, "/api/tasks")
api.add_resource(TaskList, "/api/tasks/all")
api.add_resource(TaskDetail, "/api/tasks/<int:id>")

api.add_resource(DiscussionCreate, "/api/discussions")
api.add_resource(StoryDiscussionList, "/api/stories/<int:story_id>/discussions")
api.add_resource(DiscussionDetail, "/api/discussions/<int:id>")


api.add_resource(SprintCreate, "/api/sprints")
api.add_resource(SprintList, "/api/sprints/all")
api.add_resource(SprintDetail, "/api/sprints/<int:id>")

api.add_resource(Search, "/api/search/<string:text>")

api.add_resource(ProfileResource, "/api/users/profile")
api.add_resource(AllUsersResource, "/api/users/all") 

api.add_resource(TeamCreate, "/api/teams")
api.add_resource(TeamList, "/api/teams/all")
api.add_resource(AddTeamMembers, "/api/teams/<int:id>/members")
api.add_resource(AssignTeamToEpic, "/api/teams/<int:id>/assign_epic") 
api.add_resource(DeleteTeam, "/api/teams/<int:id>")
api.add_resource(RemoveTeamMember, "/api/teams/<int:team_id>/members/<int:user_id>")

api.add_resource(NotificationsList, "/api/notifications")
api.add_resource(NotificationDetail, "/api/notifications/<int:id>")

api.add_resource(BoardSummaryResource, "/api/board-summary") 

api.add_resource(AdminUserRoleChange, '/api/admin/change-user-role')

# ---------------------------------------------------------------------------------WEB UI ROUTES-----------------------------------------------------------------------------------------------
@app.route('/')
def home_page(): 
    return render_template('home.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('kanban.html')

@app.route('/register')
def register_page():
    return render_template('signup.html')

@app.route('/epics') 
def epics_page():
    return render_template('epics/list.html') 

@app.route("/profile")
def profile_page():
    return render_template("profile.html")

@app.route("/epics/summary") 
def epic_summary_page():
    epic_id = request.args.get("id")
    if not epic_id:
        return "Missing epic ID", 400
    return render_template("epics/summary.html", project_id=epic_id)

@app.route('/teams')
def team_page():
    return render_template('teams.html')

@app.route("/stories") 
def stories_page():
    return render_template("stories/list.html") 


@app.route("/sprints") 
def sprints_page():
    return render_template("sprints.html")

@app.route("/kanban")
def kanban_page():
    epic_id = request.args.get("id")
    return render_template("kanban.html", epic_id=epic_id)

@app.route("/backlog")
def backlog_page():
    epic_id = request.args.get("id")
    return render_template("backlog.html", epic_id=epic_id)

@app.route("/notifications")
def notifications_page():
    return render_template("notifications.html")

@app.route("/board-summary") 
def board_summary_page():
    return render_template("board_summary.html")


@app.route("/tasks")
def tasks_page():
    return render_template("tasks.html")

@app.route("/stories/<int:story_id>")
def story_detail_page(story_id):
    return render_template("story_detail.html", story_id=story_id)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True,port=3000)