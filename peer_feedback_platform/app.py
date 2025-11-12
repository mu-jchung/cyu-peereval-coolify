from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import os
import csv
import string
import random
from io import StringIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///peer_feedback.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    student_code = db.Column(db.String(20), unique=True, nullable=True)
    
    def generate_student_code(self):
        """Generate a unique student code"""
        while True:
            code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            if not User.query.filter_by(student_code=code).first():
                self.student_code = code
                break
        return code

class Class(db.Model):
    __tablename__ = 'classes'
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    teacher = db.relationship('User', backref='classes')

class ClassEnrollment(db.Model):
    __tablename__ = 'class_enrollments'
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey('classes.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey('classes.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)

class GroupMember(db.Model):
    __tablename__ = 'group_members'
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

class Assignment(db.Model):
    __tablename__ = 'assignments'
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey('classes.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    due_date = db.Column(db.DateTime)
    results_released = db.Column(db.Boolean, default=False)
    presenting_group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=False)
    cls = db.relationship('Class', backref='assignments')
    presenting_group = db.relationship('Group', foreign_keys=[presenting_group_id])

class AssignmentGroup(db.Model):
    __tablename__ = 'assignment_groups'
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignments.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)

class FeedbackSubmission(db.Model):
    __tablename__ = 'feedback_submissions'
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignments.id'), nullable=False)
    presenting_group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)
    evaluator_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    presenting_group = db.relationship('Group', foreign_keys=[presenting_group_id])

class FeedbackItem(db.Model):
    __tablename__ = 'feedback_items'
    id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(db.Integer, db.ForeignKey('feedback_submissions.id'), nullable=False)
    target = db.Column(db.String(20), nullable=False)
    target_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    content = db.Column(db.Text, nullable=False)

class TeacherNote(db.Model):
    __tablename__ = 'teacher_notes'
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignments.id'), nullable=False)
    target_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    note = db.Column(db.Text, nullable=False)

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.role != 'teacher':
            flash('Access denied. Teachers only.', 'error')
            return redirect(url_for('student_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            if user.role == 'teacher':
                return redirect(url_for('teacher_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_code = request.form['email']
        password = request.form['password']
        
        # Try to find user by email first
        user = User.query.filter_by(email=email_or_code).first()
        
        # If not found by email and input looks like a code, try by code
        if not user and len(email_or_code) >= 6:
            user = User.query.filter_by(student_code=email_or_code.upper()).first()
        
        # Check password or student code as password
        password_valid = False
        if user:
            # Check regular password hash
            password_valid = check_password_hash(user.password_hash, password)
            # For students, also allow student code as password
            if not password_valid and user.role == 'student' and user.student_code:
                password_valid = (password.upper() == user.student_code)
        
        if user and password_valid:
            session['user_id'] = user.id
            session['user_role'] = user.role
            session['user_name'] = user.name
            
            if user.role == 'teacher':
                return redirect(url_for('teacher_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid email/code or password', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        role = request.form.get('role', 'teacher')
        
        if role == 'student' and not email.endswith('@monmouth.edu'):
            flash('Students must use a @monmouth.edu email address', 'error')
            return render_template('signup.html')
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered', 'error')
            return render_template('signup.html')
        
        new_user = User(
            email=email,
            password_hash=generate_password_hash(password, method='pbkdf2'),
            role=role,
            name=name
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Student Routes
@app.route('/student/dashboard')
@login_required
def student_dashboard():
    user = User.query.get(session['user_id'])
    if user.role != 'student':
        return redirect(url_for('teacher_dashboard'))
    
    enrollments = ClassEnrollment.query.filter_by(user_id=user.id).all()
    class_ids = [e.class_id for e in enrollments]
    classes = Class.query.filter(Class.id.in_(class_ids)).all() if class_ids else []
    
    assignments_data = []
    for cls in classes:
        assignments = Assignment.query.filter_by(class_id=cls.id).all()
        for assignment in assignments:
            group_member = GroupMember.query.filter_by(user_id=user.id).first()
            if group_member:
                group = Group.query.get(group_member.group_id)
                submission = FeedbackSubmission.query.filter_by(
                    assignment_id=assignment.id,
                    evaluator_user_id=user.id
                ).first()
                
                assignments_data.append({
                    'assignment': assignment,
                    'class': cls,
                    'group': {'id': group.id, 'name': group.name} if group else None,
                    'submitted': submission is not None
                })
    
    return render_template('student_dashboard.html', assignments=assignments_data, user=user)

@app.route('/student/assignment/<int:assignment_id>/feedback', methods=['GET', 'POST'])
@login_required
def submit_feedback(assignment_id):
    user = User.query.get(session['user_id'])
    assignment = Assignment.query.get_or_404(assignment_id)
    
    # Check if assignment is active and has a presenting group
    if not assignment.is_active or not assignment.presenting_group_id:
        flash('This assignment is not currently active', 'error')
        return redirect(url_for('student_dashboard'))
    
    # Check if student is in the presenting group
    group_member = GroupMember.query.filter_by(user_id=user.id).first()
    if not group_member:
        flash('You are not assigned to a group', 'error')
        return redirect(url_for('student_dashboard'))
    
    presenting_group = Group.query.get(assignment.presenting_group_id)
    
    # Students in the presenting group cannot submit feedback
    if group_member.group_id == assignment.presenting_group_id:
        flash('Students in the presenting group cannot submit feedback', 'error')
        return redirect(url_for('student_dashboard'))
    
    # Get presenting group members
    presenting_group_members = GroupMember.query.filter_by(
        group_id=assignment.presenting_group_id
    ).all()
    members = [User.query.get(gm.user_id) for gm in presenting_group_members]
    
    if request.method == 'POST':
        # Check if already submitted feedback for this presentation
        existing_submission = FeedbackSubmission.query.filter_by(
            assignment_id=assignment_id,
            presenting_group_id=assignment.presenting_group_id,
            evaluator_user_id=user.id
        ).first()
        
        if existing_submission:
            flash('You have already submitted feedback for this group presentation', 'error')
            return redirect(url_for('student_dashboard'))
        
        # Create submission for the presenting group
        submission = FeedbackSubmission(
            assignment_id=assignment_id,
            presenting_group_id=assignment.presenting_group_id,
            evaluator_user_id=user.id
        )
        db.session.add(submission)
        db.session.flush()
        
        # Add group feedback
        group_feedback = request.form.get('group_feedback')
        if group_feedback:
            feedback_item = FeedbackItem(
                submission_id=submission.id,
                target='group',
                content=group_feedback
            )
            db.session.add(feedback_item)
        
        # Add individual member feedback
        for member in members:
            individual_feedback = request.form.get(f'member_{member.id}')
            if individual_feedback:
                feedback_item = FeedbackItem(
                    submission_id=submission.id,
                    target='individual',
                    target_user_id=member.id,
                    content=individual_feedback
                )
                db.session.add(feedback_item)
        
        db.session.commit()
        flash('Feedback submitted successfully!', 'success')
        return redirect(url_for('student_dashboard'))
    
    return render_template('feedback_form.html', 
                         assignment=assignment, 
                         presenting_group=presenting_group, 
                         members=members,
                         user=user)

@app.route('/student/assignment/<int:assignment_id>/results')
@login_required
def view_results(assignment_id):
    user = User.query.get(session['user_id'])
    assignment = Assignment.query.get_or_404(assignment_id)
    
    if not assignment.results_released:
        flash('Results have not been released yet', 'error')
        return redirect(url_for('student_dashboard'))
    
    group_member = GroupMember.query.filter_by(user_id=user.id).first()
    if not group_member:
        flash('You are not assigned to a group', 'error')
        return redirect(url_for('student_dashboard'))
    
    group = Group.query.get(group_member.group_id)
    
    group_feedback = []
    submissions = FeedbackSubmission.query.filter_by(
        assignment_id=assignment_id,
        group_id=group.id
    ).all()
    
    for submission in submissions:
        items = FeedbackItem.query.filter_by(
            submission_id=submission.id,
            target='group'
        ).all()
        group_feedback.extend([item.content for item in items])
    
    individual_feedback = []
    for submission in submissions:
        items = FeedbackItem.query.filter_by(
            submission_id=submission.id,
            target='individual',
            target_user_id=user.id
        ).all()
        individual_feedback.extend([item.content for item in items])
    
    teacher_notes = TeacherNote.query.filter_by(
        assignment_id=assignment_id,
        target_user_id=user.id
    ).all()
    
    return render_template('results.html',
                         assignment=assignment,
                         group=group,
                         group_feedback=group_feedback,
                         individual_feedback=individual_feedback,
                         teacher_notes=teacher_notes,
                         user=user)

# Teacher Routes
@app.route('/teacher/dashboard')
@teacher_required
def teacher_dashboard():
    user = User.query.get(session['user_id'])
    classes = Class.query.filter_by(teacher_id=user.id).all()
    return render_template('teacher_dashboard.html', classes=classes, user=user)

@app.route('/teacher/class/create', methods=['GET', 'POST'])
@teacher_required
def create_class():
    if request.method == 'POST':
        name = request.form['name']
        new_class = Class(
            teacher_id=session['user_id'],
            name=name
        )
        db.session.add(new_class)
        db.session.commit()
        flash('Class created successfully!', 'success')
        return redirect(url_for('teacher_dashboard'))
    
    return render_template('create_class.html')

@app.route('/teacher/class/<int:class_id>')
@teacher_required
def view_class(class_id):
    cls = Class.query.get_or_404(class_id)
    if cls.teacher_id != session['user_id']:
        flash('Access denied', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    enrollments = ClassEnrollment.query.filter_by(class_id=class_id).all()
    students = [User.query.get(e.user_id) for e in enrollments]
    groups = Group.query.filter_by(class_id=class_id).all()
    assignments = Assignment.query.filter_by(class_id=class_id).all()
    
    # Serialize groups for JSON
    groups_data = [{'id': g.id, 'name': g.name, 'class_id': g.class_id} for g in groups]
    
    return render_template('view_class.html', 
                         cls=cls, 
                         students=students, 
                         groups=groups_data,
                         assignments=assignments)

@app.route('/teacher/class/<int:class_id>/add_student', methods=['POST'])
@teacher_required
def add_student(class_id):
    cls = Class.query.get_or_404(class_id)
    if cls.teacher_id != session['user_id']:
        flash('Access denied', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    email = request.form['email']
    name = request.form['name']
    password = request.form.get('password', 'password123')
    
    if not email.endswith('@monmouth.edu'):
        flash('Students must have @monmouth.edu email', 'error')
        return redirect(url_for('view_class', class_id=class_id))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(
            email=email,
            password_hash=generate_password_hash(password, method='pbkdf2'),
            role='student',
            name=name
        )
        user.generate_student_code()
        db.session.add(user)
        db.session.flush()
    
    existing = ClassEnrollment.query.filter_by(
        class_id=class_id,
        user_id=user.id
    ).first()
    
    if not existing:
        enrollment = ClassEnrollment(class_id=class_id, user_id=user.id)
        db.session.add(enrollment)
        db.session.commit()
        flash('Student added successfully!', 'success')
    else:
        flash('Student already enrolled', 'error')
    
    return redirect(url_for('view_class', class_id=class_id))

@app.route('/teacher/class/<int:class_id>/create_group', methods=['POST'])
@teacher_required
def create_group(class_id):
    cls = Class.query.get_or_404(class_id)
    if cls.teacher_id != session['user_id']:
        flash('Access denied', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    name = request.form['name']
    student_ids = request.form.getlist('student_ids')
    
    group = Group(class_id=class_id, name=name)
    db.session.add(group)
    db.session.flush()
    
    for student_id in student_ids:
        member = GroupMember(group_id=group.id, user_id=int(student_id))
        db.session.add(member)
    
    db.session.commit()
    flash('Group created successfully!', 'success')
    return redirect(url_for('view_class', class_id=class_id))

@app.route('/teacher/class/<int:class_id>/delete_student/<int:user_id>', methods=['POST'])
@teacher_required
def delete_student(class_id, user_id):
    cls = Class.query.get_or_404(class_id)
    if cls.teacher_id != session['user_id']:
        flash('Access denied', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    # Remove student from class
    enrollment = ClassEnrollment.query.filter_by(class_id=class_id, user_id=user_id).first()
    if enrollment:
        db.session.delete(enrollment)
        db.session.commit()
        flash('Student removed successfully!', 'success')
    else:
        flash('Student not found', 'error')
    
    return redirect(url_for('view_class', class_id=class_id))

@app.route('/teacher/class/<int:class_id>/student/<int:user_id>')
@teacher_required
def view_student_code(class_id, user_id):
    cls = Class.query.get_or_404(class_id)
    if cls.teacher_id != session['user_id']:
        flash('Access denied', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    student = User.query.get_or_404(user_id)
    enrollment = ClassEnrollment.query.filter_by(class_id=class_id, user_id=user_id).first()
    if not enrollment:
        flash('Student not found in this class', 'error')
        return redirect(url_for('view_class', class_id=class_id))
    
    return render_template('student_code_modal.html', student=student, class_id=class_id)

@app.route('/teacher/class/<int:class_id>/delete_group/<int:group_id>', methods=['POST'])
@teacher_required
def delete_group(class_id, group_id):
    cls = Class.query.get_or_404(class_id)
    if cls.teacher_id != session['user_id']:
        flash('Access denied', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    group = Group.query.get_or_404(group_id)
    if group.class_id != class_id:
        flash('Access denied', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    # Delete all group members first
    GroupMember.query.filter_by(group_id=group_id).delete()
    
    # Delete the group
    db.session.delete(group)
    db.session.commit()
    flash('Group deleted successfully!', 'success')
    
    return redirect(url_for('view_class', class_id=class_id))

@app.route('/teacher/class/<int:class_id>/create_assignment', methods=['GET', 'POST'])
@teacher_required
def create_assignment(class_id):
    cls = Class.query.get_or_404(class_id)
    if cls.teacher_id != session['user_id']:
        flash('Access denied', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        due_date_str = request.form['due_date']
        due_date = datetime.strptime(due_date_str, '%Y-%m-%d') if due_date_str else None
        
        assignment = Assignment(
            class_id=class_id,
            name=name,
            description=description,
            due_date=due_date
        )
        db.session.add(assignment)
        db.session.flush()
        
        group_ids = request.form.getlist('group_ids')
        for group_id in group_ids:
            ag = AssignmentGroup(assignment_id=assignment.id, group_id=int(group_id))
            db.session.add(ag)
        
        db.session.commit()
        flash('Assignment created successfully!', 'success')
        return redirect(url_for('view_class', class_id=class_id))
    
    groups = Group.query.filter_by(class_id=class_id).all()
    return render_template('create_assignment.html', cls=cls, groups=groups)

@app.route('/teacher/assignment/<int:assignment_id>/manage', methods=['GET', 'POST'])
@teacher_required
def manage_assignment(assignment_id):
    assignment = Assignment.query.get_or_404(assignment_id)
    cls = Class.query.get(assignment.class_id)
    
    if cls.teacher_id != session['user_id']:
        flash('Access denied', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    if request.method == 'POST':
        group_id = request.form.get('presenting_group_id')
        is_active = request.form.get('is_active') == 'on'
        
        if group_id:
            assignment.presenting_group_id = int(group_id)
        assignment.is_active = is_active
        
        db.session.commit()
        flash('Assignment updated successfully!', 'success')
        return redirect(url_for('manage_assignment', assignment_id=assignment_id))
    
    groups = Group.query.filter_by(class_id=assignment.class_id).all()
    
    # Get members for the presenting group if it exists
    presenting_group_members = []
    if assignment.presenting_group_id:
        group_members = GroupMember.query.filter_by(group_id=assignment.presenting_group_id).all()
        presenting_group_members = [User.query.get(gm.user_id) for gm in group_members]
    
    return render_template('manage_assignment.html', 
                         assignment=assignment, 
                         groups=groups, 
                         cls=cls,
                         presenting_group_members=presenting_group_members)

@app.route('/teacher/assignment/<int:assignment_id>/review')
def review_feedback(assignment_id):
    assignment = Assignment.query.get_or_404(assignment_id)
    cls = Class.query.get(assignment.class_id)
    
    if cls.teacher_id != session['user_id']:
        flash('Access denied', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    submissions = FeedbackSubmission.query.filter_by(assignment_id=assignment_id).all()
    
    feedback_data = []
    for submission in submissions:
        evaluator = User.query.get(submission.evaluator_user_id)
        presenting_group = Group.query.get(submission.presenting_group_id)
        items = FeedbackItem.query.filter_by(submission_id=submission.id).all()
        
        for item in items:
            target_name = presenting_group.name if item.target == 'group' else User.query.get(item.target_user_id).name
            feedback_data.append({
                'evaluator': evaluator.name,
                'presenting_group': presenting_group.name,
                'target': target_name,
                'type': item.target,
                'content': item.content
            })
    
    groups = Group.query.filter_by(class_id=assignment.class_id).all()
    all_students = []
    for group in groups:
        members = GroupMember.query.filter_by(group_id=group.id).all()
        for member in members:
            user = User.query.get(member.user_id)
            all_students.append({'id': user.id, 'name': user.name, 'group': group.name})
    
    teacher_notes = TeacherNote.query.filter_by(assignment_id=assignment_id).all()
    notes_dict = {note.target_user_id: note.note for note in teacher_notes}
    
    return render_template('review_feedback.html',
                         assignment=assignment,
                         feedback_data=feedback_data,
                         students=all_students,
                         notes_dict=notes_dict)

@app.route('/teacher/assignment/<int:assignment_id>/add_note', methods=['POST'])
@teacher_required
def add_teacher_note(assignment_id):
    assignment = Assignment.query.get_or_404(assignment_id)
    cls = Class.query.get(assignment.class_id)
    
    if cls.teacher_id != session['user_id']:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    student_id = request.form['student_id']
    note_content = request.form['note']
    
    existing_note = TeacherNote.query.filter_by(
        assignment_id=assignment_id,
        target_user_id=student_id
    ).first()
    
    if existing_note:
        existing_note.note = note_content
    else:
        note = TeacherNote(
            assignment_id=assignment_id,
            target_user_id=student_id,
            note=note_content
        )
        db.session.add(note)
    
    db.session.commit()
    return jsonify({'success': True})

@app.route('/teacher/assignment/<int:assignment_id>/release', methods=['POST'])
@teacher_required
def release_results(assignment_id):
    assignment = Assignment.query.get_or_404(assignment_id)
    cls = Class.query.get(assignment.class_id)
    
    if cls.teacher_id != session['user_id']:
        flash('Access denied', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    assignment.results_released = True
    db.session.commit()
    
    flash('Results released to students!', 'success')
    return redirect(url_for('review_feedback', assignment_id=assignment_id))

# API Endpoints
@app.route('/api/group/<int:group_id>/members')
@login_required
def get_group_members(group_id):
    group = Group.query.get_or_404(group_id)
    members = GroupMember.query.filter_by(group_id=group_id).all()
    
    members_data = []
    for member in members:
        user = User.query.get(member.user_id)
        members_data.append({
            'id': user.id,
            'name': user.name,
            'email': user.email
        })
    
    return jsonify(members_data)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)