from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from functools import wraps
import secrets
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from supabase import create_client, Client
from werkzeug.security import generate_password_hash, check_password_hash
import pytz
import random
import string

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Security configurations
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'  # HTTPS only in production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=4)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file upload

# Flask-Mail configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@peerevaluation.com')

mail = Mail(app)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Security headers middleware
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    if os.environ.get('FLASK_ENV') == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Supabase configuration
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')

# Validate required environment variables
if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set in environment variables")

# Initialize supabase with error handling
supabase = None
try:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    print("✅ Supabase connected successfully")
except Exception as e:
    print(f"⚠️  Warning: Could not connect to Supabase: {e}")
    raise


# Timezone helper for US East Coast time
EST = pytz.timezone('US/Eastern')

def get_est_now():
    """Get current time in US Eastern Time"""
    return datetime.now(EST)

def parse_iso_datetime(date_str):
    """Robust ISO 8601 datetime parser for Python 3.9"""
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str)
    except ValueError:
        try:
            # Handle Z suffix
            if date_str.endswith('Z'):
                date_str = date_str.replace('Z', '+00:00')
            
            # Handle variable microsecond precision
            if '.' in date_str:
                # Find where the timezone part starts
                plus_idx = date_str.find('+')
                minus_idx = date_str.rfind('-') # Be careful with date separators
                
                # Assuming ISO format YYYY-MM-DDTHH:MM:SS.mmmmmm+HH:MM
                # The minus sign for timezone is after the T.
                t_idx = date_str.find('T')
                if t_idx != -1:
                    minus_idx = date_str.find('-', t_idx)
                
                tz_idx = -1
                if plus_idx != -1:
                    tz_idx = plus_idx
                elif minus_idx != -1:
                    # Check if this minus is for timezone (usually 3 chars from end or 6 chars from end)
                    # e.g. -05:00 (6 chars) or -0500 (5 chars)
                    if len(date_str) - minus_idx <= 6:
                        tz_idx = minus_idx
                
                if tz_idx != -1:
                    main_part = date_str[:tz_idx]
                    tz_part = date_str[tz_idx:]
                    
                    # Split main part to get microseconds
                    if '.' in main_part:
                        dt_part, us_part = main_part.split('.')
                        # Pad to 6 digits
                        if len(us_part) < 6:
                            us_part = us_part.ljust(6, '0')
                        elif len(us_part) > 6:
                            us_part = us_part[:6]
                        
                        return datetime.fromisoformat(f"{dt_part}.{us_part}{tz_part}")
            
            raise
        except Exception:
            # If all else fails, try to return naive datetime if possible or re-raise
            raise ValueError(f"Invalid isoformat string: {date_str}")

def convert_utc_to_est(utc_time_str):
    """Convert UTC ISO string to EST string"""
    try:
        # Parse UTC time
        utc_time = parse_iso_datetime(utc_time_str)
        
        # Convert to EST
        if utc_time.tzinfo is None:
            # If no timezone info, assume UTC
            utc_time = utc_time.replace(tzinfo=pytz.UTC)
        
        est_time = utc_time.astimezone(EST)
        return est_time.isoformat()
    except:
        return utc_time_str

def generate_verification_code():
    """Generate a 6-digit verification code"""
    return ''.join(random.choices(string.digits, k=6))

def send_verification_email(email, code):
    """Send verification code via email"""
    try:
        if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
            # For development, just log the code
            print(f"📧 Verification code for {email}: {code}")
            return True
        
        msg = Message(
            'Peer Evaluation Platform - Verification Code',
            recipients=[email]
        )
        msg.body = f"""
Hello,

Thank you for registering with the Peer Evaluation Platform.

Your verification code is: {code}

This code will expire in 10 minutes.

If you did not request this code, please ignore this email.

Best regards,
Peer Evaluation Platform
"""
        mail.send(msg)
        return True
    except Exception as e:
        print(f"❌ Error sending email: {e}")
        return False

# Authentication decorators
def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'teacher':
            # Check if this is an API request
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'student':
            return jsonify({'error': 'Unauthorized'}), 401
        
        # Check if student session is still valid (4 hours)
        if session.get('role') == 'student':
            created_at = session.get('created_at')
            if created_at:
                created_time = parse_iso_datetime(created_at)
                if created_time.tzinfo is None:
                    created_time = pytz.timezone('US/Eastern').localize(created_time)
                if get_est_now() - created_time > timedelta(hours=4):
                    session.clear()
                    return jsonify({'error': 'Session expired'}), 401
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        
        # Check if student session is still valid (4 hours)
        if session.get('role') == 'student':
            created_at = session.get('created_at')
            if created_at:
                created_time = parse_iso_datetime(created_at)
                if created_time.tzinfo is None:
                    created_time = pytz.timezone('US/Eastern').localize(created_time)
                if get_est_now() - created_time > timedelta(hours=4):
                    session.clear()
                    return jsonify({'error': 'Session expired'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('role') == 'teacher':
            return redirect(url_for('teacher_dashboard'))
        elif session.get('role') == 'student':
            return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        passcode = data.get('passcode')  # For student login
        student_name = data.get('student_name')  # For student login
        guest_login = data.get('guest_login')  # For guest login
        
        try:
            # Check if this is teacher login (has email)
            if email:
                response = supabase.table('teachers').select('*').eq('email', email).execute()
                
                if response.data and len(response.data) > 0:
                    teacher = response.data[0]
                    # Verify password hash
                    if check_password_hash(teacher['password'], password):
                        session['user_id'] = teacher['id']
                        session['role'] = 'teacher'
                        session['name'] = teacher['name']
                        return jsonify({'success': True, 'redirect': url_for('teacher_dashboard')})
                    else:
                        return jsonify({'error': 'Invalid credentials'}), 401
                else:
                    return jsonify({'error': 'Invalid credentials'}), 401
            # Student login with name and passcode
            elif passcode and student_name:
                # For student login, we need to search by name first, then verify passcode
                student_response = supabase.table('students').select('*').eq('name', student_name).execute()
                
                if student_response.data and len(student_response.data) > 0:
                    # Find all matching students with correct passcode
                    matching_students = []
                    for student in student_response.data:
                        if check_password_hash(student['passcode'], passcode):
                            matching_students.append(student)
                    
                    if not matching_students:
                        return jsonify({'error': 'Invalid passcode'}), 401
                    
                    # If student is in multiple classes, return class list for selection
                    if len(matching_students) > 1:
                        classes_info = []
                        for student in matching_students:
                            class_response = supabase.table('classes').select('id, name').eq('id', student['class_id']).execute()
                            if class_response.data:
                                classes_info.append({
                                    'student_id': student['id'],
                                    'class_id': student['class_id'],
                                    'class_name': class_response.data[0]['name'],
                                    'team_id': student['team_id']
                                })
                        return jsonify({'success': True, 'multiple_classes': True, 'classes': classes_info})
                    
                    # Single class - proceed with login
                    student = matching_students[0]
                    
                    # Check access expiration
                    if student.get('access_expires_at'):
                        expires_at = parse_iso_datetime(student['access_expires_at'])
                        if get_est_now().replace(tzinfo=None) > expires_at.replace(tzinfo=None):
                            return jsonify({'error': 'Access has expired'}), 401
                    
                    # Check device token
                    if student.get('device_token'):
                        cookie_token = request.cookies.get('device_token')
                        if not cookie_token or cookie_token != student['device_token']:
                            return jsonify({'error': 'Login restricted to the original device'}), 401
                    else:
                        # Lock to this device
                        new_device_token = secrets.token_urlsafe(32)
                        supabase.table('students').update({'device_token': new_device_token}).eq('id', student['id']).execute()
                        student['device_token'] = new_device_token
                    
                    # Create session for student
                    session['user_id'] = student['id']
                    session['role'] = 'student'
                    session['name'] = student['name']
                    session['class_id'] = student['class_id']
                    session['team_id'] = student['team_id']
                    session['created_at'] = get_est_now().isoformat()
                    
                    response = jsonify({'success': True, 'redirect': url_for('student_dashboard')})
                    response.set_cookie('device_token', student['device_token'], max_age=31536000, httponly=True)
                    return response
                else:
                    return jsonify({'error': 'Invalid passcode'}), 401
            # Guest login
            elif guest_login:
                name = data.get('name', '').strip()
                guest_passcode = data.get('passcode', '').strip()
                
                if not name:
                    return jsonify({'error': 'Please provide a name'}), 400
                
                if not guest_passcode:
                    return jsonify({'error': 'Please provide a passcode'}), 400
                
                # Try to find an existing guest (added by teacher or previously created)
                existing_students = supabase.table('students').select('*').eq('name', name).execute()
                
                matching_guests = []
                if existing_students.data:
                    for student in existing_students.data:
                        # Check if it's a guest (student_id is 'non-student' or empty)
                        if student.get('student_id') in ['non-student', '']:
                            # Check if passcode matches (hashed or preset 449922)
                            if check_password_hash(student['passcode'], guest_passcode):
                                matching_guests.append(student)
                
                if not matching_guests:
                    return jsonify({'error': 'Guest account not found or invalid passcode.'}), 401
                
                # If guest is in multiple classes, return class list for selection
                if len(matching_guests) > 1:
                    classes_info = []
                    for student in matching_guests:
                        class_response = supabase.table('classes').select('id, name').eq('id', student['class_id']).execute()
                        if class_response.data:
                            classes_info.append({
                                'student_id': student['id'],
                                'class_id': student['class_id'],
                                'class_name': class_response.data[0]['name'],
                                'team_id': student['team_id']
                            })
                    return jsonify({'success': True, 'multiple_classes': True, 'classes': classes_info})
                
                # Single class - proceed with login
                student = matching_guests[0]
                
                # Check access expiration
                if student.get('access_expires_at'):
                    expires_at = parse_iso_datetime(student['access_expires_at'])
                    if get_est_now().replace(tzinfo=None) > expires_at.replace(tzinfo=None):
                        return jsonify({'error': 'Access has expired'}), 401
                
                # Check device token
                if student.get('device_token'):
                    cookie_token = request.cookies.get('device_token')
                    if not cookie_token or cookie_token != student['device_token']:
                        return jsonify({'error': 'Login restricted to the original device'}), 401
                else:
                    # Lock to this device
                    new_device_token = secrets.token_urlsafe(32)
                    supabase.table('students').update({'device_token': new_device_token}).eq('id', student['id']).execute()
                    student['device_token'] = new_device_token

                # Found matching guest account
                session['user_id'] = student['id']
                session['role'] = 'student'
                session['name'] = student['name']
                session['class_id'] = student['class_id']
                session['team_id'] = student['team_id']
                session['created_at'] = get_est_now().isoformat()
                
                response = jsonify({'success': True, 'redirect': url_for('student_dashboard')})
                response.set_cookie('device_token', student['device_token'], max_age=31536000, httponly=True)
                return response
            else:
                return jsonify({'error': 'Please provide email or passcode'}), 400
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    return render_template('login.html')

@app.route('/select-class', methods=['POST'])
def select_class():
    """Handle class selection for students in multiple classes"""
    try:
        data = request.get_json()
        student_id = data.get('student_id')
        class_id = data.get('class_id')
        team_id = data.get('team_id')
        
        if not student_id:
            return jsonify({'error': 'Invalid request'}), 400
        
        # Get student info
        student_response = supabase.table('students').select('*').eq('id', student_id).execute()
        if not student_response.data:
            return jsonify({'error': 'Student not found'}), 404
        
        student = student_response.data[0]
        
        # Check access expiration only
        if student.get('access_expires_at'):
            expires_at = parse_iso_datetime(student['access_expires_at'])
            if get_est_now().replace(tzinfo=None) > expires_at.replace(tzinfo=None):
                return jsonify({'error': 'Access has expired'}), 401
        
        # Device token was already verified during initial login
        # Just use the existing token or set one if not present
        device_token = student.get('device_token')
        if not device_token:
            device_token = secrets.token_urlsafe(32)
            supabase.table('students').update({'device_token': device_token}).eq('id', student['id']).execute()
        
        # Create session
        session['user_id'] = student['id']
        session['role'] = 'student'
        session['name'] = student['name']
        session['class_id'] = class_id
        session['team_id'] = team_id
        session['created_at'] = get_est_now().isoformat()
        
        response = jsonify({'success': True, 'redirect': url_for('student_dashboard')})
        response.set_cookie('device_token', device_token, max_age=31536000, httponly=True)
        return response
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def register():
    if request.method == 'POST':
        data = request.get_json()
        action = data.get('action', 'request_code')
        
        if action == 'request_code':
            # Step 1: Validate email and send verification code
            email = data.get('email', '').strip().lower()
            
            # Validate @monmouth.edu email domain
            if not email.endswith('@monmouth.edu'):
                return jsonify({'error': 'Only @monmouth.edu email addresses are allowed for teacher accounts'}), 400
            
            # Check if email already exists
            try:
                existing = supabase.table('teachers').select('id').eq('email', email).execute()
                if existing.data and len(existing.data) > 0:
                    return jsonify({'error': 'An account with this email already exists'}), 400
            except Exception as e:
                return jsonify({'error': 'Database error'}), 500
            
            # Generate and store verification code
            code = generate_verification_code()
            expiry = (get_est_now() + timedelta(minutes=10)).isoformat()
            
            # Store code in session (temporary storage)
            session['verification_code'] = code
            session['verification_email'] = email
            session['verification_expiry'] = expiry
            
            # Send verification email
            if send_verification_email(email, code):
                return jsonify({'success': True, 'message': 'Verification code sent to your email'})
            else:
                return jsonify({'error': 'Failed to send verification email. Please try again.'}), 500
        
        elif action == 'verify_and_register':
            # Step 2: Verify code and create account
            name = data.get('name')
            email = data.get('email', '').strip().lower()
            password = data.get('password')
            code = data.get('code')
            
            # Validate email domain again
            if not email.endswith('@monmouth.edu'):
                return jsonify({'error': 'Only @monmouth.edu email addresses are allowed'}), 400
            
            # Verify code
            stored_code = session.get('verification_code')
            stored_email = session.get('verification_email')
            stored_expiry = session.get('verification_expiry')
            
            if not stored_code or not stored_email or not stored_expiry:
                return jsonify({'error': 'No verification code found. Please request a new one.'}), 400
            
            if email != stored_email:
                return jsonify({'error': 'Email does not match verification request'}), 400
            
            if code != stored_code:
                return jsonify({'error': 'Invalid verification code'}), 400
            
            # Check if code expired
            expiry_time = parse_iso_datetime(stored_expiry)
            if get_est_now() > expiry_time:
                session.pop('verification_code', None)
                session.pop('verification_email', None)
                session.pop('verification_expiry', None)
                return jsonify({'error': 'Verification code has expired. Please request a new one.'}), 400
            
            try:
                # Hash the password before storing using pbkdf2 (compatible with Python 3.9)
                hashed_password = generate_password_hash(password, method='pbkdf2')
                
                response = supabase.table('teachers').insert({
                    'name': name,
                    'email': email,
                    'password': hashed_password,
                    'created_at': get_est_now().isoformat()
                }).execute()
                
                # Clear verification data from session
                session.pop('verification_code', None)
                session.pop('verification_email', None)
                session.pop('verification_expiry', None)
                
                return jsonify({'success': True, 'redirect': url_for('login')})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        else:
            return jsonify({'error': 'Invalid action'}), 400
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/teacher/dashboard')
@teacher_required
def teacher_dashboard():
    return render_template('teacher_dashboard.html')

@app.route('/student/dashboard')
@student_required
def student_dashboard():
    return render_template('student_dashboard.html')

# API Routes for Classes
@app.route('/api/classes', methods=['GET', 'POST'])
@teacher_required
def manage_classes():
    if request.method == 'POST':
        data = request.get_json()
        class_name = data.get('class_name')
        
        try:
            # Create class using EST time
            class_response = supabase.table('classes').insert({
                'name': class_name,
                'teacher_id': session['user_id'],
                'created_at': get_est_now().isoformat()
            }).execute()
            
            if not class_response.data or len(class_response.data) == 0:
                return jsonify({'error': 'Failed to create class - no response from server'}), 500
            
            class_id = class_response.data[0]['id']
            
            # Create default "Guests" team
            supabase.table('teams').insert({
                'name': 'Guests',
                'class_id': class_id,
                'created_at': get_est_now().isoformat()
            }).execute()
            
            return jsonify({'success': True, 'class': class_response.data[0]})
        except Exception as e:
            print(f"ERROR creating class: {str(e)}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': f'Failed to create class: {str(e)}'}), 500
    
    else:  # GET
        try:
            response = supabase.table('classes').select('*').eq('teacher_id', session['user_id']).execute()
            return jsonify({'classes': response.data})
        except Exception as e:
            print(f"ERROR getting classes: {str(e)}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': f'Failed to load classes: {str(e)}'}), 500

@app.route('/api/classes/<int:class_id>/teams', methods=['GET', 'POST'])
@teacher_required
def manage_teams(class_id):
    if request.method == 'POST':
        data = request.get_json()
        team_name = data.get('team_name')
        
        try:
            # Check if team name already exists in this class
            existing_team = supabase.table('teams').select('*').eq('class_id', class_id).eq('name', team_name).execute()
            if existing_team.data:
                return jsonify({'error': f'Team "{team_name}" already exists in this class'}), 400

            response = supabase.table('teams').insert({
                'name': team_name,
                'class_id': class_id,
                'created_at': datetime.now().isoformat()
            }).execute()
            
            new_team = response.data[0]
            
            # No longer creating default Placeholder member
            # Teams can now exist with no members
            
            return jsonify({'success': True, 'team': new_team})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    else:  # GET
        try:
            # Fetch all teams but filter out 'Teachers' team
            response = supabase.table('teams').select('*').eq('class_id', class_id).neq('name', 'Teachers').execute()
            return jsonify({'teams': response.data})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>/teams/<int:team_id>/members')
@teacher_required
def get_team_members(class_id, team_id):
    try:
        # Get all students in this team
        response = supabase.table('students').select('*').eq('team_id', team_id).eq('class_id', class_id).execute()
        # Remove passcode from response for security
        members = [{'id': s['id'], 'name': s['name'], 'student_id': s.get('student_id')} for s in response.data]
        return jsonify({'members': members})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>/teams/<int:team_id>', methods=['DELETE'])
@teacher_required
def delete_team(class_id, team_id):
    try:
        # Verify team belongs to this class
        team_check = supabase.table('teams').select('id').eq('id', team_id).eq('class_id', class_id).execute()
        if not team_check.data:
            return jsonify({'error': 'Team not found'}), 404
        
        # Delete all students in the team first
        supabase.table('students').delete().eq('team_id', team_id).execute()
        
        # Delete the team
        supabase.table('teams').delete().eq('id', team_id).execute()
        
        return jsonify({'success': True, 'message': 'Team deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>/students')
@teacher_required
def get_class_students(class_id):
    try:
        # Get all students in this class
        response = supabase.table('students').select('*').eq('class_id', class_id).execute()
        # Remove passcode from response for security
        students = [{'id': s['id'], 'name': s['name'], 'student_id': s.get('student_id'), 'team_id': s.get('team_id')} for s in response.data]
        return jsonify({'students': students})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>/assignments', methods=['GET', 'POST'])
@teacher_required
def manage_assignments(class_id):
    if request.method == 'POST':
        data = request.get_json()
        
        try:
            response = supabase.table('assignments').insert({
                'name': data.get('name'),
                'class_id': class_id,
                'start_time': convert_utc_to_est(data.get('start_time')),
                'end_time': convert_utc_to_est(data.get('end_time')),
                'created_at': get_est_now().isoformat()
            }).execute()
            
            return jsonify({'success': True, 'assignment': response.data[0]})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    else:  # GET
        try:
            response = supabase.table('assignments').select('*').eq('class_id', class_id).execute()
            return jsonify({'assignments': response.data})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/api/assignments/<int:assignment_id>', methods=['PUT', 'DELETE'])
@teacher_required
def update_assignment(assignment_id):
    if request.method == 'DELETE':
        try:
            supabase.table('assignments').delete().eq('id', assignment_id).execute()
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    data = request.get_json()
    
    try:
        response = supabase.table('assignments').update({
            'name': data.get('name'),
            'start_time': convert_utc_to_est(data.get('start_time')),
            'end_time': convert_utc_to_est(data.get('end_time'))
        }).eq('id', assignment_id).execute()
        
        return jsonify({'success': True, 'assignment': response.data[0]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>/access-link', methods=['POST'])
@teacher_required
def generate_access_link(class_id):
    try:
        data = request.get_json() or {}
        hours = data.get('hours', 2)  # Default to 2 hours
        
        # Validate hours (must be between 0.1 and 24 hours)
        try:
            hours = float(hours)
            if hours <= 0 or hours > 24:
                return jsonify({'error': 'Hours must be between 0.1 and 24'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid hours value'}), 400
        
        token = secrets.token_urlsafe(32)
        # Link expires in specified hours (default 2 hours)
        expires_at = get_est_now() + timedelta(hours=hours)
        
        supabase.table('access_tokens').insert({
            'token': token,
            'class_id': class_id,
            'expires_at': expires_at.isoformat(),
            'created_at': get_est_now().isoformat()
        }).execute()
        
        link = url_for('join_class', token=token, _external=True)
        return jsonify({'success': True, 'link': link, 'expires_at': expires_at.isoformat(), 'hours': hours})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/teams/<int:team_id>/add-students', methods=['POST'])
@teacher_required
def add_students_to_team(team_id):
    """Teacher inputs text with student list. Format depends on team type:
    - Regular teams: 'Full Name StudentID' per line (e.g., 'Mike Lee S123456')
    - Guests team: Just 'Full Name' per line (e.g., 'Mike Lee')
    """
    data = request.get_json()
    text_input = data.get('text', '').strip()  # Multi-line text input
    
    try:
        added_students = []
        lines = [line.strip() for line in text_input.split('\n') if line.strip()]
        
        # Get team to find class_id and team name
        team = supabase.table('teams').select('class_id', 'name').eq('id', team_id).single().execute()
        class_id = team.data['class_id']
        team_name = team.data['name']
        is_guest_team = team_name == 'Guests'
        
        # Get class name for guest passcode
        class_name = ''
        if is_guest_team:
            class_response = supabase.table('classes').select('name').eq('id', class_id).single().execute()
            class_name = class_response.data['name']
        
        for line in lines:
            if is_guest_team:
                # For Guests team, just use the full line as name
                name = line.strip()
                # Ensure unique name
                name = get_unique_student_name(name, team_id)
                
                student_id = 'non-student'
                
                # Create guest student account with class name as passcode
                student_data = {
                    'name': name,
                    'team_id': team_id,
                    'class_id': class_id,
                    'student_id': 'non-student',
                    'passcode': generate_password_hash(class_name, method='pbkdf2'),
                    'is_pre_added': False,
                    'created_at': get_est_now().isoformat()
                }
                
                response = supabase.table('students').insert(student_data).execute()
                added_students.append({'name': name, 'student_id': 'non-student'})
            else:
                # For regular teams, parse "Full Name StudentID" format
                parts = line.rsplit(' ', 1)
                if len(parts) == 2:
                    name = parts[0].strip()
                    # Ensure unique name
                    name = get_unique_student_name(name, team_id)
                    
                    student_id = parts[1].strip()
                    
                    # Create student with available fields only
                    student_data = {
                        'name': name,
                        'team_id': team_id,
                        'class_id': class_id,
                        'created_at': get_est_now().isoformat()
                    }
                    
                    # Try to add optional fields if they exist
                    try:
                        student_data['student_id'] = student_id
                        student_data['passcode'] = generate_password_hash(student_id, method='pbkdf2')  # Hash the passcode
                        student_data['is_pre_added'] = True
                    except:
                        pass
                    
                    response = supabase.table('students').insert(student_data).execute()
                    added_students.append({'name': name, 'student_id': student_id})
        
        return jsonify({'success': True, 'added': added_students})
    except Exception as e:
        print(f"ERROR adding students: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/join/<token>', methods=['GET', 'POST'])
def join_class(token):
    if request.method == 'POST':
        data = request.get_json()
        student_name = data.get('student_name')
        student_id = data.get('student_id', '')
        team_id = data.get('team_id')
        is_guest = data.get('is_guest', False)
        
        try:
            # Verify token
            token_response = supabase.table('access_tokens').select('*').eq('token', token).execute()
            
            if not token_response.data or len(token_response.data) == 0:
                return jsonify({'error': 'Invalid token'}), 400
            
            token_data = token_response.data[0]
            expires_at = parse_iso_datetime(token_data['expires_at'])
            
            # Check if token expired (using EST time)
            if get_est_now().replace(tzinfo=None) > expires_at.replace(tzinfo=None):
                return jsonify({'error': 'Token expired'}), 400
            
            class_id = token_data['class_id']
            
            # Generate device token for this session
            device_token = secrets.token_urlsafe(32)
            
            # Guest join
            if is_guest:
                # Get class name for guest passcode
                class_response = supabase.table('classes').select('name').eq('id', class_id).execute()
                class_name = class_response.data[0]['name'] if class_response.data else 'Guest'
                
                # Get or create the "Guests" team for this class
                guests_team_response = supabase.table('teams').select('*').eq('class_id', class_id).eq('name', 'Guests').execute()
                
                if guests_team_response.data and len(guests_team_response.data) > 0:
                    guests_team = guests_team_response.data[0]
                else:
                    # Create "Guests" team if it doesn't exist
                    team_response = supabase.table('teams').insert({
                        'name': 'Guests',
                        'class_id': class_id,
                        'created_at': get_est_now().isoformat()
                    }).execute()
                    guests_team = team_response.data[0]
                
                # Check if student with this exact name already exists in this team
                existing_student_response = supabase.table('students').select('*').eq('name', student_name).eq('team_id', guests_team['id']).execute()
                
                if existing_student_response.data and len(existing_student_response.data) > 0:
                    # Student with this name already exists - log them in directly
                    student = existing_student_response.data[0]
                    # Update their access expiration and device token
                    supabase.table('students').update({
                        'access_expires_at': expires_at.isoformat(),
                        'device_token': device_token
                    }).eq('id', student['id']).execute()
                    student['device_token'] = device_token
                else:
                    # New guest - create account
                    student_response = supabase.table('students').insert({
                        'name': student_name,
                        'student_id': '',  # No student ID for guests
                        'passcode': generate_password_hash(class_name, method='pbkdf2'),  # Hash the class name as passcode
                        'team_id': guests_team['id'],
                        'class_id': class_id,
                        'is_pre_added': False,
                        'access_expires_at': expires_at.isoformat(), # Set access expiration
                        'device_token': device_token, # Set device token
                        'created_at': get_est_now().isoformat()
                    }).execute()
                    
                    student = student_response.data[0]
                team_id = guests_team['id']
            else:
                # Student join
                # First check if student with this name already exists in this team
                existing_student_response = supabase.table('students').select('*').eq('name', student_name).eq('team_id', team_id).execute()
                
                if existing_student_response.data and len(existing_student_response.data) > 0:
                    # Student with this name already exists - log them in directly
                    student = existing_student_response.data[0]
                    # Update their access expiration and device token
                    supabase.table('students').update({
                        'access_expires_at': expires_at.isoformat(),
                        'device_token': device_token
                    }).eq('id', student['id']).execute()
                    student['device_token'] = device_token
                else:
                    # Check if student was pre-added by teacher
                    pre_added_response = supabase.table('students').select('*').eq('student_id', student_id).eq('team_id', team_id).eq('is_pre_added', True).execute()
                    
                    if pre_added_response.data and len(pre_added_response.data) > 0:
                        # Student was pre-added by teacher, update their name
                        student = pre_added_response.data[0]
                        supabase.table('students').update({
                            'name': student_name,
                            'access_expires_at': expires_at.isoformat(),
                            'device_token': device_token
                        }).eq('id', student['id']).execute()
                    else:
                        # New student: create account with SID as passcode
                        student_response = supabase.table('students').insert({
                            'name': student_name,
                            'student_id': student_id,
                            'passcode': generate_password_hash(student_id, method='pbkdf2'),  # Hash the student ID used as passcode
                            'team_id': team_id,
                            'class_id': class_id,
                            'is_pre_added': False,
                            'access_expires_at': expires_at.isoformat(), # Set access expiration
                            'device_token': device_token, # Set device token
                            'created_at': get_est_now().isoformat()
                        }).execute()
                        student = student_response.data[0]
            
            # Create session
            session['user_id'] = student['id']
            session['role'] = 'student'
            session['name'] = student['name']
            session['class_id'] = class_id
            session['team_id'] = team_id
            session['created_at'] = get_est_now().isoformat()
            
            response = jsonify({'success': True, 'redirect': url_for('student_dashboard')})
            # Set device token cookie (valid for 1 year)
            response.set_cookie('device_token', device_token, max_age=31536000, httponly=True)
            return response
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    else:  # GET
        try:
            # Verify token
            token_response = supabase.table('access_tokens').select('*').eq('token', token).execute()
            
            if not token_response.data or len(token_response.data) == 0:
                return render_template('error.html', message='Invalid access link')
            
            token_data = token_response.data[0]
            expires_at = parse_iso_datetime(token_data['expires_at'])
            
            # Check expiration using EST time
            if get_est_now().replace(tzinfo=None) > expires_at.replace(tzinfo=None):
                return render_template('error.html', message='Access link has expired')
            
            # Get teams for the class
            teams_response = supabase.table('teams').select('*').eq('class_id', token_data['class_id']).execute()
            
            return render_template('join_class.html', token=token, teams=teams_response.data)
        except Exception as e:
            return render_template('error.html', message=str(e))

@app.route('/api/student/assignments')
@student_required
def get_student_assignments():
    try:
        class_id = session.get('class_id')
        
        response = supabase.table('assignments').select('*').eq('class_id', class_id).order('start_time', desc=False).execute()
        
        # Return all assignments sorted by start_time (upcoming first)
        return jsonify({'assignments': response.data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/student/teams')
@student_required
def get_student_teams():
    try:
        class_id = session.get('class_id')
        
        # Fetch teams, excluding 'Guests' and 'Teachers'
        response = supabase.table('teams').select('*, students(*)').eq('class_id', class_id).neq('name', 'Guests').neq('name', 'Teachers').execute()
        
        # No longer filtering out Placeholder - teams can have any members or be empty
        teams_data = response.data
        
        return jsonify({'teams': teams_data, 'my_team_id': session.get('team_id')})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/evaluations', methods=['POST'])
@login_required
def submit_evaluation():
    data = request.get_json()
    evaluated_team_id = data.get('evaluated_team_id')
    
    try:
        # Check if evaluating Guests team
        evaluated_team = supabase.table('teams').select('*').eq('id', evaluated_team_id).single().execute()
        if evaluated_team.data and evaluated_team.data['name'] == 'Guests':
             return jsonify({'error': 'Cannot evaluate the Guests group'}), 403

        # Determine evaluator ID
        if session.get('role') == 'teacher':
            # Get assignment to find class_id
            assignment = supabase.table('assignments').select('class_id').eq('id', data.get('assignment_id')).single().execute()
            class_id = assignment.data['class_id']
            
            # Get or create teacher student record
            evaluator = get_or_create_teacher_student_record(class_id, session.get('name', 'Teacher'))
            evaluator_id = evaluator['id']
        else:
            evaluator_id = session['user_id']
            # Check if student is evaluating their own team
            if str(session.get('team_id')) == str(evaluated_team_id):
                return jsonify({'error': 'You cannot evaluate your own team'}), 403

        # Check for existing evaluation and delete it if it exists (replacement logic)
        existing = supabase.table('team_evaluations').select('id').eq('assignment_id', data.get('assignment_id')).eq('evaluated_team_id', data.get('evaluated_team_id')).eq('evaluator_student_id', evaluator_id).execute()
        
        if existing.data:
            # Delete existing evaluation
            for eval_record in existing.data:
                # First delete member evaluations linked to this team evaluation
                supabase.table('member_evaluations').delete().eq('team_evaluation_id', eval_record['id']).execute()
                # Then delete the team evaluation
                supabase.table('team_evaluations').delete().eq('id', eval_record['id']).execute()

        # Store team evaluation
        team_eval = supabase.table('team_evaluations').insert({
            'assignment_id': data.get('assignment_id'),
            'evaluated_team_id': data.get('evaluated_team_id'),
            'evaluator_student_id': evaluator_id,
            'team_comment': data.get('team_comment'),
            'team_score': data.get('team_score'),
            'created_at': get_est_now().isoformat()
        }).execute()
        
        # Store individual evaluations
        for member_eval in data.get('member_evaluations', []):
            # No longer skipping any students - all can be evaluated
            student_id = member_eval.get('student_id')

            supabase.table('member_evaluations').insert({
                'team_evaluation_id': team_eval.data[0]['id'],
                'evaluated_student_id': student_id,
                'comment': member_eval.get('comment'),
                'score': member_eval.get('score'),
                'created_at': get_est_now().isoformat()
            }).execute()
            
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500@app.route('/api/evaluations/check/<int:assignment_id>/<int:team_id>')
@student_required
def check_evaluation_exists(assignment_id, team_id):
    try:
        # Check if evaluation exists for this student, assignment, and team
        existing = supabase.table('team_evaluations').select('id').eq('assignment_id', assignment_id).eq('evaluated_team_id', team_id).eq('evaluator_student_id', session['user_id']).execute()
        
        exists = len(existing.data) > 0
        return jsonify({'exists': exists})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/teacher/evaluations/<int:assignment_id>')
@teacher_required
def get_all_evaluations(assignment_id):
    try:
        # First get all team evaluations for this assignment
        team_evals = supabase.table('team_evaluations').select('*').eq('assignment_id', assignment_id).execute()
        
        # For each team evaluation, fetch the related data
        result = []
        for team_eval in team_evals.data:
            # Get evaluator student info
            evaluator = supabase.table('students').select('id, name, team:teams(name)').eq('id', team_eval['evaluator_student_id']).single().execute()
            
            # Get evaluated team info
            evaluated_team = supabase.table('teams').select('id, name').eq('id', team_eval['evaluated_team_id']).single().execute()
            
            # Get member evaluations
            member_evals = supabase.table('member_evaluations').select('*').eq('team_evaluation_id', team_eval['id']).execute()
            
            # Enrich member evaluations with student names
            for member_eval in member_evals.data:
                student = supabase.table('students').select('id, name').eq('id', member_eval['evaluated_student_id']).single().execute()
                member_eval['evaluated_student'] = student.data
            
            # Build the evaluation object
            eval_obj = {
                'id': team_eval['id'],
                'assignment_id': team_eval['assignment_id'],
                'evaluated_team_id': team_eval['evaluated_team_id'],
                'evaluator_student_id': team_eval['evaluator_student_id'],
                'team_comment': team_eval['team_comment'],
                'team_score': team_eval['team_score'],
                'created_at': team_eval['created_at'],
                'evaluator': evaluator.data,
                'evaluated_team': evaluated_team.data,
                'member_evaluations': member_evals.data
            }
            result.append(eval_obj)
        
        return jsonify({'evaluations': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/teacher/report/<int:student_id>/<int:assignment_id>')
@teacher_required
def generate_report(student_id, assignment_id):
    try:
        # Get student info
        student = supabase.table('students').select('*, team:teams(name), class:classes(name)').eq('id', student_id).single().execute()
        
        # Get assignment info
        assignment = supabase.table('assignments').select('*').eq('id', assignment_id).single().execute()
        
        # Get team evaluations for student's team
        team_evals = supabase.table('team_evaluations').select('''
            *,
            evaluator:students!evaluator_student_id(name)
        ''').eq('assignment_id', assignment_id).eq('evaluated_team_id', student.data['team_id']).execute()
        
        # Get individual evaluations for this student
        member_evals = supabase.table('member_evaluations').select('''
            *,
            team_evaluation:team_evaluations(evaluator:students!evaluator_student_id(name))
        ''').eq('evaluated_student_id', student_id).execute()
        
        report = {
            'student': student.data,
            'assignment': assignment.data,
            'team_evaluations': team_evals.data,
            'member_evaluations': member_evals.data
        }
        
        return jsonify({'report': report})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<int:class_id>/students/<int:student_id>', methods=['DELETE'])
@teacher_required
def delete_student(class_id, student_id):
    try:
        # Get student info first
        student_response = supabase.table('students').select('*').eq('id', student_id).execute()
        if not student_response.data:
            return jsonify({'error': 'Student not found'}), 404
        
        # Delete the student
        supabase.table('students').delete().eq('id', student_id).execute()
        
        # No longer deleting teams when removing students
        # Teams can now exist with no members
        
        return jsonify({'success': True, 'message': 'Student deleted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_unique_student_name(original_name, team_id):
    """Helper to generate unique name like 'Name (2)' if duplicate exists in team"""
    # Check if name already exists in this team
    existing = supabase.table('students').select('id').eq('team_id', team_id).eq('name', original_name).execute()
    
    if not existing.data:
        return original_name
    
    # Name exists, append " (2)", " (3)", etc.
    counter = 2
    while True:
        new_name = f"{original_name} ({counter})"
        existing = supabase.table('students').select('id').eq('team_id', team_id).eq('name', new_name).execute()
        if not existing.data:
            return new_name
        counter += 1

def get_or_create_teacher_student_record(class_id, teacher_name):
    """
    Ensures a 'student' record exists for the teacher in the given class
    so they can submit evaluations.
    """
    # 1. Check if "Teachers" team exists for this class
    teachers_team_response = supabase.table('teams').select('*').eq('class_id', class_id).eq('name', 'Teachers').execute()
    
    if teachers_team_response.data:
        teachers_team = teachers_team_response.data[0]
    else:
        # Create "Teachers" team
        team_response = supabase.table('teams').insert({
            'name': 'Teachers',
            'class_id': class_id,
            'created_at': get_est_now().isoformat()
        }).execute()
        teachers_team = team_response.data[0]
    
    # 2. Check if teacher student record exists
    # We use a special student_id format: 'teacher-{teacher_id}' or just 'teacher' if generic
    # But since we have teacher_name, let's use that to find them.
    # Better: use session['user_id'] to make it unique if we had multiple teachers.
    # For now, let's assume one teacher per class or just use name.
    # Let's use student_id = 'teacher' for simplicity as requested.
    
    teacher_student_response = supabase.table('students').select('*').eq('team_id', teachers_team['id']).eq('name', teacher_name).execute()
    
    if teacher_student_response.data:
        return teacher_student_response.data[0]
    else:
        # Create teacher student record
        student_response = supabase.table('students').insert({
            'name': teacher_name,
            'student_id': 'teacher',
            'passcode': generate_password_hash('teacher', method='pbkdf2'), # Dummy passcode
            'team_id': teachers_team['id'],
            'class_id': class_id,
            'is_pre_added': False,
            'created_at': get_est_now().isoformat()
        }).execute()
        return student_response.data[0]

if __name__ == '__main__':
    # Production: Vercel handles the server
    # Development: Run Flask development server
    is_production = os.environ.get('FLASK_ENV') == 'production'
    
    if is_production:
        # Production mode - let Vercel handle it
        pass
    else:
        # Development mode
        app.run(debug=True, host='0.0.0.0', port=5001)
