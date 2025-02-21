from flask import render_template, flash, redirect, url_for, request, abort
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db
from models import User, Club
from forms import LoginForm, SignupForm, ClubForm
from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def moderator_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (current_user.role not in ['moderator', 'admin']):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    clubs = Club.query.filter_by(status='active').all()
    return render_template('index.html', clubs=clubs)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Successfully logged in!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid email or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = SignupForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    users = User.query.all()
    clubs = Club.query.all()
    return render_template('admin/panel.html', users=users, clubs=clubs)

@app.route('/admin/users/<int:user_id>/role', methods=['POST'])
@login_required
@admin_required
def update_user_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')

    # Prevent self-demotion for the last admin
    if user.id == current_user.id and new_role != 'admin':
        admin_count = User.query.filter_by(role='admin').count()
        if admin_count <= 1:
            flash('Cannot remove the last admin user.', 'danger')
            return redirect(url_for('admin_panel'))

    if new_role in ['student', 'moderator', 'admin']:
        user.role = new_role
        user.is_admin = (new_role == 'admin')
        db.session.commit()
        flash(f'Updated role for {user.username} to {new_role}', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/clubs/<int:club_id>/status', methods=['POST'])
@login_required
@admin_required
def update_club_status(club_id):
    club = Club.query.get_or_404(club_id)
    new_status = request.form.get('status')
    if new_status in ['active', 'inactive', 'pending']:
        club.status = new_status
        db.session.commit()
        flash(f'Updated status for {club.name} to {new_status}', 'success')

        # Notify club creator of status change
        status_messages = {
            'active': 'approved and is now active',
            'inactive': 'deactivated',
            'pending': 'set to pending review'
        }
        flash(f'Your club "{club.name}" has been {status_messages[new_status]}.', 'info')
    return redirect(url_for('admin_panel'))

@app.route('/clubs')
def clubs():
    clubs = Club.query.filter_by(status='active').all()
    return render_template('clubs.html', clubs=clubs)

@app.route('/club/<int:club_id>')
def club_details(club_id):
    club = Club.query.get_or_404(club_id)
    return render_template('club_details.html', club=club)

@app.route('/create-club', methods=['GET', 'POST'])
@login_required
def create_club():
    form = ClubForm()
    if form.validate_on_submit():
        # Determine initial status based on user role
        initial_status = 'active' if current_user.role in ['admin', 'moderator'] else 'pending'

        club = Club(
            name=form.name.data,
            description=form.description.data,
            creator_id=current_user.id,
            status=initial_status
        )
        db.session.add(club)
        db.session.commit()

        if initial_status == 'pending':
            flash('Club created successfully! Waiting for admin approval.', 'success')
        else:
            flash('Club created successfully!', 'success')
        return redirect(url_for('clubs'))
    return render_template('create_club.html', form=form)

@app.route('/join-club/<int:club_id>')
@login_required
def join_club(club_id):
    club = Club.query.get_or_404(club_id)
    if club.status != 'active':
        flash('This club is not currently active', 'warning')
        return redirect(url_for('club_details', club_id=club_id))
    if club not in current_user.clubs_joined:
        current_user.clubs_joined.append(club)
        db.session.commit()
        flash(f'You have joined {club.name}!', 'success')
    return redirect(url_for('club_details', club_id=club_id))

@app.route('/admin/clubs/<int:club_id>/members/<int:user_id>/remove', methods=['POST'])
@login_required
@admin_required
def remove_club_member(club_id, user_id):
    try:
        club = Club.query.get_or_404(club_id)
        user = User.query.get_or_404(user_id)

        if user in club.members:
            # Remove the user from the club's members
            club.members.remove(user)
            db.session.commit()
            flash(f'Successfully removed {user.username} from {club.name}', 'success')
        else:
            flash(f'User {user.username} is not a member of {club.name}', 'warning')

    except Exception as e:
        db.session.rollback()
        flash(f'Error removing member: {str(e)}', 'danger')

    return redirect(url_for('admin_panel'))