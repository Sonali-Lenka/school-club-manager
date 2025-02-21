from flask import render_template, flash, redirect, url_for, request
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db
from models import User, Club
from forms import LoginForm, SignupForm, ClubForm

@app.route('/')
def index():
    clubs = Club.query.all()
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

@app.route('/clubs')
def clubs():
    clubs = Club.query.all()
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
        club = Club(
            name=form.name.data,
            description=form.description.data,
            creator_id=current_user.id
        )
        db.session.add(club)
        db.session.commit()
        flash('Club created successfully!', 'success')
        return redirect(url_for('clubs'))
    return render_template('create_club.html', form=form)

@app.route('/join-club/<int:club_id>')
@login_required
def join_club(club_id):
    club = Club.query.get_or_404(club_id)
    if club not in current_user.clubs_joined:
        current_user.clubs_joined.append(club)
        db.session.commit()
        flash(f'You have joined {club.name}!', 'success')
    return redirect(url_for('club_details', club_id=club_id))
