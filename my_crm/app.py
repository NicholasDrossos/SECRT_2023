from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crm.db'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(80), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('welcome'))
        else:
            flash('Login failed. Check username and/or password.')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/welcome')
@login_required
def welcome():
    if current_user.role == 'admin':
        return render_template('welcome.html', admin=True)
    return render_template('welcome.html', admin=False)


@app.route('/add_customer')
@login_required
def add_customer():
    # ... your code for adding a customer
    return render_template('add_customer.html')


@app.route('/view_customers')
@login_required
def view_customers():
    # ... your code for viewing customers
    return render_template('view_customers.html')


@app.route('/user_management')
@login_required
def user_management():
    if current_user.role == 'admin':
        all_users = User.query.all()  # Get all users from the database
        return render_template('user_management.html', all_users=all_users)
    else:
        flash('Access unauthorized.')
        return redirect(url_for('welcome'))


@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('Access unauthorized.')
        return redirect(url_for('welcome'))

    username = request.form.get('new_username')
    password = request.form.get('new_password')
    role = request.form.get('new_role')

    if not username or not password or not role:
        flash('Please fill all fields.')
        return redirect(url_for('user_management'))

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash('Username already exists.')
        return redirect(url_for('user_management'))

    new_user = User(username=username,
                    password=generate_password_hash(password, method='scrypt'),
                    role=role)
    db.session.add(new_user)
    db.session.commit()
    flash('User added successfully.')
    return redirect(url_for('user_management'))


@app.route('/remove_user', methods=['POST'])
@login_required
def remove_user():
    if current_user.role != 'admin':
        flash('Access unauthorized.')
        return redirect(url_for('welcome'))

    user_id = request.form.get('user_id')
    user_to_remove = User.query.get(user_id)

    if not user_to_remove:
        flash('User not found.')
        return redirect(url_for('user_management'))

    if user_to_remove.id == current_user.id:
        flash('You cannot remove yourself.')
        return redirect(url_for('user_management'))

    db.session.delete(user_to_remove)
    db.session.commit()
    flash('User removed successfully.')
    return redirect(url_for('user_management'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Manually adding an admin user for testing
        if not User.query.filter_by(username='owner').first():
            new_user = User(username='owner',
                            password=generate_password_hash('secrtowner', method='scrypt'),
                            role='admin')
            db.session.add(new_user)
            db.session.commit()
    app.run(debug=True)
