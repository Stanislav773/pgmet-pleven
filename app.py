import os
import re
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'pgmet-pleven-2026-secret'

# Точен абсолютен път до базата данни
базисен_път = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(
    базисен_път, 'pgmet.db'
)

db = SQLAlchemy(app)

мениджър_вход = LoginManager()
мениджър_вход.init_app(app)
мениджър_вход.login_view = 'login'


class Потребител(UserMixin, db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(100), unique=True, nullable=False)
  email = db.Column(db.String(150), unique=True, nullable=False)
  password = db.Column(db.String(200), nullable=False)
  is_verified = db.Column(db.Boolean, default=True)


with app.app_context():
  db.create_all()


@мениджър_вход.user_loader
def зареди_потребител(user_id):
  return Потребител.query.get(int(user_id))


def слаба_парола(парола):
  слаби_списък = [
      '12345678',
      '123456789',
      '123456',
      'password',
      'qwerty',
      'qwerty123',
      'parola',
      'parola123',
      'admin',
      '11111111',
      '00000000',
  ]
  if парола.lower() in слаби_списък or len(парола) < 8:
    return True
  if not re.search(r'[A-Za-z]', парола) or not re.search(r'\d', парола):
    return True
  return False


@app.route('/')
def индекс():
  if current_user.is_authenticated:
    return redirect(url_for('home'))
  return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
  if request.method == 'POST':
    потребителско_име = request.form.get('username').strip()
    имейл = request.form.get('email').strip()
    парола = request.form.get('password')

    if слаба_парола(парола):
      flash(
          'Паролата е твърде слаба! Използвай поне 8 символа с букви и цифри.',
          'error',
      )
      return redirect(url_for('register'))

    if Потребител.query.filter_by(username=потребителско_име).first():
      flash('Това потребителско име вече е заето.', 'error')
      return redirect(url_for('register'))

    if Потребител.query.filter_by(email=имейл).first():
      flash('Този имейл вече е регистриран.', 'error')
      return redirect(url_for('register'))

    # Създаваме потребителя веднага в базата данни без нужда от код за потвърждение
    хеширана_парола = generate_password_hash(парола, method='scrypt')
    нов_потребител = Потребител(
        username=потребителско_име,
        email=имейл,
        password=хеширана_парола,
        is_verified=True,
    )
    db.session.add(нов_потребител)
    db.session.commit()

    flash(
        'Профилът беше създаден успешно! Вече можеш да влезеш с данните си.',
        'success',
    )
    return redirect(url_for('login'))

  return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
  if request.method == 'POST':
    входни_данни = request.form.get('login_input').strip()
    парола = request.form.get('password')

    потребител = Потребител.query.filter(
        (Потребител.email == входни_данни)
        | (Потребител.username == входни_данни)
    ).first()
    if потребител and check_password_hash(потребител.password, парола):
      login_user(потребител)
      return redirect(url_for('home'))
    else:
      flash('Невалиден имейл/потребителско име или парола.', 'error')

  return render_template('login.html')


# Основни защитени маршрути
@app.route('/home')
@login_required
def home():
  return render_template('home.html', username=current_user.username)


@app.route('/specialnosti')
@login_required
def specialnosti():
  return render_template('specialnosti.html', username=current_user.username)


@app.route('/naukavane')
@login_required
def naukavane():
  return render_template('naukavane.html', username=current_user.username)


@app.route('/klasove')
@login_required
def klasove():
  return render_template('klasove.html', username=current_user.username)


@app.route('/rukovodstvo')
@login_required
def rukovodstvo():
  return render_template('rukovodstvo.html', username=current_user.username)


@app.route('/prepodavateli')
@login_required
def prepodavateli():
  return render_template('prepodavateli.html', username=current_user.username)


@app.route('/talantite')
@login_required
def talantite():
  return render_template('talantite.html', username=current_user.username)


@app.route('/logout')
@login_required
def logout():
  logout_user()
  return redirect(url_for('login'))


if __name__ == '__main__':
  app.run(debug=True)
