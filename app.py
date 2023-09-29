from flask import Flask, render_template, request, session, redirect,  url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt


import requests
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'B80385F6-2357-4488-8261-442E68006A0B'  # Güvenlik için rastgele bir anahtar seçin
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # SQLite veritabanı kullanıyoruz

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
questions = []

QUESTION_API_URL = 'https://opentdb.com/api.php'
WEATHER_API_URL = 'https://api.collectapi.com/weather/getWeather'
WEATHER_API_KEY = '1sU6vlo5omT8XiylGj1gao:2puqCfX7PCdDEwYNVGaaSD'


# Kullanıcı modeli
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


class UserScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)

    # UserScore sınıfına ait bir ilişkili kullanıcı ekleme
    user = db.relationship('User', foreign_keys=user_id)

    def __init__(self, user_id, score):
        self.user_id = user_id
        self.score = score


# -------------------- PRIVATE METHODS START -------------------- #

def get_weather_data(city):
    headers = {
        'authorization': 'apikey ' + WEATHER_API_KEY,
        'content-type': 'application/json'
    }
    params = {
        'data.lang': 'tr',
        'data.city': city
    }

    response = requests.get(WEATHER_API_URL, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        result = data.get('result', [])
        # İlk 3 günü al
        three_day_forecast = result[:3]
        return three_day_forecast
    else:
        return None
    

# WTForms ile kayıt formu oluşturma
class RegistrationForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Şifre', validators=[DataRequired(), Length(min=6, max=120)])
    confirm_password = PasswordField('Şifreyi Onayla', validators=[DataRequired(), EqualTo('password')])

    submit = SubmitField('Kayıt Ol')

    # Kullanıcı adının benzersiz olup olmadığını kontrol etme
    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError('Bu kullanıcı adı zaten kullanılıyor, lütfen farklı bir kullanıcı adı seçin.')

class LoginForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[DataRequired()])
    password = PasswordField('Şifre', validators=[DataRequired()])
    submit = SubmitField('Giriş Yap')        


def get_random_question():
    params = {
        "amount": 1,
        "type": "multiple"
    }
    response = requests.get(QUESTION_API_URL, params=params)
    data = response.json()
    if data["results"]:
        question_data = data["results"][0]
        question = question_data["question"]
        correct_answer = question_data["correct_answer"]
        incorrect_answers = question_data["incorrect_answers"]
        options = [correct_answer] + incorrect_answers
        random.shuffle(options)
        return {
            "question": question,
            "options": options,
            "correct_answer": correct_answer
        }
    return None

# -------------------- PRIVATE METHODS END -------------------- #


# Ana Sayfa
@app.route('/', methods=['GET', 'POST'])
def index():
    if session and session.get('username'):
        isLogin = True
    else:
        isLogin = False
    if request.method == 'POST':
        city = request.form['city']
        weather_data = get_weather_data(city)
        return render_template('index.html', weather_data=weather_data, isLogin=isLogin)
    return render_template('index.html', isLogin=isLogin)

# Kayıt sayfası
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Form verilerini veritabanına kaydet
        new_user = User(username=form.username.data, password=form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Başarıyla kayıt oldunuz. Şimdi giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Giriş sayfası
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username,password=password).first()
        if user:
            flash('Başarıyla giriş yaptınız!', 'success')
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Geçersiz kullanıcı adı veya şifre. Lütfen tekrar deneyin.', 'danger')
    return render_template('login.html', form=form)

# Çıkış sayfası
@app.route('/logout')
def logout():
    # Kullanıcının oturumunu sonlandır
    session.clear()
    flash('Başarıyla çıkış yaptınız!', 'success')
    return redirect(url_for('index'))

# Soru sayfası
@app.route('/question', methods=['GET', 'POST'])
def question():
    if session and session.get('username'):
        isLogin = True
    else:
        isLogin = False

    if not session.get('total_score'):
        session['total_score'] = 0

    if request.method == 'GET':
        question_data = get_random_question()
        if question_data:
            questions.append(question_data)
            return render_template('question.html', question=question_data , isLogin=isLogin)
        else:
            flash('Sorular çekilemedi.', 'danger')
            return redirect(url_for('question'))

    if request.method == 'POST':
        user_answer = request.form.get('answer')
        correct_answer = request.form.get('correct_answer')

        if user_answer == correct_answer:
            flash('Doğru cevap!', 'success')
            session['total_score'] += 1
        else:
            flash('Yanlış cevap. Doğru cevap: ' + correct_answer, 'danger')

       
        if session.get('username'):
            username = session['username']
            user = User.query.filter_by(username=username).first()
            
            if user:
                user_score = UserScore.query.filter_by(user_id=user.id).first()
                if user_score:
                    user_score.score = session['total_score']
                else:
                    new_user_score = UserScore(user_id=user.id, score=session['total_score'])
                    db.session.add(new_user_score)
                db.session.commit()

        question_data = get_random_question()
        if question_data:
            questions.append(question_data)
            return render_template('question.html', question=question_data, isLogin=isLogin)
        else:
            flash('Sorular çekilemedi.', 'danger')
            return redirect(url_for('question'))

@app.route('/leaderboard')
def leaderboard():
    if session and session.get('username'):
        isLogin = True
    else:
        isLogin = False
    leaderboard_data = UserScore.query.order_by(UserScore.score.desc()).all()
    return render_template('leaderboard.html', leaderboard_data=leaderboard_data, isLogin=isLogin)
        

if __name__ == '__main__':
   
    with app.app_context():
        db.create_all()
    app.run(debug=True)
