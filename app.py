from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from database3 import get_db_connection, create_tables, close_db_connection
import uuid
import os
from datetime import datetime, timedelta
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import random
import string
from PIL import Image, ImageDraw, ImageFont
import joblib
app = Flask(__name__)
app.secret_key = os.urandom(24)
import nltk
from nltk.corpus import stopwords
def send_verification_email(to_email, subject, content):
    api_key='api_key'
    sg=SendGridAPIClient(api_key)
    message = Mail(
        from_email='sendermail.com',  # Replace with verified email
        to_emails=to_email,
        subject=subject,
        html_content=content
    )
    try:
        sg.send(message)
    except Exception as e:
        print(f"Error sending email: {e}")
        flash('Could not send verification email. Please try again.')

# Ensure static folders exist
if not os.path.exists('static/uploads'):
    os.makedirs('static/uploads')
if not os.path.exists('static/captcha'):
    os.makedirs('static/captcha')

# Load models and vectorizers
svm_model = joblib.load('models/best_svm_text_model.pkl')
tfidf_vectorizer = joblib.load('models/tfidf_vectorizer.pkl')

# Download stopwords
nltk.download('stopwords')
stop_words = stopwords.words('english')

# Text cleaning function
def clean_text(text):
    text = re.sub(r'\W', ' ', str(text))
    text = re.sub(r'\d', ' ', text)
    text = text.lower()
    text = re.sub(r'\s+', ' ', text)
    return text

# Function to extract article text from a URL
def extract_text_from_url(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        paragraphs = soup.find_all('p')
        article_text = ' '.join([p.get_text() for p in paragraphs])
        return clean_text(article_text)
    except Exception as e:
        print(f"Error extracting text from URL: {e}")
        return None

# Function to predict news
def predict_news(input_text):
    if re.match(r'^https?:\/\/', input_text):
        article_text = extract_text_from_url(input_text)
        if not article_text:
            return "Error extracting text from the URL."
    else:
        article_text = input_text

    cleaned_text = clean_text(article_text)
    tfidf_input = tfidf_vectorizer.transform([cleaned_text])

    prediction = svm_model.predict(tfidf_input)[0]
    return "Fake" if prediction == 1 else "Genuine"


# Generate captcha image
def generate_captcha():
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    captcha_img_path = os.path.join('static/captcha', f"{captcha_text}.png")

    # Create image
    img = Image.new('RGB', (200, 80), color=(255, 255, 255))
    d = ImageDraw.Draw(img)
    font = ImageFont.load_default()

    d.text((20, 30), captcha_text, font=font, fill=(0, 0, 0))
    img.save(captcha_img_path)
    
    return captcha_text, captcha_img_path

# Home route
@app.route('/')
def home():
    return render_template('home.html')

# About route
@app.route('/about')
def about():
    return render_template('about.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash("Passwords do not match!")
            return redirect(url_for('register'))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Email is already registered. Please login.')
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(password)
        verification_code = str(uuid.uuid4())[:6]  # Generate 6-digit OTP
        valid_until = datetime.now() + timedelta(minutes=5)

        cursor.execute('INSERT INTO users (first_name, last_name, email, password, verification_code, valid_until) VALUES (?, ?, ?, ?, ?, ?)',
                       (first_name, last_name, email, hashed_password, verification_code, valid_until))
        conn.commit()

        # Send OTP for verification
        send_verification_email(email, 'Verify Your Account', f'Your OTP is: {verification_code}')

        flash('Registration successful! Please check your email to verify your account.')
        return redirect(url_for('verify_otp1', email=email))

    return render_template('register.html')

# OTP Verification route
@app.route('/verify_otp1', methods=['GET', 'POST'])
def verify_otp1():
    email = request.args.get('email')
    if request.method == 'POST':
        entered_otp = request.form['otp']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if user:
            if user['verification_code'] == entered_otp and datetime.now() <= datetime.fromisoformat(user['valid_until']):
                cursor.execute('UPDATE users SET verification_code = NULL, valid_until = NULL WHERE email = ?', (email,))
                conn.commit()
                flash('Registered successfully! You can now log in.')
                return redirect(url_for('login'))
            else:
                flash('Invalid or expired OTP. Please try again.')

    return render_template('verify_otp1.html', email=email)

# Login route with captcha
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        entered_captcha = request.form['captcha'].strip()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if 'captcha_text' in session and entered_captcha != session['captcha_text']:
            flash('Invalid captcha. Please try again.')
            return redirect(url_for('login'))

        if user and check_password_hash(user['password'], password) and user['verification_code'] is None:
            session['user_id'] = user['id']
            session['user_name'] = user['first_name']
            flash('Login successful!')
            return redirect(url_for('home'))
        else:
            flash('Login failed. Check your email and password or verify your email.')
            return redirect(url_for('login'))

    # Generate captcha
    captcha_text, captcha_img_path = generate_captcha()
    session['captcha_text'] = captcha_text

    return render_template('login.html', captcha_img=captcha_img_path)

# Forgot password route
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if user:
            otp = str(uuid.uuid4())[:6]  # Generate a 6-digit OTP
            cursor.execute('UPDATE users SET verification_code = ?, valid_until = ? WHERE email = ?', (otp, datetime.now() + timedelta(minutes=5), email))
            conn.commit()

            send_verification_email(email, 'Reset Your Password', f'Your OTP is: {otp}. Please verify it.')
            flash('OTP sent to your email.')
            return redirect(url_for('verify_otp2', email=email))
        else:
            flash('Email not found.')

        return redirect(url_for('forgot'))

    return render_template('forgot.html')

# OTP Verification for password reset route
@app.route('/verify_otp2', methods=['GET', 'POST'])
def verify_otp2():
    email = request.args.get('email')
    if request.method == 'POST':
        entered_otp = request.form['otp']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ? AND verification_code = ?', (email, entered_otp))
        user = cursor.fetchone()

        if user and datetime.now() <= datetime.fromisoformat(user['valid_until']):
            cursor.execute('UPDATE users SET verification_code = NULL, valid_until = NULL WHERE email = ?', (email,))
            conn.commit()
            flash('OTP verified! You can now reset your password.')
            return redirect(url_for('reset_password', email=email))
        else:
            flash('Invalid or expired OTP.')

    return render_template('verify_otp2.html', email=email)

# Reset password route
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    email = request.args.get('email')
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('reset_password', email=email))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password = ? WHERE email = ?', (generate_password_hash(password), email))
        conn.commit()

        flash('Password reset successfully! You can now log in.')
        return redirect(url_for('login'))

    return render_template('reset_password.html', email=email)
# Profile route
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('Please log in to view your profile.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        profile_image = request.files['profile_image']
        if profile_image:
            image_path = os.path.join('static/uploads', profile_image.filename)
            profile_image.save(image_path)

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET profile_image = ? WHERE id = ?', (image_path, session['user_id']))
            conn.commit()

            session['profile_image'] = image_path
            flash('Profile image updated successfully!')
            return redirect(url_for('profile'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    close_db_connection(conn)

    return render_template('profile.html', user=user)

# Prediction route
@app.route('/prediction', methods=['GET', 'POST'])
def prediction():
    prediction = None
    if request.method == 'POST':
        input_text = request.form['input_text']

        # Use the predict_news function for prediction
        prediction = predict_news(input_text)

        if 'user_id' in session:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO predictions (user_id, news, value) VALUES (?, ?, ?)',
                           (session['user_id'], input_text, prediction))
            conn.commit()

        flash(f'Prediction Result: {prediction}')
        return render_template('prediction.html', prediction=prediction)

    return render_template('prediction.html')

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)
