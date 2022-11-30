from flask import Flask, render_template, request, abort, redirect, send_file
from flask_wtf import FlaskForm
from wtforms import StringField, validators, SelectField, IntegerField, PasswordField, EmailField
import bleach
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
import os
import datetime
import io
import glob
from werkzeug import security
from flask_login import LoginManager, login_user, login_required, login_manager, UserMixin, current_user, logout_user

app = Flask(__name__)


SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///items.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = "/login"  # type: ignore
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):  # type: ignore
    id = db.Column(db.Integer, primary_key=True)
    login = password = db.Column(db.String(20), unique=False, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(20), unique=False, nullable=False)
    admin = db.Column(db.Integer(), unique=False, nullable=False)


class Category(db.Model):  # type: ignore
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    user_id = db.Column(db.Integer(), unique=False, nullable=False)


class Item(db.Model):  # type: ignore
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    amount = db.Column(db.String(20), unique=False, nullable=False)
    category_id = db.Column(db.Integer(), unique=False, nullable=False)


class Log(db.Model):  # type: ignore
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Integer(), unique=False, nullable=False)
    result = db.Column(db.Integer(), unique=False, nullable=False)
    action = db.Column(db.String(20), unique=False, nullable=False)
    date = db.Column(db.DateTime, unique=False, nullable=False)
    user_id = db.Column(db.Integer(), unique=False, nullable=False)
    category_id = db.Column(db.Integer(), unique=False, nullable=False)
    item_id = db.Column(db.Integer(), unique=False, nullable=False)


# with app.app_context():
#     db.create_all()


@app.route('/')
def main():
    if current_user.is_authenticated:  # type: ignore
        return redirect('/list')
    else:
        return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    class MyForm(FlaskForm):
        email = EmailField('email', validators=[
            validators.DataRequired()])
        password = PasswordField('password', validators=[
            validators.DataRequired()])
    form = MyForm()

    if form.validate_on_submit():
        try:
            email = bleach.clean(request.form['email'])
            password = request.form['password']

            user = User.query.filter_by(email=email).first()

            if security.check_password_hash(user.password, password):

                login_user(user, remember=True)
                return redirect('/list')
            else:
                raise Exception('Incorrect Username or Password')

        except Exception as e:

            form.password.errors.append(  # type: ignore
                f'{e}')

            return render_template('login.html', form=form)

    return render_template('login.html', form=form)


@app.route('/guest')
def guest_login():
    try:
        user = User.query.filter_by(email='guest@guest.com').first()
        login_user(user)
        return redirect('/list')
    except Exception:
        db.session.add(User(login='Guest', email='guest@guest.com',
                       password='Aa@12345678', admin=1))  # type: ignore
        db.session.commit()
        return redirect('/guest')


@app.route('/register', methods=['GET', 'POST'])
def register():
    class MyForm(FlaskForm):
        login = StringField('login', validators=[
            validators.DataRequired(), validators.length(min=3, max=20)])
        email = EmailField('email', validators=[
            validators.DataRequired(), validators.email(), validators.length(min=3, max=100)])
        password = PasswordField('password', validators=[
            validators.DataRequired(), validators.EqualTo('repeat_password', message='Passwords must be equal.')])
        repeat_password = PasswordField('repeat_password', validators=[
            validators.DataRequired()])

    form = MyForm()

    if form.validate_on_submit():
        print('Form Validated')
        try:
            login = bleach.clean(request.form['login'])
            email = bleach.clean(request.form['email'])
            password = security.generate_password_hash(
                request.form['password'], method='pbkdf2:sha256', salt_length=10)

            db.session.add(
                User(login=login, email=email, password=password, admin=1))  # type: ignore
            db.session.commit()
            return redirect('/login')
        except IntegrityError as e:
            form.email.errors.append(  # type: ignore
                f'This E-mail has already been registered')
            db.session.rollback()
            print(e)
            return render_template('register.html', form=form)
        except Exception as e:
            print(e)
            abort(404)

    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')


def update_list():
    categories = Category.query.filter_by(
        user_id=current_user.id)  # type: ignore
    data = [(i, Item.query.filter_by(category_id=i.id))for i in categories]
    return data


@app.route('/list')
@login_required
def list():
    return render_template('list.html', data=update_list())


@app.route('/edit', methods=["GET", "POST"])
@login_required
def edit():

    data = update_list()

    class MyForm(FlaskForm):
        name = StringField('name', validators=[
            validators.DataRequired(), validators.length(min=3, max=25)])
        amount = IntegerField('amount', validators=[
            validators.DataRequired()])
        category = SelectField('category', validators=[
                               validators.DataRequired()], choices=[(i.id, i.name) for i in Category.query.filter_by(user_id=current_user.id)])  # type: ignore

    form = MyForm()

    if form.validate_on_submit():
        print('Form Validated')
        try:
            name = bleach.clean(request.form['name'])
            amount = bleach.clean(request.form['amount'])
            category_raw = bleach.clean(request.form['category'])
            category = Category.query.filter_by(id=category_raw).first()

            db.session.add(
                Item(name=name, amount=amount, category_id=category.id))
            db.session.commit()
            data = update_list()
        except IntegrityError:
            db.session.rollback()
            form.name.errors.append(  # type: ignore
                f'This Item has already been registered')
            return render_template('edit.html', form=form, data=data)
        except Exception as e:
            print(e)
            abort(404)
        return render_template('edit.html', form=form, data=data)

    return render_template('edit.html', form=form, data=data)


@app.route('/category', methods=["GET", "POST"])
@login_required
def category():

    data = update_list()

    class MyForm(FlaskForm):
        name = StringField('name', validators=[
            validators.DataRequired(), validators.length(min=4, max=25)])

    form = MyForm()

    if form.validate_on_submit():

        try:
            name = bleach.clean(request.form['name'])
            db.session.add(
                Category(name=name, user_id=current_user.id))  # type: ignore
            db.session.commit()
            data = update_list()
            return render_template('category.html', form=form, data=data)
        except IntegrityError:
            form.name.errors.append(  # type: ignore
                f'This Category has already been registered')

            db.session.rollback()
            return render_template('category.html', form=form, data=data, error='This category already exists')
        except Exception as E:
            print(E)
            abort(404)

    return render_template('category.html', form=form, data=data)


@app.route('/logs')
@login_required
def logs():
    data = Log.query.filter_by(user_id=current_user.id).order_by(Log.date.desc()).limit(  # type: ignore
        100)

    data = [[i.date.strftime('%x - %X'),
             User.query.filter_by(id=i.user_id).first().login,
             Category.query.filter_by(id=i.category_id).first().name,
             Item.query.filter_by(id=i.item_id).first().name,
             i.action,
             i.amount,
             i.result
             ]for i in data]

    return render_template(
        'logs.html', data=data)  # type: ignore


@app.route("/delete/<page>", methods=["POST"])
@login_required
def delete(page):

    page = bleach.clean(page)
    id = request.form.get("id")
    if page == 'edit':

        item = Item.query.filter_by(id=id).first()
        db.session.delete(item)

    elif page == 'category':

        items = Item.query.filter_by(category_id=id)
        items.delete()
        category = Category.query.filter_by(id=id).first()
        db.session.delete(category)

    else:
        abort(404)
    db.session.commit()
    return redirect(f'/{page}')


@app.route('/update/<int:id>', methods=["POST", "GET"])
@login_required
def update(id):
    if request.method == 'POST':
        print(id, type(id))
        item = Item.query.get(id)
        amount = int(request.form['amount'])
        if amount < 1:
            return redirect('/')
        if Item is None:
            abort(404)
        total = int(item.amount)

        if request.form['bttn'] == '+':
            action = "Added"
            item.amount = total + amount
        elif request.form['bttn'] == '-':
            action = "Subtracted"
            item.amount = total - amount
        else:
            abort(404)
        result = int(item.amount)
        db.session.add(Log(result=result, amount=amount, action=action, date=datetime.datetime.now(), user_id=current_user.id,  # type: ignore
                       category_id=item.category_id, item_id=item.id))  # type: ignore
        db.session.commit()

    return redirect('/')


@app.route('/download', methods=['GET'])
@login_required
def download():

    if request.method == 'GET':

        files = glob.glob('exports/*')
        for f in files:
            os.remove(f)

        today = datetime.date.today().strftime('%d_%m_%y')
        print(today)

        with app.app_context():
            data = update_list()
        rows = ['ID,  Name ,  Amount , Category']
        for i in data:
            category = i[0].name
            for k in i[1]:
                rows.append(f'{k.id},{k.name},{k.amount},{category},')

        r = bytes('\n'.join(rows), 'utf-8')

        r = send_file(io.BytesIO(r), download_name=f'{today}.csv')

        return r
    else:
        return redirect('/edit')


if __name__ == '__main__':
    app.run()
