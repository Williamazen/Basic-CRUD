from flask import Flask, render_template, request, abort, redirect
from flask_wtf import FlaskForm
from wtforms import StringField, validators, SelectField, IntegerField
import bleach
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///items.db'
db = SQLAlchemy(app)

# Setting up the secret key for flaskWTF
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY


class Category(db.Model):  # type: ignore
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)


class Item(db.Model):  # type: ignore
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    amount = db.Column(db.String(20), unique=False, nullable=False)
    category = db.Column(db.String(20), unique=False, nullable=False)


def update_categories():
    # I use this to define the categories for the dropdown and for the divider on main()
    # It used to be just a variable but i made it into a function so it updates before being used
    with app.app_context():
        return [(i.name, i.name) for i in db.session.query(Category).all()]


@app.route('/')
def main():
    data = []
    for i in update_categories():
        category = i[0]
        items = [r for r in db.session.query(Item).filter_by(
            category=category).distinct()]
        data.append([(category, items)])

    return render_template('index.html', data=data)


@app.route('/edit', methods=["GET", "POST"])
def edit():

    data = Item.query.all()

    class MyForm(FlaskForm):
        name = StringField('name', validators=[
            validators.DataRequired(), validators.length(min=4, max=25)])
        amount = IntegerField('amount', validators=[
            validators.DataRequired()])
        category = SelectField('category', validators=[
                               validators.DataRequired()], choices=update_categories())

    form = MyForm()

    if form.validate_on_submit():
        print('Form Validated')
        try:
            name = bleach.clean(request.form['name'])
            amount = bleach.clean(request.form['amount'])
            category = bleach.clean(request.form['category'])

            db.session.add(Item(name=name, amount=amount, category=category))
            db.session.commit()
            data = Item.query.all()
        except IntegrityError:
            db.session.rollback()
            return render_template('edit.html', form=form, data=data, error='This item already exists.')
        except Exception:
            abort(404)
        return render_template('edit.html', form=form, data=data)

    return render_template('edit.html', form=form, data=data)


@app.route('/category', methods=["GET", "POST"])
def category():

    data = Category.query.all()

    class MyForm(FlaskForm):
        name = StringField('name', validators=[
            validators.DataRequired(), validators.length(min=4, max=25)])

    form = MyForm()

    if form.validate_on_submit():
        print('Form Validated')
        try:
            name = bleach.clean(request.form['name'])

            db.session.add(Category(name=name))
            db.session.commit()
            data = Category.query.all()
            return render_template('category.html', form=form, data=data)
        except IntegrityError:
            db.session.rollback()
            return render_template('category.html', form=form, data=data, error='This category already exists')
        except Exception:
            abort(404)

    return render_template('category.html', form=form, data=data)


@app.route("/delete/<obj>", methods=["POST"])
def delete(obj):
    # So, i originally made this to delete items from /edit but adapted it to delete from /category too.
    # There probably is a more elegant way to switch between the two pages but the if statements did the trick.
    # My main objective was to detect what it wants do delete and adjust according to it

    bleach.clean(obj)
    if obj == 'item':
        obj = Item
        r = '/edit'

    elif obj == 'category':
        obj = Category
        r = '/category'
    else:
        abort(404)
    name = request.form.get("name")
    item = obj.query.filter_by(name=name).first()

    db.session.delete(item)
    db.session.commit()
    return redirect(r)


@app.route('/update/<int:id>', methods=["POST", "GET"])
def update(id):
    if request.method == 'POST':
        print(id, type(id))
        item = Item.query.get(id)
        if Item is None:
            abort(404)

        print(request.form['bttn'])
        if request.form['bttn'] == '+':
            item.amount = int(item.amount) + 1
        if request.form['bttn'] == '-':
            item.amount = int(item.amount) - 1
        db.session.commit()

    return redirect('/')


if __name__ == '__main__':
    app.run()
