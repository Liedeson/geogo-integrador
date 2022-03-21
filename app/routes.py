from flask import flash, redirect, render_template, url_for
from flask_login import login_user, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from app.forms import RegisterUser, LoginUser, RegisterDesafio

from app import db
from app.models import User
from app.models import Desafio


def init_app(app):

    # inicio

    @app.route('/')
    def index():
        if current_user.is_active:
            desafios = Desafio.query.all()
            return render_template('home.html', desafios=desafios)
        return render_template('index.html')

    # sobre

    @app.route('/sobre')
    def sobre():
        return render_template('sobre.html')

    # autenticação 

    @app.route('/register/', methods=('GET', 'POST'))
    def register():
        form = RegisterUser()

        if form.validate_on_submit():

            if User.query.filter_by(email=form.email.data).first():
                flash("O email já está registrado", category="danger")
                return redirect(url_for('register'))

            user = User()

            user.name = form.name.data
            user.email = form.email.data
            user.password = generate_password_hash(form.password.data)

            db.session.add(user)
            db.session.commit()

            login_user(user)

            return redirect(url_for('index'))

        return render_template('register.html', form=form)

    @app.route('/login/', methods=('GET', 'POST'))
    def login():
        form = LoginUser()

        if form.validate_on_submit():

            user = User.query.filter_by(email=form.email.data).first()

            if not user:
                flash("Email incorreto", category="danger")
                return redirect(url_for('login'))

            if not check_password_hash(user.password, form.password.data):
                flash("Email correto", category='success')
                flash("Senha incorreta", category='danger')
                return redirect(url_for('login'))

            login_user(user)
            return redirect(url_for('index'))

        return render_template('login.html', form=form)

    @app.route('/logout')
    def logout():
        logout_user()
        return redirect(url_for('index'))

    # Perfil

    @app.route('/perfil/')
    def profile():
        user = User.query.filter_by(id=current_user.id).first()
        form = RegisterUser()
        return render_template('profile.html', user=user, form=form)

    @app.route('/perfil/edit', methods=('GET', 'POST'))
    def editar_perfil():
        user = User.query.filter_by(id=current_user.id).first()
        form = RegisterUser()

        form.name.data = user.name
        form.email.data = user.email

        return render_template('editar_perfil.html', form=form, user=user)

    @app.route('/perfil/edit/submit', methods=('GET', 'POST'))
    def submit_profile_edit():
        form = RegisterUser()

        user = User.query.filter_by(id=current_user.id).first()

        if form.validate_on_submit():

            if User.query.filter_by(email=form.email.data).first():
                if form.email.data != user.email:
                    flash("O email já está registrado", category="danger")
                    return redirect(url_for("editar_perfil"))

            user.name = form.name.data
            user.email = form.email.data

            db.session.commit()

            return redirect(url_for('profile'))

    @app.route('/perfil/excluir')
    def delete_profile():
        user = User.query.filter_by(id=current_user.id).first()

        db.session.delete(user)
        db.session.commit()

        return redirect(url_for('index'))

    # Desafios
    
    @app.route('/desafio/<id>')
    def desafio(id):
        desafio = Desafio.query.filter_by(id=id).first()
        return render_template('desafio.html', desafio=desafio)

    @app.route('/criar/desafio', methods=('GET', 'POST'))
    def novo_desafio():
        form = RegisterDesafio()

        if form.validate_on_submit():

            desafio = Desafio()

            desafio.title = form.title.data
            desafio.description = form.description.data

            db.session.add(desafio)
            db.session.commit()

            flash('Desafio criado com sucesso', category='success')

        form.title.data = ''
        form.description.data = ''

        return render_template('novo_desafio.html', form=form)

    @app.route('/desafio/concluida/<id>')
    def desafio_completo(id):
        desafio = Desafio.query.filter_by(id=id).first()

        db.session.delete(desafio)
        db.session.commit()

        return redirect(url_for('index'))

    @app.route('/desafio/editar/<id>', methods=('GET', 'POST'))
    def editar_desafio(id):
        form = RegisterDesafio()
        desafio = Desafio.query.filter_by(id=id).first()

        form.title.data = desafio.title
        form.description.data = desafio.description

        return render_template('editar_desafio.html', desafio=desafio, form=form)

    @app.route('/desafio/editar/submit/<id>', methods=('GET', 'POST'))
    def submit_desafio_edit(id):
        form = RegisterDesafio()
        desafio = Desafio.query.filter_by(id=id).first()

        if form.validate_on_submit():

            desafio.title = form.title.data
            desafio.description = form.description.data

            db.session.commit()

            return redirect(url_for('desafio', id=id))

    @app.route('/desafio/excluir/<id>')
    def excluir_desafio(id):
        task = Desafio.query.filter_by(id=id).first()

        db.session.delete(task)
        db.session.commit()

        return redirect(url_for('index'))
