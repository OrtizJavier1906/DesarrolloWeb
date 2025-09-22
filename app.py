# 1. Se importan las librerías necesarias
import os
import re
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# 2. Inicialización y configuración de Flask
app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'BD.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'f9bf78b9a18ce6d46a0cd2a0b86df9da'

# 3. Inicialización de la base de datos
db = SQLAlchemy(app)

# 4. Modelos de la Base de Datos
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombres = db.Column(db.String(80), nullable=False)
    apellidos = db.Column(db.String(80), nullable=False)
    telefono = db.Column(db.String(20), nullable=False)
    edad = db.Column(db.Integer, nullable=False)
    correo = db.Column(db.String(120), unique=True, nullable=False)
    contrasena = db.Column(db.String(128), nullable=False)
    esVendedor = db.Column(db.Boolean, default=False, nullable=False)
    productos = db.relationship('Producto', backref='vendedor', lazy=True)

    def __repr__(self):
        return f'<Usuario {self.correo}>'

class Producto(db.Model):
    idProducto = db.Column(db.Integer, primary_key=True)
    NombreAlbum = db.Column(db.String(100), nullable=False)
    Artista = db.Column(db.String(100), nullable=False)
    Genero = db.Column(db.String(50), nullable=False)
    Precio = db.Column(db.Float, nullable=False)
    Cantidad = db.Column(db.Integer, nullable=False)
    idUsuario = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)

    def __repr__(self):
        return f'<Producto {self.NombreAlbum}>'


# 5. Rutas de la Aplicación
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        correo = request.form['correo']
        contrasena = request.form['contrasena']
        user = Usuario.query.filter_by(correo=correo).first()

        if user:
            if check_password_hash(user.contrasena, contrasena):
                session['user_id'] = user.id
                session['user_name'] = user.nombres
                flash('¡Inicio de sesión exitoso!', 'success')
                return redirect(url_for('exitoso'))
            else:
                flash('Contraseña incorrecta. Por favor, inténtalo de nuevo.', 'danger')
                return redirect(url_for('login'))
        else:
            flash('El correo ingresado no existe. Si no tienes una cuenta puedes crear una nueva', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/exitoso')
def exitoso():
    # Se verifica si el usuario ha iniciado sesión
    if 'user_id' not in session:
        flash('Por favor, inicia sesión para acceder a esta página.', 'warning')
        return redirect(url_for('login'))
    return render_template('inicioexitoso.html')

def es_contrasena_segura(contrasena):
    if len(contrasena) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."
    if not re.search(r'[A-Z]', contrasena):
        return False, "La contraseña debe contener al menos una letra mayúscula."
    if not re.search(r'[a-z]', contrasena):
        return False, "La contraseña debe contener al menos una letra minúscula."
    if not re.search(r'[0-9]', contrasena):
        return False, "La contraseña debe contener al menos un número."
    return True, ""

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        correo_existente = Usuario.query.filter_by(correo=request.form['correo']).first()
        if correo_existente:
            flash('El correo electrónico ya está registrado. Por favor, utiliza otro.', 'danger')
            return redirect(url_for('registro'))

        contrasena = request.form['contrasena']
        es_segura, mensaje_error = es_contrasena_segura(contrasena)
        if not es_segura:
            flash(mensaje_error, 'danger')
            return redirect(url_for('registro'))

        hashed_contrasena = generate_password_hash(contrasena, method='pbkdf2:sha256')
        nuevo_usuario = Usuario(
            nombres=request.form['nombres'],
            apellidos=request.form['apellidos'],
            telefono=request.form['telefono'],
            edad=request.form['edad'],
            correo=request.form['correo'],
            contrasena=hashed_contrasena,
            esVendedor=False
        )
        db.session.add(nuevo_usuario)
        db.session.commit()
        flash('¡Registro exitoso! Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))

    return render_template('registro.html')

@app.route('/servendedor', methods=['GET', 'POST'])
def servendedor():
    # Se asegura que el usuario haya iniciado sesión
    if 'user_id' not in session:
        flash('Debes iniciar sesión para poder vender productos.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        nombre_album = request.form['nombre_album']
        artista = request.form['artista']
        genero = request.form['genero']
        precio = request.form['precio']
        cantidad = request.form['cantidad']
        
        user_id = session['user_id']

        nuevo_producto = Producto(
            NombreAlbum=nombre_album,
            Artista=artista,
            Genero=genero,
            Precio=float(precio),
            Cantidad=int(cantidad),
            idUsuario=user_id
        )
        db.session.add(nuevo_producto)

        # Se actualiza el estado del usuario a vendedor
        usuario_actual = Usuario.query.get(user_id)
        if not usuario_actual.esVendedor:
            usuario_actual.esVendedor = True
        
        db.session.commit()

        flash('¡Felicidades! Has registrado tu primer vinilo y ahora eres vendedor.', 'success')
        return redirect(url_for('exitoso'))

    return render_template('servendedor.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado la sesión.', 'info')
    return redirect(url_for('login'))


# 6. Iniciar la Aplicación
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
