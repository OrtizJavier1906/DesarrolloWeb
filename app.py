# 1. Se importan las librerías necesarias
import os # Importado para manejar rutas de archivos
import re # Importado para validación de contraseña con expresiones regulares
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# 2. Inicialización y configuración de Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_llave_secreta_aqui'

# --- CORRECCIÓN DE RUTA DE LA BASE DE DATOS ---
# Se establece una ruta absoluta para asegurar que el archivo BD.db se cree siempre en la carpeta del proyecto.
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'BD.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 3. Inicialización de la base de datos
db = SQLAlchemy(app)

# 4. Modelos de la Base de Datos (Sin cambios)
class UsuarioComprador(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombres = db.Column(db.String(80), nullable=False)
    apellidos = db.Column(db.String(80), nullable=False)
    telefono = db.Column(db.String(20), nullable=False)
    edad = db.Column(db.Integer, nullable=False)
    correo = db.Column(db.String(120), unique=True, nullable=False)
    contrasena = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f'<UsuarioComprador {self.correo}>'

class UsuarioVendedor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombres = db.Column(db.String(80), nullable=False)
    apellidos = db.Column(db.String(80), nullable=False)
    telefono = db.Column(db.String(20), nullable=False)
    edad = db.Column(db.Integer, nullable=False)
    correo = db.Column(db.String(120), unique=True, nullable=False)
    contrasena = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f'<UsuarioVendedor {self.correo}>'

# 5. Rutas de la Aplicación
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login/<user_type>', methods=['GET', 'POST'])
def login(user_type):
    if request.method == 'POST':
        correo = request.form['correo']
        contrasena = request.form['contrasena']
        
        user = None
        if user_type == 'comprador':
            user = UsuarioComprador.query.filter_by(correo=correo).first()
        elif user_type == 'vendedor':
            user = UsuarioVendedor.query.filter_by(correo=correo).first()

        if user and check_password_hash(user.contrasena, contrasena):
            flash('¡Inicio de sesión exitoso!', 'success')
            return redirect(url_for('exitoso'))
        else:
            flash('Correo o contraseña incorrectos. Por favor, inténtalo de nuevo.', 'danger')
            return redirect(url_for('login', user_type=user_type))

    return render_template('login.html', user_type=user_type)

@app.route('/exitoso')
def exitoso():
    return render_template('inicioExitoso.html')

def es_contrasena_segura(contrasena):
    """Verifica que la contraseña cumpla con los requisitos de seguridad."""
    if len(contrasena) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."
    if not re.search(r'[A-Z]', contrasena):
        return False, "La contraseña debe contener al menos una letra mayúscula."
    if not re.search(r'[a-z]', contrasena):
        return False, "La contraseña debe contener al menos una letra minúscula."
    if not re.search(r'[0-9]', contrasena):
        return False, "La contraseña debe contener al menos un número."
    return True, ""

@app.route('/registro-comprador', methods=['GET', 'POST'])
def registroC():
    if request.method == 'POST':
        contrasena = request.form['contrasena']
        
        # --- LÓGICA DE CONTRASEÑA SEGURA ---
        es_segura, mensaje_error = es_contrasena_segura(contrasena)
        if not es_segura:
            flash(mensaje_error, 'danger')
            return redirect(url_for('registroC'))

        # Si la contraseña es segura, procede con el registro
        hashed_contrasena = generate_password_hash(contrasena, method='pbkdf2:sha256')
        nuevo_usuario = UsuarioComprador(
            nombres=request.form['nombres'],
            apellidos=request.form['apellidos'],
            telefono=request.form['telefono'],
            edad=request.form['edad'],
            correo=request.form['correo'],
            contrasena=hashed_contrasena
        )
        db.session.add(nuevo_usuario)
        db.session.commit()

        # --- REDIRECCIÓN CORREGIDA ---
        flash('¡Registro de comprador exitoso! Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login', user_type='comprador'))

    return render_template('registroC.html')

@app.route('/registro-vendedor', methods=['GET', 'POST'])
def registroV():
    if request.method == 'POST':
        contrasena = request.form['contrasena']
        
        # --- LÓGICA DE CONTRASEÑA SEGURA ---
        es_segura, mensaje_error = es_contrasena_segura(contrasena)
        if not es_segura:
            flash(mensaje_error, 'danger')
            return redirect(url_for('registroV'))
            
        hashed_contrasena = generate_password_hash(contrasena, method='pbkdf2:sha256')
        nuevo_usuario = UsuarioVendedor(
            nombres=request.form['nombres'],
            apellidos=request.form['apellidos'],
            telefono=request.form['telefono'],
            edad=request.form['edad'],
            correo=request.form['correo'],
            contrasena=hashed_contrasena
        )
        db.session.add(nuevo_usuario)
        db.session.commit()
        
        # --- REDIRECCIÓN CORREGIDA ---
        flash('¡Registro de vendedor exitoso! Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login', user_type='vendedor'))
        
    return render_template('registroV.html')

# 6. Iniciar la Aplicación
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

