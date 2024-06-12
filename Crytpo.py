import csv
import hashlib
import io
import os

import pandas as pd
import streamlit as st
from cryptography.hazmat.primitives import constant_time, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import boto3

# Configurar boto3 para usar S3
s3_client = boto3.client(
    's3',
    aws_access_key_id='AKIAW3MEAVXTOEKOWBZT',
    aws_secret_access_key='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',
    region_name='us-west-2'
)

BUCKET_NAME = 'crypto2024'
USERS_CSV_S3_KEY = 'credentials.csv'

# Cargar usuarios desde S3
def load_users():
    try:
        obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=USERS_CSV_S3_KEY)
        return pd.read_csv(io.BytesIO(obj['Body'].read()))
    except s3_client.exceptions.NoSuchKey:
        # Si el archivo no existe, crear un DataFrame vacío
        df = pd.DataFrame(columns=['username', 'password_hash', 'private_key_path', 'public_key_path'])
        save_users(df)
        return df

# Guardar usuarios en S3
def save_users(users):
    csv_buffer = io.StringIO()
    users.to_csv(csv_buffer, index=False)
    s3_client.put_object(Bucket=BUCKET_NAME, Key=USERS_CSV_S3_KEY, Body=csv_buffer.getvalue())

def generate_keys(user):
    # Generar el par de claves
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Serializar y guardar las claves en archivos
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Subir las claves a S3
    private_key_path = f'{user}/private_key.pem'
    public_key_path = f'{user}/public_key.pem'
    s3_client.put_object(Bucket=BUCKET_NAME, Key=private_key_path, Body=private_key_pem)
    s3_client.put_object(Bucket=BUCKET_NAME, Key=public_key_path, Body=public_key_pem)

    return private_key_path, public_key_path

def load_user_keys(user):
    try:
        private_key_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=f'{user}/private_key.pem')
        public_key_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=f'{user}/public_key.pem')
        
        private_key = serialization.load_pem_private_key(private_key_obj['Body'].read(), password=None)
        public_key = serialization.load_pem_public_key(public_key_obj['Body'].read())
        
        return private_key, public_key
    except s3_client.exceptions.NoSuchKey:
        return None, None

def calculate_hash(data):
    return hashlib.sha256(data).digest()

def sign_document(private_key, document, document_name, user):
    try:
        document_hash = calculate_hash(document)
        # Firmar el hash del documento
        signature = private_key.sign(
            document_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        # Crear una carpeta con el nombre del usuario si no existe
        user_folder = os.path.join("users", user)
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)

        # Crear una subcarpeta con el nombre del archivo dentro de la carpeta del usuario
        folder_name = os.path.join(user_folder, os.path.splitext(document_name)[0])
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)

        # Guardar el archivo firmado en la subcarpeta
        signed_document_path = os.path.join(folder_name, document_name)
        with open(signed_document_path, "wb") as f:
            f.write(document)

        # Guardar la firma y el hash en un archivo con el nombre personalizado
        signature_filename = f"{os.path.splitext(document_name)[0]}_signature.sig"
        signature_path = os.path.join(folder_name, signature_filename)
        with open(signature_path, "wb") as f:
            f.write(signature)
            f.write(document_hash)  # Guardar el hash del documento

        st.success(f"Documento firmado y guardado en '{folder_name}'.")
        st.write("Ruta del archivo firmado:", os.path.abspath(signed_document_path))
        st.write("Ruta del archivo de firma:", os.path.abspath(signature_path))

        # Proporcionar enlaces de descarga para el documento firmado y la firma
        with open(signed_document_path, "rb") as f:
            signed_document_bytes = f.read()
        with open(signature_path, "rb") as f:
            signature_bytes = f.read()

        st.download_button(
            label="Descargar documento firmado",
            data=signed_document_bytes,
            file_name=document_name,
        )

        st.download_button(
            label="Descargar archivo de firma",
            data=signature_bytes,
            file_name=signature_filename,
        )

        # Cerrar sesión después de firmar el documento
        st.session_state.logged_in = False
        st.session_state.current_user = None

    except Exception as e:
        st.error(f"Error al firmar el documento: {e}")

def save_credentials(user, password):
    # Cargar las credenciales existentes
    credentials = load_credentials()
    if user in credentials:
        st.error(
            "El nombre de usuario ya existe. Por favor, elija otro nombre de usuario."
        )
        return False

    # Guardar las credenciales en un archivo CSV
    file_exists = os.path.isfile("credentials.csv")
    with open("credentials.csv", "a", newline="") as csvfile:
        fieldnames = ["username", "password"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow({"username": user, "password": password})
    st.success("Usuario registrado correctamente.")
    return True

def load_credentials():
    credentials = {}
    if os.path.isfile("credentials.csv"):
        with open("credentials.csv", "r") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                credentials[row["username"]] = row["password"]
    return credentials

def verify_signature(public_key, document, signature):
    try:
        document_hash = calculate_hash(document)
        # Leer el hash guardado en el archivo de firma
        saved_document_hash = signature[-32:]
        signature = signature[:-32]
        if not constant_time.bytes_eq(document_hash, saved_document_hash):
            st.error("El documento ha sido modificado.")
            return False
        public_key.verify(
            signature,
            saved_document_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        st.error(f"Error al verificar la firma: {e}")
        return False

def main():
    st.title("Sistema de Firma Digital")

    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.current_user = None

    choice = st.sidebar.selectbox(
        "Seleccione una opción", ["Iniciar Sesión", "Registrarse", "Autenticar Firma"]
    )

    if choice == "Iniciar Sesión":
        st.subheader("Iniciar Sesión")
        user = st.text_input("Nombre de usuario", key="login_user")
        password = st.text_input("Contraseña", type="password", key="login_password")
        if st.button("Iniciar Sesión"):
            credentials = load_credentials()
            if user in credentials and credentials[user] == password:
                st.session_state.logged_in = True
                st.session_state.current_user = user
                st.success(f"Bienvenido, {user}")
            else:
                st.session_state.logged_in = False
                st.session_state.current_user = None
                st.error("Usuario o contraseña incorrectos.")

        if st.session_state.logged_in:
            st.subheader("Firmar Documento")
            document = st.file_uploader(
                "Seleccione el documento a firmar", key="upload_document"
            )
            if document is not None:
                document_name = document.name
                document_content = document.read()
                private_key, _ = load_user_keys(st.session_state.current_user)
                if private_key:
                    if st.button("Firmar Documento"):
                        sign_document(
                            private_key,
                            document_content,
                            document_name,
                            st.session_state.current_user,
                        )
        else:
            st.warning("Por favor, inicie sesión para firmar documentos.")

    elif choice == "Registrarse":
        st.subheader("Registrarse")
        user = st.text_input("Nombre de usuario", key="register_user")
        password = st.text_input("Contraseña", type="password", key="register_password")
        if st.button("Registrarse"):
            if user and password:
                if save_credentials(user, password):
                    generate_keys(user)
            else:
                st.error("Debe ingresar un nombre de usuario y una contraseña válidos.")

    elif choice == "Autenticar Firma":
        st.subheader("Autenticar Firma")
        document = st.file_uploader(
            "Seleccione el documento a autenticar", key="auth_upload_document"
        )
        signature_file = st.file_uploader(
            "Seleccione el archivo de firma", key="auth_upload_signature"
        )
        user = st.text_input("Nombre de usuario del firmante", key="auth_user")
        if st.button("Autenticar Firma"):
            if document is not None and signature_file is not None and user:
                document_content = document.read()
                signature_content = signature_file.read()
                _, public_key = load_user_keys(user)
                if public_key:
                    if verify_signature(public_key, document_content, signature_content):
                        st.success("La firma es válida.")
                    else:
                        st.error("La firma no es válida.")
                else:
                    st.error("No se encontraron las claves del usuario.")
            else:
                st.error("Debe proporcionar todos los archivos y el nombre de usuario.")

if _name_ == "_main_":
    main()