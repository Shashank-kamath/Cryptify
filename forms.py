from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, BooleanField
from wtforms.validators import DataRequired

class CryptoForm(FlaskForm):
    text = StringField('Text', validators=[DataRequired()])
    key = StringField('Key', validators=[DataRequired()])
    operation = SelectField('Operation', choices=[('encrypt', 'Encrypt'), ('decrypt', 'Decrypt')], validators=[DataRequired()])
    cipher = SelectField('Cipher', choices=[('caesar', 'Caesar'), ('vigenere', 'Vigenère'), ('aes', 'AES'), ('rsa', 'RSA'), ('blowfish', 'Blowfish')], validators=[DataRequired()])
    generate_rsa_keys = BooleanField('Generate RSA Keys')
    submit = SubmitField('Submit')
