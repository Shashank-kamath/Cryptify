from flask import Flask, render_template, request, redirect, url_for
from forms import CryptoForm
from crypto_utils import encrypt, decrypt, generate_rsa_keys

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

@app.route('/', methods=['GET', 'POST'])
def index():
    form = CryptoForm()
    rsa_keys = None
    result = None
    
    if form.validate_on_submit():
        text = form.text.data
        key = form.key.data
        operation = form.operation.data
        cipher = form.cipher.data
        
        if form.generate_rsa_keys.data and cipher == 'rsa':
            private_key, public_key = generate_rsa_keys()
            rsa_keys = {
                'private_key': private_key,
                'public_key': public_key
            }
        else:
            if operation == 'encrypt':
                result = encrypt(text, key, cipher)
            elif operation == 'decrypt':
                result = decrypt(text, key, cipher)
        
        return render_template('result.html', result=result, rsa_keys=rsa_keys, operation=operation)
    
    return render_template('index.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
