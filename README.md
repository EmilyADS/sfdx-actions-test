C:\Users\emily\OneDrive\Documentos\GITHUB\sfdx-actions-test\.github\workflows\server.key
3MVG9dZJodJWITSsG.BrFRTEjksR1pjSwekGx1.Mnqx.t8XPdk4wvPbCoJyXAsJwlIHoRuEiWxcr0JVMpDPJz
emily.berteloni@companyteste1.com

python -m PyInstaller --onefile --windowed frontend.py




import tkinter as tk
from datetime import datetime
import jwt
import time
import requests

def run_salesforce_tool():
    response_text.delete('1.0', tk.END)  # Limpa o texto anterior, se houver

    try:
        key_file = key_file_entry.get().strip()
        issuer = issuer_entry.get().strip()
        subject = subject_entry.get().strip()
        is_sandbox = sandbox_var.get().strip()

        IS_SANDBOX = is_sandbox.lower() == 'true'

        # *** Update these values to match your configuration ***
        # Defina os valores reais para ISSUER e SUBJECT aqui
        ISSUER = issuer
        SUBJECT = subject

        DOMAIN = 'test' if IS_SANDBOX else 'login'

        # Verifique se KEY_FILE contém o caminho correto para seu arquivo de chave privada
        print('Loading private key...')
        with open(key_file, 'r') as fd:
            private_key = fd.read()
            print(private_key)

        print('Generating signed JWT assertion...')
        claim = {
            'iss': ISSUER,
            'exp': int(time.time()) + 300,
            'aud': 'https://{}.salesforce.com'.format(DOMAIN),
            'sub': SUBJECT,
        }
        print(claim)
        print(ISSUER, IS_SANDBOX, SUBJECT, DOMAIN)
        assertion = jwt.encode(claim, private_key, algorithm='RS256', headers={'alg': 'RS256'})

        print('Making OAuth request...')
        r = requests.post('https://{}.salesforce.com/services/oauth2/token'.format(DOMAIN), data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': assertion,
        })

        print('Status:', r.status_code)
        response_text.insert(tk.END, f'Status: {r.status_code}\nResponse: {r.json()}')
        print(r.json())
    except Exception as e:
        # Captura qualquer exceção e imprime uma mensagem de erro
        error_message = f"Erro: {str(e)}"
        response_text.insert(tk.END, error_message)

root = tk.Tk()
root.title("Salesforce Tool")

key_file_label = tk.Label(root, text="Adicione aqui o caminho da sua chave privada: KEY_FILE:")
key_file_label.pack()
key_file_entry = tk.Entry(root)
key_file_entry.pack()

issuer_label = tk.Label(root, text="Adicione aqui a consumer key: ISSUER:")
issuer_label.pack()
issuer_entry = tk.Entry(root)
issuer_entry.pack()

subject_label = tk.Label(root, text="Adicione aqui o username: SUBJECT:")
subject_label.pack()
subject_entry = tk.Entry(root)
subject_entry.pack()

sandbox_label = tk.Label(root, text="É ambiente de sandbox? (True/False):")
sandbox_label.pack()

sandbox_var = tk.StringVar(value="False")
sandbox_entry = tk.Entry(root, textvariable=sandbox_var)
sandbox_entry.pack()

run_button = tk.Button(root, text="Run Salesforce Tool", command=run_salesforce_tool)
run_button.pack()

response_text = tk.Text(root, height=10, width=100)
response_text.pack()

root.mainloop()
