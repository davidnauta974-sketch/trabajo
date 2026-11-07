from pathlib import Path
import secrets,os
root=Path(__file__).resolve().parent.parent
p=root/'.secrets/api_key';p.parent.mkdir(exist_ok=True)
if p.exists():raise SystemExit('El archivo ya existe; no se sobrescribe.')
with p.open('x',encoding='utf8') as f:f.write(secrets.token_urlsafe(32)+'\n')
if os.name!='nt':p.chmod(0o400)
print('Secreto local creado. Valor omitido. La carpeta .secrets está excluida de Git y Docker build.')
