"""Run the actual Conftest binary; never substitute simulated policy outcomes."""
from pathlib import Path
import subprocess,json,datetime,os,argparse

parser=argparse.ArgumentParser();parser.add_argument('--conftest',default='conftest');args=parser.parse_args()
root=Path(__file__).resolve().parent.parent;out=root/'artifacts';out.mkdir(exist_ok=True)
results=[]
def run(name,command,expected=0):
 p=subprocess.run(command,cwd=root,text=True,encoding='utf8',errors='replace',capture_output=True)
 content=p.stdout+p.stderr
 (out/(name+'.txt')).write_text('$ '+' '.join(command)+'\n\n'+content+'\nEXIT_CODE='+str(p.returncode)+'\n',encoding='utf8')
 results.append({'name':name,'command':command,'exit_code':p.returncode,'expected_exit_code':expected})
 print(name,'exit',p.returncode,'expected',expected,flush=True)
 if p.returncode!=expected:raise SystemExit(content)
run('versions',[args.conftest,'--version'])
run('unit-compose',[args.conftest,'verify','--policy','policy/compose','--no-color'])
run('unit-dockerfile',[args.conftest,'verify','--policy','policy/dockerfile','--no-color'])
run('before-compose',[args.conftest,'test','fixtures/insecure/docker-compose.yml','--policy','policy/compose','--no-color'],1)
run('before-dockerfile',[args.conftest,'test','fixtures/insecure/Dockerfile','--policy','policy/dockerfile','--no-color'],1)
run('after-compose',[args.conftest,'test','docker-compose.yml','--policy','policy/compose','--no-color'])
run('after-dockerfile',[args.conftest,'test','Dockerfile','--policy','policy/dockerfile','--no-color'])
(out/'local-results.json').write_text(json.dumps({'executed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Real local CLI execution; not GitLab pipeline evidence','results':results},indent=2),encoding='utf8')
print('Todas las comprobaciones locales terminaron con el resultado previsto.')
