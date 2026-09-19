#!/usr/bin/env python3
"""Snapshot-backed maintenance for ONE single-replica DeSo StatefulSet.

See PLANS/badger-maintenance.md. No defaults identify a production target.
Each phase is explicit; plan/status are read-only. Never deletes source storage.
Only sanitized state is saved; no container env, seeds, or credentials are saved.
"""
import argparse, copy, datetime, fcntl, hashlib, json, os, pathlib, re
import subprocess, time

def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True).encode()).hexdigest()
def switched(spec,container,mount_path,volume_name,claim):
    result=copy.deepcopy(spec)
    target=next(c for c in result['template']['spec']['containers'] if c['name']==container)
    mounts=[m for m in target['volumeMounts'] if m['mountPath']==mount_path]
    if len(mounts)!=1 or mounts[0].get('subPath') or mounts[0].get('subPathExpr'):
        raise ValueError('Exactly one whole-volume data mount required')
    volumes=result['template']['spec'].setdefault('volumes',[])
    if any(v['name']==volume_name for v in volumes):raise ValueError('New volume name already exists')
    mounts[0]['name']=volume_name
    volumes.append({'name':volume_name,'persistentVolumeClaim':{'claimName':claim}})
    return result

class Operation:
    def __init__(self,path):
        self.path=pathlib.Path(path).resolve();self.r=json.loads(self.path.read_text())
        self.env=dict(os.environ,CLOUDSDK_CORE_ACCOUNT=self.r['account'])
    def save(self,stage=None,**kw):
        self.r.update(kw)
        if stage:self.r['stage']=stage
        self.r['updatedAt']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        tmp=self.path.with_suffix('.tmp');tmp.write_text(json.dumps(self.r,indent=2)+'\n');tmp.chmod(0o600);tmp.replace(self.path)
        print(json.dumps({'stage':self.r['stage'],'state':str(self.path)}),flush=True)
    def run(self,args,data=None,timeout=90):
        p=subprocess.run(args,input=data,env=self.env,capture_output=True,timeout=timeout)
        if p.returncode:raise RuntimeError(p.stderr.decode(errors='replace')[:900])
        return p.stdout.decode()
    def k(self,*args,data=None,timeout=90):
        return self.run(['kubectl','--context',self.r['context'],'-n',self.r['namespace'],*args],data,timeout)
    def get(self,kind,name):return json.loads(self.k('get',kind,name,'-o','json'))
    def g(self,*args,timeout=180):
        s=self.run(['gcloud',*args,'--account='+self.r['account'],'--project='+self.r['project'],'--quiet','--format=json'],timeout=timeout)
        return json.loads(s) if s.strip() else None
    def api(self,pod,path,data=None):
        args=['exec',pod,'-c',self.r['container'],'--','wget','-T','12','-qO-']
        if self.r.get('hostHeader'):args+=['--header=Host: '+self.r['hostHeader']]
        if data is not None:args+=['--header=Content-Type: application/json','--post-data='+json.dumps(data)]
        return json.loads(self.k(*args,'http://127.0.0.1:81'+path))
    def create(self,obj):self.k('create','-f','-',data=json.dumps(obj).encode())
    def wait(self,fn,seconds=600):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            if fn():return
            time.sleep(5)
        raise RuntimeError('Timed out; inspect state before retrying. No source storage deleted.')
    def absent(self,kind,name):return not self.k('get',kind,name,'--ignore-not-found','-o','name').strip()
    def scale(self,n):
        s=self.get('sts',self.r['statefulset'])
        self.k('patch','sts',self.r['statefulset'],'--type=json','-p',json.dumps([
            {'op':'test','path':'/metadata/resourceVersion','value':s['metadata']['resourceVersion']},
            {'op':'replace','path':'/spec/replicas','value':n}]))
    def stop(self):
        if not self.absent('pod',self.r['pod']):self.k('delete','pod',self.r['pod'],'--grace-period=180','--wait=false')
        self.scale(0);self.wait(lambda:self.absent('pod',self.r['pod']))
    def helper_exec(self,*args,timeout=90):return self.k('exec',self.r['helper'],'-c','maintenance','--',*args,timeout=timeout)
    def copy_binary(self,local,remote):
        data=pathlib.Path(local).read_bytes()
        self.k('exec','-i',self.r['helper'],'-c','maintenance','--','sh','-c','cat > '+remote+' && chmod 0755 '+remote,data=data,timeout=180)
        assert self.helper_exec('sha256sum',remote).split()[0]==hashlib.sha256(data).hexdigest()
    def remove_helper(self):
        if not self.absent('pod',self.r['helper']):
            self.k('delete','pod',self.r['helper'],'--wait=false');self.wait(lambda:self.absent('pod',self.r['helper']))
    def health(self):
        r=self.r;p=self.get('pod',r['pod'])
        own=self.api(r['pod'],'/api/v0/get-committed-tip-block-info')
        ref=self.api(r['referencePod'],'/api/v0/get-committed-tip-block-info')
        canonical=self.api(r['referencePod'],'/api/v1/block',{'Height':own['Height'],'FullBlock':False})['Header']['BlockHashHex']==own['HashHex']
        state=self.api(r['pod'],'/api/v1/node-info',{})['DeSoStatus']['State']
        return {'height':own['Height'],'hash':own['HashHex'],'lag':ref['Height']-own['Height'],'canonical':canonical,'state':state,'ready':all(c['ready'] for c in p['status']['containerStatuses']),'restarts':sum(c['restartCount'] for c in p['status']['containerStatuses'])}
    def plan(self):
        r=self.r;s=self.get('sts',r['statefulset']);p=self.get('pod',r['pod']);spec=s['spec']
        assert spec['replicas']==1 and spec['updateStrategy']['type']=='OnDelete','Only single-replica OnDelete StatefulSets supported'
        assert r['pod']==r['statefulset']+'-0'
        assert all(v=='Retain' for v in spec.get('persistentVolumeClaimRetentionPolicy',{}).values())
        c=next(c for c in spec['template']['spec']['containers'] if c['name']==r['container'])
        m=next(m for m in c['volumeMounts'] if m['mountPath']==r['mountPath'])
        assert not m.get('subPath') and not m.get('subPathExpr')
        claim=next(v['persistentVolumeClaim']['claimName'] for v in p['spec']['volumes'] if v['name']==m['name'])
        pvc=self.get('pvc',claim);pv=self.get('pv',pvc['spec']['volumeName'])
        assert pv['spec']['persistentVolumeReclaimPolicy']=='Retain'
        fs=pv['spec'].get('gcePersistentDisk',pv['spec'].get('csi',{})).get('fsType','ext4')
        assert fs in ('','ext4'),'Only ext4 volumes are supported by this driver'
        disk=pv['spec'].get('gcePersistentDisk',{}).get('pdName') or pv['spec'].get('csi',{}).get('volumeHandle','').split('/')[-1]
        assert disk
        d=self.g('compute','disks','describe',disk,'--zone='+r['zone'])
        assert len(d.get('users',[]))==1 and d['users'][0].endswith('/'+p['spec']['nodeName'])
        node=self.get('node',p['spec']['nodeName'])
        assert node['status']['nodeInfo']['architecture']=='amd64','Build the tools for the actual target architecture'
        self.k('exec',r['pod'],'-c',r['container'],'--','test','-f',r['dbPath']+'/MANIFEST')
        h=self.health();assert h['canonical'],'Starting source must match the reference chain'
        self.save('planned',originalSpecHash=digest(spec),originalMounts=c['volumeMounts'],originalVolumes=spec['template']['spec'].get('volumes',[]),image=c['image'],resources=c.get('resources',{}),sourceDisk=disk,sourceDiskID=d['id'],diskSizeGiB=int(d['sizeGb']),diskType=d['type'].split('/')[-1],sourceClaim=claim,node=p['spec']['nodeName'],baseline=h)
    def clone(self):
        r=self.r;assert r['stage']=='planned'
        assert digest(self.get('sts',r['statefulset'])['spec'])==r['originalSpecHash']
        try:
            self.stop()
            self.wait(lambda:not self.g('compute','disks','describe',r['sourceDisk'],'--zone='+r['zone']).get('users'))
            self.g('compute','snapshots','create',r['snapshot'],'--source-disk='+r['sourceDisk'],'--source-disk-zone='+r['zone'],'--storage-location='+r['zone'].rsplit('-',1)[0],'--async')
            self.wait(lambda:self.g('compute','snapshots','describe',r['snapshot'])['status']=='READY',1200)
            snap=self.g('compute','snapshots','describe',r['snapshot']);assert snap['sourceDiskId']==r['sourceDiskID']
            self.save('snapshot-ready',snapshotID=snap['id'])
        finally:
            # Resume the original even if snapshot creation fails.
            self.scale(1)
        self.g('compute','disks','create',r['cloneDisk'],'--zone='+r['zone'],'--source-snapshot='+r['snapshot'],'--type='+r['diskType'],'--size='+str(r['diskSizeGiB'])+'GB',timeout=600)
        d=self.g('compute','disks','describe',r['cloneDisk'],'--zone='+r['zone']);assert d['sourceSnapshotId']==r['snapshotID']
        self.save('clone-ready',cloneDiskID=d['id'])
    def compact(self,binary,audit):
        r=self.r;assert r['stage'] in ('clone-ready','compacting'),'Interrupted phases require inspecting saved state first'
        d=self.g('compute','disks','describe',r['cloneDisk'],'--zone='+r['zone'])
        assert d['id']==r['cloneDiskID'] and d['sourceSnapshotId']==r['snapshotID']
        for pod in json.loads(self.k('get','pods','-o','json'))['items']:
            for volume in pod['spec'].get('volumes',[]):
                if volume.get('persistentVolumeClaim',{}).get('claimName')==r['cloneDisk']:
                    assert pod['metadata']['name']==r['helper'],'Copy is mounted by a different pod'
        if r['stage']=='clone-ready':
            size=str(r['diskSizeGiB'])+'Gi'
            self.create({'apiVersion':'v1','kind':'PersistentVolume','metadata':{'name':r['cloneDisk']},'spec':{'capacity':{'storage':size},'accessModes':['ReadWriteOnce'],'persistentVolumeReclaimPolicy':'Retain','storageClassName':'','gcePersistentDisk':{'pdName':r['cloneDisk'],'fsType':'ext4'},'claimRef':{'namespace':r['namespace'],'name':r['cloneDisk']},'nodeAffinity':{'required':{'nodeSelectorTerms':[{'matchExpressions':[{'key':'topology.kubernetes.io/zone','operator':'In','values':[r['zone']]}]}]}}}})
            self.create({'apiVersion':'v1','kind':'PersistentVolumeClaim','metadata':{'name':r['cloneDisk']},'spec':{'accessModes':['ReadWriteOnce'],'resources':{'requests':{'storage':size}},'storageClassName':'','volumeName':r['cloneDisk']}})
            self.create({'apiVersion':'v1','kind':'Pod','metadata':{'name':r['helper'],'labels':{'badger-maintenance':r['operation']}},'spec':{'nodeSelector':{'kubernetes.io/hostname':r['node']},'automountServiceAccountToken':False,'restartPolicy':'Never','terminationGracePeriodSeconds':30,'securityContext':{'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'maintenance','image':r['image'],'command':['sh','-c',"trap 'exit 0' TERM INT; while :; do sleep 1; done"],'resources':{'requests':{'cpu':'100m','memory':'8Gi'},'limits':{'cpu':'2','memory':'12Gi'}},'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},'volumeMounts':[{'name':'copy','mountPath':r['mountPath']},{'name':'tmp','mountPath':'/tmp'}]}],'volumes':[{'name':'copy','persistentVolumeClaim':{'claimName':r['cloneDisk']}},{'name':'tmp','emptyDir':{'sizeLimit':'128Mi'}}]}})
            self.wait(lambda:any(s.get('ready') for s in self.get('pod',r['helper'])['status'].get('containerStatuses',[])))
            self.copy_binary(binary,'/tmp/badger-maint')
            # All substituted values are validated path/integer arguments, not shell input.
            command="nohup sh -c 'GOMAXPROCS=2 GOMEMLIMIT=8GiB /tmp/badger-maint --confirm-offline-copy --workers=1 --dir="+r['dbPath']+' --height='+str(r['baseline']['height'])+" > /tmp/maintenance.jsonl 2>&1; echo $? > /tmp/maintenance.exit' </dev/null >/dev/null 2>&1 &"
            self.helper_exec('sh','-c',command);self.save('compacting')
        deadline=time.monotonic()+7200
        while time.monotonic()<deadline:
            result=self.helper_exec('sh','-c','if test -f /tmp/maintenance.exit; then cat /tmp/maintenance.exit; else echo running; fi').strip()
            if result!='running':break
            time.sleep(10)
        else:raise RuntimeError('Still compacting. Original is online. Re-run compact to resume monitoring, not the DB process.')
        output=self.helper_exec('cat','/tmp/maintenance.jsonl');self.path.with_suffix('.maintenance.jsonl').write_text(output)
        assert result=='0','Compaction failed; original remains active. Inspect helper/OOM status.'
        rows=[json.loads(l) for l in output.splitlines() if l.startswith('{')]
        assert any(x.get('stage')=='validated' for x in rows)
        self.copy_binary(audit,'/tmp/chain-audit')
        args=['/tmp/chain-audit','--data-dir='+str(pathlib.PurePosixPath(r['dbPath']).parent)]
        if r.get('testnet'):args+=['--testnet']
        audit_out=self.helper_exec(*args,timeout=240);self.path.with_suffix('.audit.jsonl').write_text(audit_out)
        a=[json.loads(l) for l in audit_out.splitlines() if l.startswith('{')]
        tip=next(x for x in a if x['type']=='state_tip');qc=next(x for x in a if x['type']=='recent_consensus_votes')
        assert tip['committed'] and qc['verifiedQCs']>=3
        assert self.api(r['referencePod'],'/api/v1/block',{'Height':tip['height'],'FullBlock':False})['Header']['BlockHashHex']==tip['hash']
        self.save('compacted-and-audited',maintenance=rows,auditedTip=tip,verifiedQCs=qc['verifiedQCs'])
    def original_spec(self,spec):
        """Accept only the recorded layout or our exact one-volume switch."""
        r=self.r
        idx=next(i for i,c in enumerate(spec['template']['spec']['containers']) if c['name']==r['container'])
        c=spec['template']['spec']['containers'][idx];assert c['image']==r['image'] and c.get('resources',{})==r['resources']
        baseline=copy.deepcopy(spec);baseline['replicas']=1;baseline['template']['spec']['containers'][idx]['volumeMounts']=r['originalMounts'];baseline['template']['spec']['volumes']=r['originalVolumes']
        if not r['originalVolumes']:baseline['template']['spec'].pop('volumes',None)
        assert digest(baseline)==r['originalSpecHash'],'Unrelated StatefulSet changes detected; do not overwrite'
        current=copy.deepcopy(spec);current['replicas']=1
        expected_trial=switched(baseline,r['container'],r['mountPath'],r['volumeName'],r['cloneDisk'])
        assert digest(current) in (digest(baseline),digest(expected_trial)), 'Unrelated mount/volume changes detected; do not overwrite'
        return baseline
    def mount(self,trial):
        r=self.r;s=self.get('sts',r['statefulset']);spec=s['spec'];assert spec['replicas']==0
        baseline=self.original_spec(spec)
        idx=next(i for i,c in enumerate(spec['template']['spec']['containers']) if c['name']==r['container'])
        desired=switched(baseline,r['container'],r['mountPath'],r['volumeName'],r['cloneDisk']) if trial else baseline
        self.k('patch','sts',r['statefulset'],'--type=json','-p',json.dumps([
            {'op':'test','path':'/metadata/resourceVersion','value':s['metadata']['resourceVersion']},
            {'op':'add','path':'/spec/template/spec/volumes','value':desired['template']['spec'].get('volumes',[])},
            {'op':'replace','path':f'/spec/template/spec/containers/{idx}/volumeMounts','value':desired['template']['spec']['containers'][idx]['volumeMounts']}]))
        self.scale(1)
    def activate(self):
        r=self.r;assert r['stage']=='compacted-and-audited'
        assert digest(self.get('sts',r['statefulset'])['spec'])==r['originalSpecHash']
        self.remove_helper()
        self.wait(lambda:not self.g('compute','disks','describe',r['cloneDisk'],'--zone='+r['zone']).get('users'))
        if r.get('validatorKey'):
            self.save(activityBefore=self.api(r['referencePod'],'/api/v0/validators/'+r['validatorKey'])['LastActiveAtEpochNumber'])
        self.stop();self.mount(True);self.save('trial-running')
    def rollback(self):
        r=self.r;d=self.g('compute','disks','describe',r['sourceDisk'],'--zone='+r['zone'])
        assert d['id']==r['sourceDiskID'],'Original disk missing/replaced; do not attempt rollback'
        self.original_spec(self.get('sts',r['statefulset'])['spec'])
        self.remove_helper();self.stop();self.mount(False);self.save('restored-original')
    def validate(self):
        assert self.r['stage']=='trial-running';start=time.monotonic();stable=None;initial=None
        while time.monotonic()-start<1200:
            try:
                h=self.health();print(json.dumps(h),flush=True)
                okay=h['ready'] and h['canonical'] and abs(h['lag'])<=5 and h['state']=='FULLY_CURRENT' and h['restarts']==0
                if okay:
                    if stable is None:stable=time.monotonic();initial=h['height']
                    if time.monotonic()-stable>=180 and h['height']>initial:
                        self.save('health-passed',finalHealth=h,validatorParticipationStillNeedsVerification=bool(self.r.get('validatorKey')));return
                else:stable=None
            except Exception as e:stable=None;print(str(e)[:200],flush=True)
            time.sleep(10)
        self.rollback();raise RuntimeError('Live health gate failed; original disk restored. Verify its recovery.')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=['plan','clone','compact','activate','validate','rollback','status'])
    p.add_argument('--state',required=True);p.add_argument('--config');p.add_argument('--confirm-target');p.add_argument('--binary');p.add_argument('--audit-binary');a=p.parse_args()
    path=pathlib.Path(a.state).expanduser().resolve()
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with path.with_suffix('.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if a.phase=='plan':
            if path.exists():raise ValueError('Use a fresh state path; never overwrite a prior operation')
            c=json.loads(pathlib.Path(a.config).read_text())
            for key in ['account','context','project','zone','namespace','statefulset','referencePod','operation','dbPath']:
                if not c.get(key):raise ValueError('Missing '+key)
            if not re.fullmatch('[a-z][a-z0-9-]{1,38}',c['operation']):raise ValueError('operation must be a short new resource name')
            if any('REPLACE' in str(v) for v in c.values()):raise ValueError('Replace all example placeholders first')
            if c['referencePod']==c['statefulset']+'-0':raise ValueError('Reference must be a different healthy node')
            c.setdefault('container','be');c.setdefault('mountPath','/pd')
            if not re.fullmatch(r'/[a-zA-Z0-9_./-]+/badgerdb',c['dbPath']) or '..' in c['dbPath'].split('/') or not c['dbPath'].startswith(c['mountPath']+'/'):raise ValueError('Unsafe or unsupported DB path')
            c.update(pod=c['statefulset']+'-0',snapshot=c['operation']+'-before',cloneDisk=c['operation']+'-copy',helper=c['operation']+'-worker',volumeName=c['operation'],stage='new')
            path.write_text(json.dumps(c));path.chmod(0o600)
        op=Operation(path)
        if a.phase not in ('plan','status') and a.confirm_target!=op.r['statefulset']:raise ValueError('--confirm-target must equal the exact StatefulSet name')
        if a.phase=='compact':
            if not a.binary or not a.audit_binary:raise ValueError('Both binary paths required')
            op.compact(a.binary,a.audit_binary)
        elif a.phase=='status':print(json.dumps(op.r,indent=2))
        else:getattr(op,a.phase)()
if __name__=='__main__':main()
