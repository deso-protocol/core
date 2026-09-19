import copy
import unittest
from unittest import mock
from gke_badger_maintenance import switched, Operation, digest

class MountSafetyTest(unittest.TestCase):
    def setUp(self):
        self.spec={'replicas':1,'volumeClaimTemplates':[{'metadata':{'name':'original'}}],
          'template':{'spec':{'containers':[{'name':'be','image':'immutable@sha256:abc',
          'env':[{'name':'EXAMPLE_IDENTITY','value':'preserve'}],'resources':{'limits':{'memory':'40G'}},
          'volumeMounts':[{'name':'original','mountPath':'/pd'},{'name':'temp','mountPath':'/tmp'}]}],
          'volumes':[{'name':'temp','emptyDir':{}}]}}}
    def test_switch_preserves_everything_except_one_mount_and_added_volume(self):
        before=copy.deepcopy(self.spec)
        after=switched(self.spec,'be','/pd','copy','clone-pvc')
        self.assertEqual(self.spec,before)
        added=after['template']['spec']['volumes'].pop()
        self.assertEqual(added,{'name':'copy','persistentVolumeClaim':{'claimName':'clone-pvc'}})
        after['template']['spec']['containers'][0]['volumeMounts'][0]['name']='original'
        self.assertEqual(after,before)
    def test_existing_volume_rejected(self):
        with self.assertRaises(ValueError):switched(self.spec,'be','/pd','temp','clone-pvc')
    def test_partial_mount_rejected(self):
        self.spec['template']['spec']['containers'][0]['volumeMounts'][0]['subPath']='db'
        with self.assertRaises(ValueError):switched(self.spec,'be','/pd','copy','clone-pvc')
    def test_missing_mount_rejected(self):
        with self.assertRaises(ValueError):switched(self.spec,'be','/wrong','copy','clone-pvc')
    def operation(self):
        op=Operation.__new__(Operation)
        c=self.spec['template']['spec']['containers'][0]
        op.r={'statefulset':'target','sourceDisk':'source','sourceDiskID':'123','zone':'zone-a',
              'container':'be','mountPath':'/pd','volumeName':'copy','cloneDisk':'clone-pvc',
              'image':c['image'],'resources':copy.deepcopy(c['resources']),
              'originalMounts':copy.deepcopy(c['volumeMounts']),
              'originalVolumes':copy.deepcopy(self.spec['template']['spec']['volumes']),
              'originalSpecHash':digest(self.spec)}
        return op
    def test_only_recorded_original_and_exact_trial_layouts_are_accepted(self):
        op=self.operation()
        for layout in (self.spec,switched(self.spec,'be','/pd','copy','clone-pvc')):
            for replicas in (0,1):
                current=copy.deepcopy(layout);current['replicas']=replicas
                self.assertEqual(op.original_spec(current),self.spec)
    def test_rollback_rejects_unrelated_volume_edits_before_stopping_node(self):
        for change in ('added-volume','edited-mount','edited-claim'):
            with self.subTest(change=change):
                op=self.operation();current=switched(self.spec,'be','/pd','copy','clone-pvc')
                pod=current['template']['spec']
                if change=='added-volume':pod['volumes'].append({'name':'new','emptyDir':{}})
                elif change=='edited-mount':pod['containers'][0]['volumeMounts'][1]['readOnly']=True
                else:pod['volumes'][-1]['persistentVolumeClaim']['claimName']='another-claim'
                op.g=mock.Mock(return_value={'id':'123'});op.get=mock.Mock(return_value={'spec':current})
                op.stop=mock.Mock();op.remove_helper=mock.Mock();op.mount=mock.Mock()
                with self.assertRaises(AssertionError):op.rollback()
                op.stop.assert_not_called();op.remove_helper.assert_not_called();op.mount.assert_not_called()

class FailureSafetyTest(unittest.TestCase):
    def operation(self):
        op=Operation.__new__(Operation)
        op.r={'statefulset':'target','sourceDisk':'source','sourceDiskID':'123','zone':'zone-a',
              'cloneDisk':'copy','cloneDiskID':'456','snapshotID':'789','helper':'worker','stage':'clone-ready'}
        return op
    def test_rollback_checks_source_identity_before_any_stop(self):
        op=self.operation();op.g=mock.Mock(return_value={'id':'unexpected'})
        op.stop=mock.Mock();op.remove_helper=mock.Mock();op.mount=mock.Mock()
        with self.assertRaises(AssertionError):op.rollback()
        op.stop.assert_not_called();op.remove_helper.assert_not_called();op.mount.assert_not_called()
    def test_compaction_rejects_replaced_clone_before_creating_worker(self):
        op=self.operation();op.g=mock.Mock(return_value={'id':'wrong','sourceSnapshotId':'789'})
        op.create=mock.Mock();op.helper_exec=mock.Mock()
        with self.assertRaises(AssertionError):op.compact('unused','unused')
        op.create.assert_not_called();op.helper_exec.assert_not_called()
    def test_compaction_rejects_clone_already_used_by_another_pod(self):
        op=self.operation();op.g=mock.Mock(return_value={'id':'456','sourceSnapshotId':'789'})
        op.k=mock.Mock(return_value='{"items":[{"metadata":{"name":"live-node"},"spec":{"volumes":[{"persistentVolumeClaim":{"claimName":"copy"}}]}}]}')
        op.create=mock.Mock();op.helper_exec=mock.Mock()
        with self.assertRaises(AssertionError):op.compact('unused','unused')
        op.create.assert_not_called();op.helper_exec.assert_not_called()
    def test_snapshot_failure_resumes_original(self):
        op=self.operation();op.r.update(stage='planned',originalSpecHash='expected',snapshot='snapshot')
        op.get=mock.Mock(return_value={'spec':{}});op.stop=mock.Mock();op.scale=mock.Mock()
        op.wait=mock.Mock();op.g=mock.Mock(side_effect=RuntimeError('snapshot service unavailable'))
        with mock.patch('gke_badger_maintenance.digest',return_value='expected'):
            with self.assertRaises(RuntimeError):op.clone()
        op.stop.assert_called_once();op.scale.assert_called_once_with(1)

if __name__=='__main__':unittest.main()
