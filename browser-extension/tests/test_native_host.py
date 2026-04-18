import importlib.util,io,json,struct,tempfile,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('axiom_native_host',Path(__file__).resolve().parents[1]/'native/host.py');host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
class NativeHostTests(unittest.TestCase):
 def test_valid_frame(self):
  stream=io.BytesIO();host.write_message(stream,{'request_id':'one','ok':True});stream.seek(0);self.assertEqual(host.read_message(stream)['request_id'],'one')
 def test_oversized_frame(self):
  with self.assertRaises(ValueError):host.read_message(io.BytesIO(struct.pack('<I',host.MAX_INPUT+1)))
 def test_truncated_frame(self):
  with self.assertRaises(EOFError):host.read_message(io.BytesIO(struct.pack('<I',10)+b'{}'))
 def test_malformed_json(self):
  with self.assertRaises(ValueError):host.read_message(io.BytesIO(struct.pack('<I',1)+b'!'))
 def test_unknown_message_type(self):
  with self.assertRaises(ValueError):host.read_message(io.BytesIO(struct.pack('<I',2)+b'[]'))
 def test_exact_extension_identity(self):self.assertRegex(host.expected_origin(),r'^chrome-extension://[a-p]{32}/$')
 def test_no_host_output_content_logs(self):self.assertNotIn('print(',Path(host.__file__).read_text())
