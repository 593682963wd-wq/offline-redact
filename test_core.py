import unittest,tempfile,json
from pathlib import Path
from core import run

class Tests(unittest.TestCase):
 def test_email_ip(self):
  r=run({'text':'demo@example.invalid 192.0.2.8'});self.assertNotIn('demo@',r['redacted']);self.assertNotIn('192.0.2.8',r['redacted'])
 def test_empty(self):self.assertEqual(run({})['redacted'],'')
 def test_bad(self):
  with self.assertRaises(TypeError):run({'text':9})
 def test_nested(self):self.assertEqual(run({'data':{'mail':['demo@example.invalid']}})['data']['mail'],['[EMAIL]'])

if __name__=="__main__":unittest.main()
