"""作者：Wangyuan；日期：2026-11-08。职责：通过合成输入复验已确认缺陷。"""
import unittest
from core import run
class ReleaseTests(unittest.TestCase):
 def test_url_with_ip_credentials_entirely_redacted(self) -> None:
  result=run({'text':'地址https://tester:demo-pass@192.0.2.1/private'})['redacted']
  self.assertEqual(result,'地址[URL]')
 def test_secret_punctuation_not_leaked(self) -> None:
  result=run({'text':'password=Demo!secret42'})['redacted']
  self.assertEqual(result,'password=[API_SECRET]')
 def test_chinese_adjacent_ip_and_compressed_ipv6(self) -> None:
  result=run({'text':'地址192.0.2.8以及2001:db8::1'})['redacted']
  self.assertNotIn('192.0.2.8',result);self.assertNotIn('2001:db8::1',result)

 def test_authorization_bearer_with_whitespace_is_fully_redacted(self) -> None:
  self.assertEqual(run({'text':'Authorization: Bearer synthetic_token_abcdefghijk'})['redacted'],'Authorization: Bearer [API_SECRET]')
 def test_quoted_secret_with_spaces_and_escaped_quotes(self) -> None:
  for text in ['password="synthetic token with spaces"', "password='synthetic token with spaces'",r'password="synthetic \"quoted\" token"']:
   result=run({'text':text})['redacted']
   self.assertNotIn('synthetic',result);self.assertNotIn('token',result);self.assertNotIn('quoted',result)

 def test_legacy_bearer_assignment_syntax_remains_redacted(self) -> None:
  for separator in ['=',': ']:
   self.assertEqual(run({'text':'bearer'+separator+'synthetic_token_abcdefghijk'})['redacted'],'bearer'+separator+'[API_SECRET]')
