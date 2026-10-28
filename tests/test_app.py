import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app

class CertificateTest(unittest.TestCase):
    def test_url_normalization(self):
        self.assertEqual(app.normalize_domain('https://theater-in-essen.de/'), 'theater-in-essen.de')
        self.assertEqual(app.normalize_domain('THEATER-IN-ESSEN.DE'), 'theater-in-essen.de')
        self.assertEqual(app.normalize_domain('https://www.theater-in-essen.de/path?q=1'), 'www.theater-in-essen.de')
        with self.assertRaises(ValueError): app.normalize_domain('https://user:pass@theater-in-essen.de')
    def test_apex_and_subdomains_combined(self):
        row=lambda id, name: {'id':id,'common_name':name,'name_value':name,'issuer_name':'test','not_after':'2027-01-01'}
        def fake(query):
            return [row(1,'theater-in-essen.de')] if query=='theater-in-essen.de' else [row(1,'theater-in-essen.de'),row(2,'www.theater-in-essen.de')]
        with patch.object(app,'fetch_ct_query',side_effect=fake), patch.object(app,'read_json',return_value={}), patch.object(app,'save_json'):
            result,cached=app.search_ct('theater-in-essen.de')
        self.assertFalse(cached)
        self.assertEqual(len(result),2)
        self.assertEqual({r['common_name'] for r in result},{'theater-in-essen.de','www.theater-in-essen.de'})

if __name__=='__main__': unittest.main()
