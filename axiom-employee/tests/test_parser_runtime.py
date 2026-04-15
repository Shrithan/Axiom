import builtins
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from axiom_agent.extraction import extract, ExtractionError
class ParserRuntimeTests(unittest.TestCase):
    def test_missing_pdf_dependency_is_not_called_malformed(self):
        original=builtins.__import__
        def importing(name,*args,**kwargs):
            if name=='fitz':raise ModuleNotFoundError('test missing parser')
            return original(name,*args,**kwargs)
        with patch('builtins.__import__',side_effect=importing):
            with self.assertRaisesRegex(ExtractionError,'Local PDF parser is unavailable') as error:extract('document.pdf',b'%PDF-1.4')
        self.assertNotIn('malformed',str(error.exception))
