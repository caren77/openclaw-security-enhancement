"""Run archived stdlib/unittest and zero-argument tests without live agent calls.

This small runner is publication tooling, not a historical experimental harness.
It requires no pytest installation and creates config only in a temporary copy.
"""
from pathlib import Path
import importlib.util
import inspect
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='openclaw-pi-unit-') as tmp:
    project=Path(tmp)/'project'
    shutil.copytree(ROOT/'experiments/prompt-injection',project)
    shutil.copyfile(project/'config.example.json',project/'config.json')
    sys.path.insert(0,str(project/'src'))
    suite=unittest.TestSuite()
    for f in sorted((project/'tests').glob('test_*.py')):
        spec=importlib.util.spec_from_file_location(f.stem,f)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
        for name,func in inspect.getmembers(module,inspect.isfunction):
            if name.startswith('test_') and func.__module__==module.__name__:
                assert not inspect.signature(func).parameters, name
                suite.addTest(unittest.FunctionTestCase(func))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful(): raise SystemExit(1)
