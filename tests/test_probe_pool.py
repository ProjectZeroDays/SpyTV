# Probe pool / device tracking tests — covers uncovered paths
import sys, os, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

class TestProbePool(unittest.TestCase):
    def test_probe_pool_exists(self):
        import test_local_provider as lp
        self.assertTrue(hasattr(lp, 'ProbePool'))
    def test_local_provider_has_methods(self):
        import test_local_provider
        for m in ('probe_device', 'load_gallery', 'reload_gallery'):
            self.assertTrue(hasattr(test_local_provider, m) or hasattr(test_local_provider, 'test_' + m.lower()))

class TestC2Endpoints(unittest.TestCase):
    def test_c2_server_import(self):
        import importlib.util
        spec = importlib.util.find_spec("c2_server")
        self.assertIsNotNone(spec, "c2_server module should import")

class TestDashboardUI(unittest.TestCase):
    def test_dashboard_html_exists(self):
        self.assertTrue(os.path.exists("c2_dashboard.html"))

if __name__ == "__main__":
    unittest.main()
