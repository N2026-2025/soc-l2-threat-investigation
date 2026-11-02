import unittest, pathlib
from app import analysis, llm
raw = (pathlib.Path(__file__).parent.parent / "samples" / "sample_logs.csv").read_bytes()
class T(unittest.TestCase):
    def setUp(self): self.df = analysis.load("x.csv", raw); self.r = analysis.analyze(self.df)
    def test_rules(self):
        self.assertTrue({"AUTH-001", "AUTH-002", "EXEC-001", "LAT-001"} <= {f["rule"] for f in self.r["findings"]})
    def test_incident_correlated(self): self.assertEqual(self.r["incidents"][0]["risk"], "Crítico")
    def test_evidence_exists(self):
        ids = set(self.df.Log_ID); self.assertTrue(all(e in ids for f in self.r["findings"] for e in f["evidence"]))
    def test_no_hallucinated_ip(self):
        s = analysis.llm_summary(self.df, self.r); o = llm.validate(dict(a="ataque desde 9.9.9.9 y 185.220.101.45", limitaciones=[]), s)
        self.assertNotIn("9.9.9.9", o["a"]); self.assertIn("185.220.101.45", o["a"])
if __name__ == "__main__": unittest.main()
