import sys
sys.path.insert(0, '.')
from app import analysis, llm, pdf

raw = open('samples/sample_logs.csv', 'rb').read()
df = analysis.load('x.csv', raw)
r = analysis.analyze(df)
s = analysis.llm_summary(df, r)
rep = llm.generate(s)
body = pdf.build_combined(r, rep, s)
open('/tmp/test_completo.pdf', 'wb').write(body)
print('PDF completo OK, bytes:', len(body))