const express = require('express');
const cors = require('cors');
const { resolveWithISP, resolveWithPublic, resolveWithDoH, resolveCustom, getSystemResolvers } = require('./dnsResolver');
const { classify, getRecommendation } = require('./detector');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'DNS Censorship Toolkit API Running' });
});

app.post('/check', async (req, res) => {
  const { domain, resolver } = req.body;

  if (!domain || typeof domain !== 'string' || domain.trim() === '') {
    return res.status(400).json({ error: 'A valid domain string is required.' });
  }

  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '');

  try {
    
    const [ispResult, publicResult, dohResult] = await Promise.all([
      resolver ? resolveCustom(resolver, cleanDomain) : resolveWithISP(cleanDomain),
      resolveWithPublic(cleanDomain),
      resolveWithDoH(cleanDomain)
    ]);

    const classification = classify(ispResult, publicResult, dohResult);
    const recommendation = getRecommendation(classification.method);

    res.json({
      domain: cleanDomain,
      status: classification.status,
      method: classification.method,
      evidence: {
        isp_result: ispResult,
        isp_source: resolver || getSystemResolvers().join(', '),
        public_result: publicResult,
        doh_result: dohResult
      },
      recommendation
    });

  } catch (err) {
    res.status(500).json({ error: 'Internal error during DNS resolution.', detail: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`DNS Toolkit API running on port ${PORT}`);
  console.log(`System resolvers detected: ${getSystemResolvers().join(', ')}`);
});

module.exports = app;
