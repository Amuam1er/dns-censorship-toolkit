// CDN IP ranges — different IPs from these providers are normal, not poisoning
// Sources: Cloudflare, Google, Fastly, Akamai published IP ranges
const CDN_RANGES = [
  // Cloudflare
  { start: '104.16.0.0',   end: '104.31.255.255' },
  { start: '172.64.0.0',   end: '172.71.255.255' },
  { start: '162.158.0.0',  end: '162.159.255.255' },
  { start: '198.41.128.0', end: '198.41.191.255' },
  { start: '190.93.240.0', end: '190.93.255.255' },
  { start: '188.114.96.0', end: '188.114.127.255' },
  { start: '197.234.240.0',end: '197.234.243.255' },
  { start: '103.21.244.0', end: '103.21.247.255' },
  { start: '103.22.200.0', end: '103.22.203.255' },
  { start: '103.31.4.0',   end: '103.31.7.255'   },
  { start: '141.101.64.0', end: '141.101.127.255' },
  { start: '108.162.192.0',end: '108.162.255.255' },
  { start: '131.0.72.0',   end: '131.0.75.255'   },
  // Google
  { start: '142.250.0.0',  end: '142.251.255.255' },
  { start: '172.217.0.0',  end: '172.217.255.255' },
  { start: '216.58.192.0', end: '216.58.223.255'  },
  { start: '74.125.0.0',   end: '74.125.255.255'  },
  // Fastly
  { start: '151.101.0.0',  end: '151.101.255.255' },
  { start: '199.232.0.0',  end: '199.232.255.255' },
  // Akamai
  { start: '23.32.0.0',    end: '23.67.255.255'   },
  { start: '96.16.0.0',    end: '96.17.255.255'   },
  { start: '184.24.0.0',   end: '184.51.255.255'  },
];

function ipToInt(ip) {
  return ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
}

function isKnownCDN(ip) {
  if (typeof ip !== 'string') return false;
  try {
    const ipInt = ipToInt(ip);
    return CDN_RANGES.some(r => ipInt >= ipToInt(r.start) && ipInt <= ipToInt(r.end));
  } catch {
    return false;
  }
}

// Full RFC 1918 + loopback private IP detection
function isPrivateIP(ip) {
  if (typeof ip !== 'string') return false;
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('127.')) return true;
  if (ip.startsWith('192.168.')) return true;
  if (ip.startsWith('172.')) {
    const second = parseInt(ip.split('.')[1], 10);
    return second >= 16 && second <= 31;
  }
  return false;
}

// Classification: specific cases first, general last
function classify(isp, pub, doh) {
  // TIMEOUT — ISP is unresponsive, others work
  if (isp === 'TIMEOUT' && (pub !== 'TIMEOUT' || doh !== 'TIMEOUT')) {
    return { status: 'blocked', method: 'timeout' };
  }

  // NXDOMAIN — ISP says domain doesn't exist, DoH/public say it does
  if (
    (isp === 'ENOTFOUND' || isp === 'NO_ANSWER') &&
    (pub !== 'ENOTFOUND' || doh !== 'ENOTFOUND')
  ) {
    return { status: 'blocked', method: 'nxdomain' };
  }

  // HIJACKING — ISP returns a private/local IP (traffic interception)
  if (isPrivateIP(isp)) {
    return { status: 'blocked', method: 'hijacking' };
  }

  // CDN VARIANCE — IPs differ but all are known CDN nodes (normal load balancing)
  if (isp !== 'ERROR' && isp !== 'TIMEOUT') {
    const ispIsCDN = isKnownCDN(isp);
    const pubIsCDN = isKnownCDN(pub);
    const dohIsCDN = isKnownCDN(doh);

    if (ispIsCDN && pubIsCDN && dohIsCDN) {
      return { status: 'accessible', method: 'cdn-variance' };
    }
    if ((ispIsCDN || pubIsCDN || dohIsCDN) && isp !== pub) {
      return { status: 'suspicious', method: 'cdn-variance' };
    }
  }

  // POISONING — DoH and public agree, ISP differs (corrupted response)
  if (pub === doh && isp !== pub && isp !== 'ERROR' && isp !== 'TIMEOUT') {
    return { status: 'blocked', method: 'poisoning' };
  }

  // ACCESSIBLE — all three resolvers agree
  if (isp === pub && pub === doh) {
    return { status: 'accessible', method: 'none' };
  }

  // SUSPICIOUS — resolvers disagree but no clear pattern
  return { status: 'suspicious', method: 'inconclusive' };
}

// Differentiated, actionable recommendations
function getRecommendation(method) {
  switch (method) {
    case 'poisoning':
      return 'Your ISP is returning a false IP. Switch to a trusted public DNS: set your DNS to 1.1.1.1 (Cloudflare) or 8.8.8.8 (Google) in your network settings.';
    case 'hijacking':
      return 'Your ISP is intercepting DNS queries and redirecting to a local IP. Use DNS over HTTPS (DoH) — enable it in your browser settings or use a DoH-capable resolver like 1.1.1.1 with HTTPS.';
    case 'nxdomain':
      return 'Your ISP is falsely reporting this domain as non-existent. Switch your DNS resolver to 1.1.1.1 or 8.8.8.8, or enable DNS over HTTPS in your browser.';
    case 'timeout':
      return 'Your ISP is blocking DNS queries to this domain. Use encrypted DNS (DoH or DoT) — enable DNS over HTTPS in Firefox/Chrome settings or configure 1.1.1.1 with HTTPS.';
    case 'cdn-variance':
      return 'Resolvers returned different IPs, but both are from known CDN providers (e.g. Cloudflare, Google, Fastly). This is normal load balancing behaviour — the domain is accessible.';
    case 'inconclusive':
      return 'DNS responses are inconsistent. Try manually setting your DNS to 1.1.1.1 and retest. If the issue persists, use DNS over HTTPS.';
    default:
      return 'No action needed. Domain is accessible and DNS is consistent.';
  }
}

module.exports = { classify, getRecommendation, isPrivateIP, isKnownCDN };