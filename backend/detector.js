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

function classify(isp, pub, doh) {
  
  if (isp === 'TIMEOUT' && (pub !== 'TIMEOUT' || doh !== 'TIMEOUT')) {
    return { status: 'blocked', method: 'timeout' };
  }

  if (
    (isp === 'ENOTFOUND' || isp === 'NO_ANSWER') &&
    (pub !== 'ENOTFOUND' || doh !== 'ENOTFOUND')
  ) {
    return { status: 'blocked', method: 'nxdomain' };
  }

  if (isPrivateIP(isp)) {
    return { status: 'blocked', method: 'hijacking' };
  }

  if (pub === doh && isp !== pub && isp !== 'ERROR' && isp !== 'TIMEOUT') {
    return { status: 'blocked', method: 'poisoning' };
  }

  if (isp === pub && pub === doh) {
    return { status: 'accessible', method: 'none' };
  }

  return { status: 'suspicious', method: 'inconclusive' };
}

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
    case 'inconclusive':
      return 'DNS responses are inconsistent. Try manually setting your DNS to 1.1.1.1 and retest. If the issue persists, use DNS over HTTPS.';
    default:
      return 'No action needed. Domain is accessible and DNS is consistent.';
  }
}

module.exports = { classify, getRecommendation, isPrivateIP };
