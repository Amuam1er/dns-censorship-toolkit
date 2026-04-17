/*
 * DNS Censorship Detection & Circumvention System
 * Copyright (C) 2026 [Your Full Name] — ICT University
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see https://www.gnu.org/licenses/
 */

const dnsModule = require('dns');
const dnsPromises = require('dns').promises;
const axios = require('axios');

function withTimeout(promise, ms = 1000) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('TIMEOUT')), ms)
    )
  ]);
}

function getSystemResolvers() {
  return dnsModule.getServers();
}

async function resolveWithISP(domain) {
  try {
    const resolver = new dnsPromises.Resolver();
    const servers = getSystemResolvers();
    resolver.setServers(servers);
    const result = await withTimeout(resolver.resolve4(domain));
    return result[0];
  } catch (err) {
    if (err.message === 'TIMEOUT') return 'TIMEOUT';
    return err.code || 'ERROR';
  }
}

async function resolveCustom(resolverIP, domain) {
  try {
    const resolver = new dnsPromises.Resolver();
    resolver.setServers([resolverIP]);
    const result = await withTimeout(resolver.resolve4(domain));
    return result[0];
  } catch (err) {
    if (err.message === 'TIMEOUT') return 'TIMEOUT';
    return err.code || 'ERROR';
  }
}

async function resolveWithPublic(domain) {
  try {
    const resolver = new dnsPromises.Resolver();
    resolver.setServers(['1.1.1.1']);
    const result = await withTimeout(resolver.resolve4(domain));
    return result[0];
  } catch (err) {
    if (err.message === 'TIMEOUT') return 'TIMEOUT';
    return err.code || 'ERROR';
  }
}

async function resolveWithDoH(domain) {
  try {
    const response = await withTimeout(
      axios.get('https://cloudflare-dns.com/dns-query', {
        headers: { accept: 'application/dns-json' },
        params: { name: domain, type: 'A' },
        timeout: 1000
      })
    );
    if (response.data && response.data.Answer && response.data.Answer.length > 0) {
      return response.data.Answer[0].data;
    }
    return 'NO_ANSWER';
  } catch (err) {
    if (err.message === 'TIMEOUT') return 'TIMEOUT';
    return err.message || 'ERROR';
  }
}

module.exports = {
  resolveWithISP,
  resolveWithPublic,
  resolveWithDoH,
  resolveCustom,
  getSystemResolvers
};
