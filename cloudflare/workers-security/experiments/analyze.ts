#!/usr/bin/env node

/**
 * Profile Analyzer
 * Analyzes attack profiles to understand WAF behavior and expected outcomes
 */

import { ALL_PROFILES, type AttackProfile } from './profiles/index.js';

// Dynamic import to handle module system differences
let WAF_RULES: any[] = [];

interface WAFMatchAnalysis {
  ruleId: string;
  description: string;
  category: string;
  severity: string;
  action: string;
  matchedRequests: Array<{
    requestIndex: number;
    path: string;
    method: string;
    matchedCondition: {
      field: string;
      operator: string;
      value: string;
    };
    actualValue: string;
  }>;
}

interface ProfileAnalysis {
  profileName: string;
  totalRequests: number;
  wafAnalysis: {
    wouldBlockCount: number;
    wouldChallengeCount: number;
    wouldAllowCount: number;
  blockRate: number;
    matchingRules: WAFMatchAnalysis[];
  };
  requestBreakdown: Array<{
    index: number;
    method: string;
    path: string;
    userAgent?: string;
    hasBody: boolean;
    wafResult: 'block' | 'challenge' | 'allow';
    matchingRules: string[];
    whyNotBlocked?: string[];
  }>;
}

/**
 * Simulate evaluating a condition against request data
 */
function evaluateCondition(
  condition: { field: string; operator: string; value: string },
  path: string,
  userAgent: string,
  query: string
): { matched: boolean; actualValue: string } {
  let fieldValue = '';

  switch (condition.field) {
    case 'path':
      fieldValue = path;
      break;
    case 'query':
      fieldValue = query;
      break;
    case 'user-agent':
      fieldValue = userAgent;
      break;
    case 'host':
      fieldValue = 'localhost'; // Simulate
      break;
    default:
      return { matched: false, actualValue: 'unknown field' };
  }

  const lowerField = fieldValue.toLowerCase();
  const lowerValue = condition.value.toLowerCase();
  let matched = false;

  switch (condition.operator) {
    case 'equals':
      matched = lowerField === lowerValue;
      break;
    case 'contains':
      matched = lowerField.includes(lowerValue);
      break;
    case 'starts-with':
      matched = lowerField.startsWith(lowerValue);
      break;
    case 'ends-with':
      matched = lowerField.endsWith(lowerValue);
      break;
    case 'regex':
      try {
        matched = new RegExp(lowerValue).test(lowerField);
      } catch {
        matched = false;
      }
      break;
  }

  return { matched, actualValue: fieldValue };
}

/**
 * Analyze a profile against WAF rules
 */
function analyzeProfile(profile: AttackProfile): ProfileAnalysis {
  const matchingRules: Map<string, WAFMatchAnalysis> = new Map();
  const requestBreakdown: ProfileAnalysis['requestBreakdown'] = [];

  profile.requests.forEach((request, index) => {
    const url = new URL(request.path, 'http://localhost');
    const path = url.pathname;
    const query = url.search;
    const userAgent = request.headers?.['User-Agent'] || 'Mozilla/5.0';

    let wafResult: 'block' | 'challenge' | 'allow' = 'allow';
    const requestMatchingRules: string[] = [];
    const whyNotBlocked: string[] = [];

    // Check each WAF rule
    for (const rule of WAF_RULES) {
      if (!rule.enabled) continue;

      for (const condition of rule.conditions) {
        const { matched, actualValue } = evaluateCondition(
          condition,
          path,
          userAgent,
          query
        );

        if (matched) {
          requestMatchingRules.push(rule.id);

          if (rule.action === 'block') {
            wafResult = 'block';
          } else if (rule.action === 'challenge' && wafResult !== 'block') {
            wafResult = 'challenge';
          }

          // Add to matching rules
          if (!matchingRules.has(rule.id)) {
            matchingRules.set(rule.id, {
              ruleId: rule.id,
              description: rule.description,
              category: rule.category,
              severity: rule.severity,
              action: rule.action,
              matchedRequests: [],
            });
          }

          matchingRules.get(rule.id)!.matchedRequests.push({
            requestIndex: index,
            path: request.path,
            method: request.method,
            matchedCondition: condition,
            actualValue,
          });

          break; // One condition match is enough for this rule
        }
      }
    }

    // If not blocked, analyze why
    if (wafResult === 'allow') {
      // Check what the request is missing to trigger blocks
      const potentialMatches: string[] = [];

      // Check SQL injection rules
      if (!query.toLowerCase().includes('union') &&
          !query.toLowerCase().includes("' or") &&
          !query.toLowerCase().includes('drop table') &&
          !query.toLowerCase().includes('--')) {
        potentialMatches.push('No SQL injection patterns in query string');
    }
    
      // Check XSS rules
      if (!query.toLowerCase().includes('<script') &&
          !query.toLowerCase().includes('onerror=') &&
          !query.toLowerCase().includes('javascript:')) {
        potentialMatches.push('No XSS patterns in query string');
      }

      // Check path traversal
      if (!path.includes('../') && !path.includes('..\\')) {
        potentialMatches.push('No path traversal patterns in path');
      }

      // Check admin protection
      if (!path.startsWith('/admin') && !path.startsWith('/.env') && !path.startsWith('/.git')) {
        potentialMatches.push('Path does not match admin protection rules');
  }
  
      // Check bot detection
      const botPatterns = ['python-requests', 'curl', 'wget', 'postman', 'bot', 'crawler'];
      const hasBotUA = botPatterns.some(p => userAgent.toLowerCase().includes(p));
      if (!hasBotUA) {
        potentialMatches.push('User-Agent does not match bot detection patterns');
      } else {
        potentialMatches.push('User-Agent matches bot pattern but rule action is "challenge" not "block"');
      }

      whyNotBlocked.push(...potentialMatches);
}

    requestBreakdown.push({
      index,
      method: request.method,
      path: request.path,
      userAgent: request.headers?.['User-Agent'],
      hasBody: !!request.body,
      wafResult,
      matchingRules: requestMatchingRules,
      whyNotBlocked: wafResult === 'allow' ? whyNotBlocked : undefined,
    });
  });

  const blockCount = requestBreakdown.filter(r => r.wafResult === 'block').length;
  const challengeCount = requestBreakdown.filter(r => r.wafResult === 'challenge').length;
  const allowCount = requestBreakdown.filter(r => r.wafResult === 'allow').length;

  return {
    profileName: profile.name,
    totalRequests: profile.requests.length,
    wafAnalysis: {
      wouldBlockCount: blockCount,
      wouldChallengeCount: challengeCount,
      wouldAllowCount: allowCount,
      blockRate: (blockCount / profile.requests.length) * 100,
      matchingRules: Array.from(matchingRules.values()),
    },
    requestBreakdown,
  };
}

/**
 * Compare two profiles
 */
function compareProfiles(profile1Name: string, profile2Name: string): string {
  const profile1 = ALL_PROFILES[profile1Name];
  const profile2 = ALL_PROFILES[profile2Name];

  if (!profile1 || !profile2) {
    return `Error: One or both profiles not found`;
  }

  const analysis1 = analyzeProfile(profile1);
  const analysis2 = analyzeProfile(profile2);

  const lines: string[] = [
    '╔════════════════════════════════════════════════════════════════════════════════╗',
    '║                          PROFILE COMPARISON ANALYSIS                            ║',
    '╚════════════════════════════════════════════════════════════════════════════════╝',
    '',
    `Comparing: ${profile1Name} vs ${profile2Name}`,
    '',
    '┌─ Profile Overview ──────────────────────────────────────────────────────────────┐',
    `│ ${profile1Name}:`.padEnd(80) + '│',
    `│   Total Requests: ${analysis1.totalRequests}`.padEnd(80) + '│',
    `│   WAF Block Rate: ${analysis1.wafAnalysis.blockRate.toFixed(1)}%`.padEnd(80) + '│',
    `│   Would Block: ${analysis1.wafAnalysis.wouldBlockCount}, Challenge: ${analysis1.wafAnalysis.wouldChallengeCount}, Allow: ${analysis1.wafAnalysis.wouldAllowCount}`.padEnd(80) + '│',
    '│'.padEnd(80) + '│',
    `│ ${profile2Name}:`.padEnd(80) + '│',
    `│   Total Requests: ${analysis2.totalRequests}`.padEnd(80) + '│',
    `│   WAF Block Rate: ${analysis2.wafAnalysis.blockRate.toFixed(1)}%`.padEnd(80) + '│',
    `│   Would Block: ${analysis2.wafAnalysis.wouldBlockCount}, Challenge: ${analysis2.wafAnalysis.wouldChallengeCount}, Allow: ${analysis2.wafAnalysis.wouldAllowCount}`.padEnd(80) + '│',
    '└────────────────────────────────────────────────────────────────────────────────┘',
    '',
  ];

  // Rules that match in profile 2 but not profile 1
  const rules1 = new Set(analysis1.wafAnalysis.matchingRules.map(r => r.ruleId));
  const rules2 = new Set(analysis2.wafAnalysis.matchingRules.map(r => r.ruleId));
  
  const onlyInProfile2 = analysis2.wafAnalysis.matchingRules.filter(r => !rules1.has(r.ruleId));
  
  if (onlyInProfile2.length > 0) {
    lines.push(`┌─ Rules that trigger in ${profile2Name} but NOT in ${profile1Name} ────────────────┐`);
    onlyInProfile2.forEach(rule => {
      lines.push(`│ ${rule.ruleId}: ${rule.description.slice(0, 60)}`.padEnd(80) + '│');
      lines.push(`│   Action: ${rule.action}, Category: ${rule.category}, Severity: ${rule.severity}`.padEnd(80) + '│');
      lines.push(`│   Example match: ${rule.matchedRequests[0]?.path.slice(0, 50)}`.padEnd(80) + '│');
    });
    lines.push('└────────────────────────────────────────────────────────────────────────────────┘');
    lines.push('');
  }

  // Key differences
  lines.push('┌─ KEY DIFFERENCES ────────────────────────────────────────────────────────────┐');
  
  // Request patterns
  const p1HasSQL = profile1.requests.some(r => 
    r.path.includes("'") || r.path.toLowerCase().includes('union') || r.path.toLowerCase().includes('select')
  );
  const p2HasSQL = profile2.requests.some(r => 
    r.path.includes("'") || r.path.toLowerCase().includes('union') || r.path.toLowerCase().includes('select')
  );
  
  lines.push(`│ SQL Injection patterns: ${profile1Name}=${p1HasSQL}, ${profile2Name}=${p2HasSQL}`.padEnd(80) + '│');
  
  const p1HasXSS = profile1.requests.some(r => 
    r.path.includes('<script') || r.path.includes('onerror=') || r.path.includes('javascript:')
  );
  const p2HasXSS = profile2.requests.some(r => 
    r.path.includes('<script') || r.path.includes('onerror=') || r.path.includes('javascript:')
  );
  
  lines.push(`│ XSS patterns: ${profile1Name}=${p1HasXSS}, ${profile2Name}=${p2HasXSS}`.padEnd(80) + '│');
  
  const p1HasPathTraversal = profile1.requests.some(r => r.path.includes('../'));
  const p2HasPathTraversal = profile2.requests.some(r => r.path.includes('../'));
  
  lines.push(`│ Path Traversal patterns: ${profile1Name}=${p1HasPathTraversal}, ${profile2Name}=${p2HasPathTraversal}`.padEnd(80) + '│');
  
  const p1HasAdmin = profile1.requests.some(r => r.path.startsWith('/admin') || r.path.includes('.env') || r.path.includes('.git'));
  const p2HasAdmin = profile2.requests.some(r => r.path.startsWith('/admin') || r.path.includes('.env') || r.path.includes('.git'));
  
  lines.push(`│ Admin/Sensitive path access: ${profile1Name}=${p1HasAdmin}, ${profile2Name}=${p2HasAdmin}`.padEnd(80) + '│');
  
  lines.push('└────────────────────────────────────────────────────────────────────────────────┘');
  lines.push('');

  // Explanation
  lines.push('┌─ EXPLANATION ────────────────────────────────────────────────────────────────┐');
  lines.push('│'.padEnd(80) + '│');
  
  if (analysis1.wafAnalysis.blockRate < analysis2.wafAnalysis.blockRate) {
    lines.push(`│ ${profile1Name} has a lower WAF block rate because:`.padEnd(80) + '│');
    
    if (!p1HasSQL && p2HasSQL) {
      lines.push('│   • It does NOT include SQL injection patterns in URLs'.padEnd(80) + '│');
    }
    if (!p1HasXSS && p2HasXSS) {
      lines.push('│   • It does NOT include XSS patterns in URLs'.padEnd(80) + '│');
    }
    if (!p1HasPathTraversal && p2HasPathTraversal) {
      lines.push('│   • It does NOT include path traversal patterns'.padEnd(80) + '│');
    }
    if (!p1HasAdmin && p2HasAdmin) {
      lines.push('│   • It does NOT access admin/sensitive paths'.padEnd(80) + '│');
    }

    // Check if it only has bot-detection patterns (which are "challenge" not "block")
    const p1OnlyBot = analysis1.wafAnalysis.matchingRules.every(r => r.action === 'challenge');
    if (p1OnlyBot && analysis1.wafAnalysis.matchingRules.length > 0) {
      lines.push('│   • Its only matching rules have "challenge" action (not "block")'.padEnd(80) + '│');
      lines.push('│   • Bot detection rules (python-requests, curl) trigger challenges,'.padEnd(80) + '│');
      lines.push('│     not blocks, so they appear as "allowed" in basic metrics'.padEnd(80) + '│');
    }
    
    lines.push('│'.padEnd(80) + '│');
    lines.push('│ The WAF rules are working correctly - they block MALICIOUS PATTERNS,'.padEnd(80) + '│');
    lines.push('│ not just suspicious user agents or login attempts.'.padEnd(80) + '│');
  }
  
  lines.push('│'.padEnd(80) + '│');
  lines.push('└────────────────────────────────────────────────────────────────────────────────┘');

  return lines.join('\n');
}

/**
 * Generate detailed analysis for a single profile
 */
function generateDetailedAnalysis(profileName: string): string {
  const profile = ALL_PROFILES[profileName];
  if (!profile) {
    return `Error: Profile "${profileName}" not found`;
  }

  const analysis = analyzeProfile(profile);
  const lines: string[] = [
    '╔════════════════════════════════════════════════════════════════════════════════╗',
    `║  DETAILED WAF ANALYSIS: ${profileName}`.padEnd(80) + '║',
    '╚════════════════════════════════════════════════════════════════════════════════╝',
    '',
    `Profile: ${profile.name}`,
    `Description: ${profile.description}`,
    `Type: ${profile.type}`,
    '',
    '┌─ WAF Summary ───────────────────────────────────────────────────────────────────┐',
    `│ Total Request Templates: ${analysis.totalRequests}`.padEnd(80) + '│',
    `│ Would be BLOCKED:        ${analysis.wafAnalysis.wouldBlockCount} (${analysis.wafAnalysis.blockRate.toFixed(1)}%)`.padEnd(80) + '│',
    `│ Would be CHALLENGED:     ${analysis.wafAnalysis.wouldChallengeCount}`.padEnd(80) + '│',
    `│ Would be ALLOWED:        ${analysis.wafAnalysis.wouldAllowCount}`.padEnd(80) + '│',
    '└────────────────────────────────────────────────────────────────────────────────┘',
    '',
  ];

  // Request-by-request breakdown
  lines.push('┌─ Request-by-Request Breakdown ─────────────────────────────────────────────────┐');
  
  analysis.requestBreakdown.forEach(req => {
    const statusIcon = req.wafResult === 'block' ? '🚫' : req.wafResult === 'challenge' ? '⚠️' : '✅';
    lines.push(`│ ${statusIcon} Request #${req.index + 1}: ${req.method} ${req.path.slice(0, 50)}`.padEnd(80) + '│');
    
    if (req.userAgent) {
      lines.push(`│    User-Agent: ${req.userAgent.slice(0, 55)}`.padEnd(80) + '│');
    }
    
    if (req.matchingRules.length > 0) {
      lines.push(`│    Matching Rules: ${req.matchingRules.join(', ')}`.padEnd(80) + '│');
    }
    
    if (req.whyNotBlocked && req.whyNotBlocked.length > 0) {
      lines.push('│    Why NOT blocked:'.padEnd(80) + '│');
      req.whyNotBlocked.slice(0, 3).forEach(reason => {
        lines.push(`│      - ${reason.slice(0, 65)}`.padEnd(80) + '│');
      });
    }
    
    lines.push('│'.padEnd(80) + '│');
  });
  
  lines.push('└────────────────────────────────────────────────────────────────────────────────┘');
  lines.push('');

  // Matching rules detail
  if (analysis.wafAnalysis.matchingRules.length > 0) {
    lines.push('┌─ Matching WAF Rules ────────────────────────────────────────────────────────────┐');
    
    analysis.wafAnalysis.matchingRules.forEach(rule => {
      lines.push(`│ ${rule.ruleId}: ${rule.description}`.padEnd(80) + '│');
      lines.push(`│   Category: ${rule.category} | Severity: ${rule.severity} | Action: ${rule.action}`.padEnd(80) + '│');
      lines.push(`│   Matches ${rule.matchedRequests.length} request(s)`.padEnd(80) + '│');
      lines.push('│'.padEnd(80) + '│');
    });
    
    lines.push('└────────────────────────────────────────────────────────────────────────────────┘');
  } else {
    lines.push('┌─ No WAF Rules Matched ──────────────────────────────────────────────────────────┐');
    lines.push('│ None of the requests in this profile trigger WAF blocking rules.'.padEnd(80) + '│');
    lines.push('│ This may be intentional for legitimate traffic profiles.'.padEnd(80) + '│');
    lines.push('└────────────────────────────────────────────────────────────────────────────────┘');
  }

  return lines.join('\n');
}

/**
 * Load WAF rules dynamically
 */
async function loadWAFRules(): Promise<void> {
  try {
    const module = await import('../src/rules/waf-config.js');
    WAF_RULES = module.WAF_RULES || [];
  } catch (error) {
    console.error('Warning: Could not load WAF rules from src/waf-config.js');
    console.error('Error:', error);
    console.error('Analysis will continue with empty rules array.');
    WAF_RULES = [];
  }
}

/**
 * Main CLI
 */
async function main() {
  // Load WAF rules first
  await loadWAFRules();
  
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log(`
Profile Analyzer - Understand WAF behavior for attack profiles

Usage:
  npx ts-node analyze.ts [command] [options]

Commands:
  analyze <profile>            Detailed WAF analysis for a profile
  compare <profile1> <profile2> Compare two profiles
  list                         List all profiles
  all                          Analyze all profiles

Examples:
  npx ts-node analyze.ts analyze MIXED_TRAFFIC
  npx ts-node analyze.ts compare MIXED_TRAFFIC WAF_COMPREHENSIVE_TEST
  npx ts-node analyze.ts all

This tool helps you understand:
  - Why certain profiles trigger WAF blocks and others don't
  - Which specific requests in a profile would be blocked
  - The difference between "block" and "challenge" actions
  - What patterns are needed to trigger each WAF rule
`);
    return;
  }

  const command = args[0];

  switch (command) {
    case 'analyze':
      if (!args[1]) {
        console.error('Error: Profile name required');
        console.log('Usage: analyze <profile_name>');
        process.exit(1);
      }
      console.log(generateDetailedAnalysis(args[1]));
      break;

    case 'compare':
      if (!args[1] || !args[2]) {
        console.error('Error: Two profile names required');
        console.log('Usage: compare <profile1> <profile2>');
      process.exit(1);
    }
      console.log(compareProfiles(args[1], args[2]));
      break;

    case 'list':
      console.log('\nAvailable Profiles:');
      console.log('─'.repeat(60));
      Object.entries(ALL_PROFILES).forEach(([name, profile]) => {
        const analysis = analyzeProfile(profile);
        console.log(`  ${name}`);
        console.log(`    ${profile.description}`);
        console.log(`    WAF Block Rate: ${analysis.wafAnalysis.blockRate.toFixed(1)}%`);
        console.log('');
      });
      break;

    case 'all':
      console.log('\n' + '═'.repeat(80));
      console.log('ANALYZING ALL PROFILES');
      console.log('═'.repeat(80) + '\n');

      Object.keys(ALL_PROFILES).forEach(name => {
        const analysis = analyzeProfile(ALL_PROFILES[name]);
        console.log(`${name}: Block=${analysis.wafAnalysis.wouldBlockCount}, Challenge=${analysis.wafAnalysis.wouldChallengeCount}, Allow=${analysis.wafAnalysis.wouldAllowCount} (${analysis.wafAnalysis.blockRate.toFixed(1)}% block rate)`);
      });

      console.log('\n' + '─'.repeat(80));
      console.log('\nFor detailed analysis of a specific profile: analyze.ts analyze <PROFILE_NAME>');
      console.log('For comparison: analyze.ts compare MIXED_TRAFFIC WAF_COMPREHENSIVE_TEST\n');
      break;

    default:
      console.error(`Unknown command: ${command}`);
      console.log('Use --help for usage information');
      process.exit(1);
    }
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});

export { analyzeProfile, compareProfiles, generateDetailedAnalysis };
