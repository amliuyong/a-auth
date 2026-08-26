#!/usr/bin/env node

const fs = require('node:fs');

const [reportPath, selector] = process.argv.slice(2);
if (!reportPath || !selector) {
  throw new Error('usage: validate_node_exact_report.cjs <report> <selector>');
}

const report = fs.readFileSync(reportPath, 'utf8');
const count = (name) => {
  const match = report.match(new RegExp(`^# ${name} (\\d+)$`, 'm'));
  return match ? Number(match[1]) : -1;
};
const escapeRegExp = (value) =>
  value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const escapedSelector = escapeRegExp(selector);
const exactSubtest = new RegExp(
  `^# Subtest: ${escapedSelector}$`,
  'm',
).test(report);
const exactPass = new RegExp(
  `^ok \\d+ - ${escapedSelector}$`,
  'm',
).test(report);

if (
  count('tests') !== 1 ||
  count('pass') !== 1 ||
  count('fail') !== 0 ||
  count('skipped') !== 0 ||
  !exactSubtest ||
  !exactPass
) {
  throw new Error(
    `exact Node selector ${selector} executed unexpectedly: ` +
      `tests=${count('tests')}, pass=${count('pass')}, ` +
      `fail=${count('fail')}, skipped=${count('skipped')}, ` +
      `exactSubtest=${exactSubtest}, exactPass=${exactPass}`,
  );
}
