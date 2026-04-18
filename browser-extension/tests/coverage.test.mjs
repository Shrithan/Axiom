import test from 'node:test';
import assert from 'node:assert/strict';
import {siteCoverage} from '../src/coverage.js';
test('Gmail describes block-all drops without claiming selective attachment protection',()=>{const coverage=siteCoverage('https://mail.google.com');assert.equal(coverage.mode,'gmail-drop-guard');assert.match(coverage.message,/ALL file/);assert.match(coverage.message,/not protected/);assert.match(coverage.message,/paperclip/);});
test('ordinary sites describe only the standard form gate',()=>{const coverage=siteCoverage('https://example.com');assert.equal(coverage.mode,'multipart');assert.match(coverage.message,/multipart/);assert.match(coverage.message,/not protected/);});
