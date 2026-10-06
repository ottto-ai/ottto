#!/usr/bin/env python3
"""Synthetic git/engine regressions; never calls a live reviewer or provider."""
import argparse
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('autoreview').resolve()
loader = importlib.machinery.SourceFileLoader('autoreview', str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
review = importlib.util.module_from_spec(spec)
loader.exec_module(review)


def report(incorrect=False, finding=False):
    return {'findings': ([{'title': 'Durable write omitted', 'body': 'Crash loses the acknowledgement.',
                          'priority': 'P1', 'confidence': 0.9, 'category': 'bug',
                          'code_location': {'file_path': 'source.rs', 'line': 1}}] if finding else []),
            'overall_correctness': 'patch is incorrect' if incorrect else 'patch is correct',
            'overall_explanation': 'Synthetic review.', 'overall_confidence': 0.9}


class AutoReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.email', 'review@example.invalid')
        self.git('config', 'user.name', 'Synthetic Reviewer')
        (self.repo / 'source.rs').write_text('fn count() -> u32 { 1 }\n')
        self.git('add', 'source.rs')
        self.git('commit', '-qm', 'baseline')
        self.base = self.git('rev-parse', 'HEAD').strip()
        self.git('update-ref', 'refs/remotes/origin/main', self.base)
        self.git('checkout', '-qb', 'feature')
        (self.repo / 'source.rs').write_text('fn count() -> u32 { 2 }\n')
        self.git('commit', '-qam', 'change')
        self.engine = self.root / 'fake-codex'
        self.engine.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
text = sys.stdin.read()
pathlib.Path(os.environ['REVIEW_CAPTURE']).write_text(json.dumps({'argv': sys.argv, 'prompt': text}))
mode = os.environ.get('REVIEW_MODE', 'clean')
if mode == 'unavailable':
    sys.exit(9)
report = {'findings': [], 'overall_correctness': 'patch is correct',
          'overall_explanation': 'Synthetic review.', 'overall_confidence': 0.9}
if mode == 'incorrect':
    report['overall_correctness'] = 'patch is incorrect'
if mode == 'bad-verdict-type':
    report['overall_correctness'] = []
if mode == 'finding':
    report['overall_correctness'] = 'patch is incorrect'
    report['findings'] = [{'title': 'Crash loses state', 'body': 'Durable write missing.',
                          'priority': 'P1', 'confidence': 0.9, 'category': 'bug',
                          'code_location': {'file_path': 'source.rs', 'line': 1}}]
if mode == 'mutate':
    pathlib.Path('source.rs').write_text('fn unexpected_edit() {}')
if mode == 'bad-priority-type':
    report['findings'] = [{'title': 'Synthetic', 'body': 'Synthetic finding.',
                          'priority': [], 'confidence': 0.9, 'category': 'bug',
                          'code_location': {'file_path': 'source.rs', 'line': 1}}]
if mode == 'bad-category-type':
    report['findings'] = [{'title': 'Synthetic', 'body': 'Synthetic finding.',
                          'priority': 'P1', 'confidence': 0.9, 'category': {},
                          'code_location': {'file_path': 'source.rs', 'line': 1}}]
if '--output-last-message' in sys.argv:
    output = sys.argv[sys.argv.index('--output-last-message') + 1]
    pathlib.Path(output).write_text('broken' if mode == 'malformed' else json.dumps(report))
else:
    print(json.dumps({'structured_output': report}))
''')
        self.engine.chmod(0o755)
        self.capture = self.root / 'capture.json'

    def git(self, *args, cwd=None):
        return subprocess.check_output(['git', '-C', str(cwd or self.repo), *args], text=True)

    def args(self, **overrides):
        values = dict(mode='branch', head='HEAD', base=None, path=[])
        values.update(overrides)
        return argparse.Namespace(**values)

    def cli(self, *args, mode='clean', cwd=None):
        env = dict(os.environ, REVIEW_CAPTURE=str(self.capture), REVIEW_MODE=mode,
                   PYTHONDONTWRITEBYTECODE='1')
        return subprocess.run([str(SCRIPT), '--change-id', 'pr-123', '--codex-bin', str(self.engine),
                               '--claude-bin', str(self.engine), *args], cwd=cwd or self.repo,
                              env=env, capture_output=True, text=True)

    def state(self):
        return json.loads((self.repo / '.git/ottto-autoreview/runs.json').read_text())

    def test_local_scope_and_selected_new_file(self):
        (self.repo / '.idea').mkdir()
        (self.repo / '.idea/private.txt').write_text('UNRELATED_PRIVATE')
        (self.repo / 'new.rs').write_text('fn new() {}\n')
        (self.repo / 'unrelated.rs').write_text('UNRELATED_SOURCE')
        change = review.bundle(self.repo, self.args(mode='local', path=['new.rs']))
        self.assertEqual(change['paths'], ['new.rs'])
        self.assertIn('fn new()', change['patch'])
        self.assertNotIn('UNRELATED', change['patch'])
        with self.assertRaises(review.ReviewError):
            review.bundle(self.repo, self.args(mode='local'))

    def test_local_literal_paths_and_escape(self):
        (self.repo / 'a*.rs').write_text('fn selected() {}')
        (self.repo / 'another.rs').write_text('NOT_SELECTED')
        change = review.bundle(self.repo, self.args(mode='local', path=['a*.rs']))
        self.assertEqual(change['paths'], ['a*.rs'])
        self.assertNotIn('NOT_SELECTED', change['patch'])
        (self.repo / 'escape.rs').symlink_to(self.engine)
        for path in ['../escape.rs', 'escape.rs', '.idea', 'auth.json']:
            with self.assertRaises(review.ReviewError):
                review.selected_paths(self.repo, [path])

    def test_synthetic_jsonl_fixtures_are_source_but_live_transcripts_are_not(self):
        for rel in ['connectors/sources/codex/fixtures/local_sessions/minimal-session.jsonl',
                    'fixtures/snapshot-audit/pi-session.jsonl']:
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{"synthetic":true}\n')
            change = review.bundle(self.repo, self.args(mode='local', path=[rel]))
            self.assertEqual(change['paths'], [rel])
            self.assertIn('synthetic', change['patch'])
        for rel in ['sessions/live.jsonl', '.codex/sessions/live.jsonl',
                    'connectors/sources/codex/local_sessions/live.jsonl']:
            self.assertFalse(review.source_path(rel))

    def test_main_sha_and_release_endpoint_comparison(self):
        change = review.bundle(self.repo, self.args())
        self.assertEqual(change['base'], self.base)
        head = self.git('rev-parse', 'HEAD').strip()
        self.git('checkout', '-qb', 'previous-release', self.base)
        (self.repo / 'released.rs').write_text('fn released() {}')
        self.git('add', 'released.rs')
        self.git('commit', '-qm', 'previous release diverged')
        previous = self.git('rev-parse', 'HEAD').strip()
        self.git('checkout', '-q', 'feature')
        release = review.bundle(self.repo, self.args(mode='release', base=previous, head=head))
        self.assertEqual(release['base'], previous)
        self.assertIn('released.rs', release['paths'])
        self.assertIn('deleted file', release['patch'])
        (self.repo / 'dirty.rs').write_text('dirty')
        with self.assertRaises(review.ReviewError):
            review.bundle(self.repo, self.args(mode='release', base=previous, head=head))

    def test_validation_never_downgrades(self):
        review.validate(report(), ['source.rs'])
        review.validate(report(True, True), ['source.rs'])
        for candidate in [report(True), {'findings': []}, report(True, True)]:
            paths = [] if candidate.get('findings') else ['source.rs']
            with self.assertRaises(review.ReviewError):
                review.validate(candidate, paths)
        bad = report(True, True)
        bad['findings'][0]['code_location']['line'] = True
        with self.assertRaises(review.ReviewError):
            review.validate(bad, ['source.rs'])

    def test_dirty_or_wrong_head_cannot_supply_branch_context(self):
        with self.assertRaises(review.ReviewError):
            review.bundle(self.repo, self.args(head=self.base))
        (self.repo / 'source.rs').write_text('fn pending() {}')
        with self.assertRaises(review.ReviewError):
            review.bundle(self.repo, self.args())

    def test_source_mutation_during_review_is_invalid(self):
        result = self.cli(mode='mutate')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.state()['runs'][-1]['outcome'], 'invalid')
        self.assertEqual(self.state()['cache'], {})

    def test_invalid_unavailable_and_findings_never_cache(self):
        for mode, outcome, code in [('incorrect', 'invalid', 2), ('malformed', 'invalid', 2),
                                    ('unavailable', 'unavailable', 2), ('finding', 'findings', 1),
                                    ('bad-verdict-type', 'invalid', 2), ('bad-priority-type', 'invalid', 2),
                                    ('bad-category-type', 'invalid', 2)]:
            with self.subTest(mode=mode):
                result = self.cli('--allow-budget-exceed', '--reason', 'synthetic regression', mode=mode)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(self.state()['runs'][-1]['outcome'], outcome)
                self.assertEqual(self.state()['cache'], {})

    def test_model_effort_and_focused_context_reach_engine(self):
        result = self.cli('--model', 'test-model', '--profile', 'focused', '--sensitive-fix',
                          '--accepted-finding', 'Persist before ACK')
        self.assertEqual(result.returncode, 0, result.stderr)
        captured = json.loads(self.capture.read_text())
        self.assertIn('test-model', captured['argv'])
        self.assertIn('--ignore-user-config', captured['argv'])
        self.assertIn('model_reasoning_effort="high"', captured['argv'])
        self.assertIn('Persist before ACK', captured['prompt'])
        self.assertIn('direct regressions', captured['prompt'])
        self.assertIsNone(self.state()['runs'][-1]['resolved_model'])

    def test_claude_requires_model_and_restricts_tools(self):
        result = self.cli('--engine', 'claude')
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.capture.exists())
        result = self.cli('--engine', 'claude', '--model', 'configured-claude')
        self.assertEqual(result.returncode, 0, result.stderr)
        captured = json.loads(self.capture.read_text())
        self.assertIn('configured-claude', captured['argv'])
        self.assertIn('Read,Glob,Grep', captured['argv'])
        self.assertIn('--restricted', captured['argv'])
        self.assertIn('--safe-mode', captured['argv'])
        self.assertEqual(captured['argv'][captured['argv'].index('--tools') + 1], 'Read,Glob,Grep')
        self.assertIn('--strict-mcp-config', captured['argv'])
        self.assertEqual(captured['argv'][captured['argv'].index('--permission-mode') + 1], 'dontAsk')

    def test_cache_invalidates_but_budget_survives_new_files_and_modes(self):
        first = self.cli()
        self.assertEqual(first.returncode, 0, first.stderr)
        cached = self.cli()
        self.assertEqual(cached.returncode, 0, cached.stderr)
        self.assertIn('exact-change cache', cached.stdout)
        posture = self.cli('--effort', 'high')
        self.assertEqual(posture.returncode, 2)
        self.assertIn('budget exhausted', posture.stderr)
        (self.repo / 'new.rs').write_text('fn new() {}')
        changed = self.cli('--mode', 'local', '--path', 'new.rs')
        self.assertEqual(changed.returncode, 2)
        self.assertIn('budget exhausted', changed.stderr)
        override = self.cli('--mode', 'local', '--path', 'new.rs', '--allow-budget-exceed',
                            '--reason', 'new trust boundary')
        self.assertEqual(override.returncode, 0, override.stderr)
        self.assertNotIn('exact-change cache', override.stdout)
        self.assertEqual(self.state()['runs'][-1]['budget_exception_reason'], 'new trust boundary')

    def test_budget_survives_worktree_move_and_rebase(self):
        first = self.cli()
        self.assertEqual(first.returncode, 0, first.stderr)
        worktree = self.root / 'worktree'
        self.git('worktree', 'add', '-q', '-b', 'other-worktree', str(worktree), 'feature')
        (worktree / 'extra.rs').write_text('fn extra() {}')
        self.git('add', 'extra.rs', cwd=worktree)
        self.git('commit', '-qm', 'new revision', cwd=worktree)
        moved = self.root / 'moved-worktree'
        self.git('worktree', 'move', str(worktree), str(moved))
        result = self.cli(cwd=moved)
        self.assertEqual(result.returncode, 2)
        self.assertIn('budget exhausted', result.stderr)
        # Amend changes content/endpoints like a rebase; same change budget remains.
        (moved / 'extra.rs').write_text('fn extra() { let _x = 1; }')
        self.git('commit', '-qam', 'amended revision', cwd=moved)
        self.assertEqual(self.cli(cwd=moved).returncode, 2)

    def test_decide_skip_and_focused_requirements(self):
        result = self.cli('--decide')
        self.assertEqual(result.returncode, 0)
        self.assertFalse(self.capture.exists())
        result = self.cli('--skip-reason', 'mechanical extraction')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.state()['runs'][-1]['outcome'], 'skipped')
        self.assertEqual(self.state()['cache'], {})
        result = self.cli('--profile', 'focused')
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.capture.exists())


if __name__ == '__main__':
    unittest.main()
