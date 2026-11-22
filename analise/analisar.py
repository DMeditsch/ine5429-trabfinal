"""Audit and summarize the full IoT campaigns without modifying their source CSVs.

Run with: .venv/bin/python analise/analisar.py
Only Python's standard library is required. No simulations are launched.
"""
import csv
import hashlib
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'analise' / 'dados'
CONFIGS = ['C0', 'C1', 'C2-16', 'C2-64', 'C2-256']
KEYS = {
    'continuous': ['config', 'run'],
    'emitter_restart': ['config', 'run', 'restart_after'],
    'directed': ['config', 'run', 'point', 'occurrence'],
    'receiver_restart': ['config', 'run', 'failure', 'history', 'restart_after'],
}
TEXT = {'config', 'point', 'failure', 'history'}
METRICS = ['encryptions', 'nonce_reuse', 'generated', 'accepted_distinct',
           'duplicate_acceptances', 'emitter_transactions', 'receiver_transactions',
           'discarded_sequences', 'prep_median_us', 'prep_p95_us', 'lost_total']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def directed_cases(config):
    if config == 'C0':
        return [('F3', 1), ('F3', 2)]
    if config == 'C1':
        return [(p, n) for p in ['F1', 'F2', 'F3'] for n in [1, 2]]
    b = int(config.split('-')[1])
    return [('F1', 1), ('F1', 2), ('F2', 1), ('F2', 2),
            ('F3', 1), ('F3', b), ('F3', b + 1)]


def expected(name):
    rows = []
    for i in range(10):
        if name == 'receiver_restart':
            for mode, hist in [('receiver', 'volatile'), ('receiver', 'persistent'),
                               ('both', 'volatile'), ('both', 'persistent'),
                               ('F4', 'persistent'), ('F5', 'persistent')]:
                for k in [250, 500, 750]:
                    rows.append(('C1', i, mode, hist, k))
        else:
            for config in CONFIGS:
                if name == 'continuous':
                    rows.append((config, i))
                elif name == 'emitter_restart':
                    rows.extend((config, i, k) for k in [250, 500, 750])
                else:
                    rows.extend((config, i, p, n) for p, n in directed_cases(config))
    return set(rows)


def read(name):
    path = ROOT / 'results' / f'{name}.csv'
    with path.open(newline='') as f:
        rows = []
        for raw in csv.DictReader(f):
            row = {k: (v if k in TEXT else v == 'True' if k == 'crashed'
                       else json.loads(v) if v else None) for k, v in raw.items()}
            row['campaign'] = name
            row['lost_total'] = sum(row['lost_samples'].values())
            caveats = []
            if row.get('point') == 'F2':
                caveats.append('emitter_transactions_omits_one_commit')
                if row['occurrence'] == 1:
                    caveats.append('discarded_sequences_omits_first_unused_block')
            if row.get('failure') == 'F5':
                caveats.append('accepted_event_is_delivery_not_durable_acceptance')
                caveats.append('receiver_transactions_omits_one_commit')
            row['measurement_caveats'] = ';'.join(caveats)
            rows.append(row)
    ids = [tuple(r[k] for k in KEYS[name]) for r in rows]
    require(len(ids) == len(set(ids)), f'{name}: duplicate scenario')
    require(set(ids) == expected(name), f'{name}: missing or unexpected scenario')
    for r in rows:
        require(r['generated'] == r['encryptions'], f'{name}: inconsistent generated count')
        require(r['accepted_distinct'] + r['lost_total'] == r['generated'],
                f'{name}: inconsistent delivery/loss count')
        require(len(r['recovery_s']) == (0 if name == 'continuous' else 1),
                f'{name}: unexpected number of restarts')
        require(all(t is None or 0 <= t <= 10 for t in r['recovery_s']),
                f'{name}: invalid recovery interval')
        if name in ('emitter_restart', 'directed'):
            require(r['crashed'], f'{name}: fault not exercised')
        if name == 'directed':
            b = int(r['config'].split('-')[1]) if r['config'].startswith('C2') else 1
            n = r['occurrence']
            total = min(1000, (n if r['point'] == 'F3' else (n - 1) * b + 1) + 30)
        else:
            total = 1000
        require(r['generated'] == total, f'{name}: incorrect sample count')
        if name == 'receiver_restart':
            require(r['replays_sent'] == r['replays_reached'] == 20,
                    'Replay reachability differs from the documented full dataset')
    return rows


def stats(values):
    return dict(zip(['median', 'min', 'max'],
                    [statistics.median(values), min(values), max(values)])) if values else {
                        'median': None, 'min': None, 'max': None}


def write_csv(name, rows):
    fields = list(dict.fromkeys(k for r in rows for k in r))
    with (OUT / name).open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict))
                             else v for k, v in row.items()})


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    params = json.loads((ROOT / 'results' / 'parameters.json').read_text())
    require(params == {'samples': 1000, 'rate': 10}, 'Not the full-specification dataset')
    data = {name: read(name) for name in KEYS}
    all_rows = [r for rows in data.values() for r in rows]
    audit = {'parameters': params, 'scenario_coverage': {}, 'input_sha256': {},
             'source_sha256_at_analysis': {}, 'backup_matches': {}}
    summaries = []
    for name, rows in data.items():
        audit['input_sha256'][f'results/{name}.csv'] = fingerprint(ROOT / 'results' / f'{name}.csv')
        audit['scenario_coverage'][name] = {
            'rows': len(rows), 'groups': len(rows) // 10,
            'encryptions': sum(r['encryptions'] for r in rows),
            'nonce_reuse': sum(r['nonce_reuse'] for r in rows),
            'accepted_distinct_sum': sum(r['accepted_distinct'] for r in rows),
            'lost_total': sum(r['lost_total'] for r in rows),
            'duplicate_acceptances': sum(r['duplicate_acceptances'] for r in rows),
            'recoveries_within_10s': sum(t is not None for r in rows for t in r['recovery_s']),
            'recoveries_unavailable_within_10s': sum(t is None for r in rows for t in r['recovery_s']),
            'rows_with_measurement_caveats': sum(bool(r['measurement_caveats']) for r in rows),
        }
        group_keys = [k for k in KEYS[name] if k != 'run']
        groups = defaultdict(list)
        for r in rows:
            groups[tuple(r[k] for k in group_keys)].append(r)
        for group, rs in groups.items():
            require(len(rs) == 10, f'{name}: group without ten repetitions')
            summary = {'campaign': name, **dict(zip(group_keys, group)), 'n': len(rs)}
            for field in METRICS:
                summary.update({f'{field}_{key}': value
                                for key, value in stats([r[field] for r in rs]).items()})
            rec = [t for r in rs for t in r['recovery_s']]
            summary['recovery_observations'] = len(rec)
            summary['recovered_within_10s'] = sum(t is not None for t in rec)
            summary['not_recovered_within_10s'] = sum(t is None for t in rec)
            summary.update({f'recovery_s_{k}': v for k, v in stats([t for t in rec if t is not None]).items()})
            for field in ['rejections', 'lost_samples']:
                counts = Counter()
                for r in rs:
                    counts.update(r[field])
                summary[field + '_sum'] = dict(counts)
            summary['measurement_caveats'] = rs[0]['measurement_caveats']
            summaries.append(summary)
    replay = []
    groups = defaultdict(list)
    for r in data['receiver_restart']:
        groups[(r['failure'], r['history'])].append(r)
    for (mode, hist), rs in groups.items():
        row = {'failure': mode, 'history': hist, 'n': len(rs)}
        for field in ['replays_sent', 'replays_reached', 'replays_accepted']:
            row[field] = sum(r[field] for r in rs)
        row['accepted_over_reached'] = row['replays_accepted'] / row['replays_reached']
        row['lost_total'] = sum(r['lost_total'] for r in rs)
        row.update({f'recovery_s_{k}': v for k, v in stats(
            [t for r in rs for t in r['recovery_s'] if t is not None]).items()})
        replay.append(row)
    for p in sorted((ROOT / 'iot').glob('*.py')):
        audit['source_sha256_at_analysis'][str(p.relative_to(ROOT))] = fingerprint(p)
    audit['input_sha256']['results/parameters.json'] = fingerprint(ROOT / 'results' / 'parameters.json')
    audit['input_sha256']['results/resume.log'] = fingerprint(ROOT / 'results' / 'resume.log')
    for backup in sorted((ROOT / 'results').glob('backup-before-resume-*')):
        for name, digest in json.loads((backup / 'sha256.json').read_text()).items():
            same = fingerprint(ROOT / 'results' / name) == digest
            require(same, f'Preserved CSV changed: {name}')
            audit['backup_matches'][str((backup / name).relative_to(ROOT))] = same
    protected = [r for r in all_rows if r['config'] != 'C0']
    audit['totals'] = {
        'rows': len(all_rows), 'encryptions': sum(r['encryptions'] for r in all_rows),
        'protected_rows': len(protected),
        'protected_encryptions': sum(r['encryptions'] for r in protected),
        'protected_nonce_reuse': sum(r['nonce_reuse'] for r in protected),
    }
    audit['integrity_log_passed'] = 'integrity: 13/13 checks passed' in (ROOT / 'results' / 'resume.log').read_text()
    OUT.mkdir(exist_ok=True)
    write_csv('execucoes.csv', all_rows)
    write_csv('resumo_cenarios.csv', summaries)
    write_csv('resumo_replay.csv', replay)
    (OUT / 'auditoria.json').write_text(json.dumps(audit, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps(audit['totals'], indent=2))
    print(f'Validated {len(summaries)} scenario groups with ten repetitions each; outputs: {OUT}')


if __name__ == '__main__':
    main()
