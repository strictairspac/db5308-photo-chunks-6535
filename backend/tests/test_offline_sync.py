"""异地底片库离线同步的领域验收测试。

运行：cd backend && python3 -m tests.test_offline_sync
"""
import copy

from src.services.domain import SPEC, solve, validate

SAMPLE = SPEC['sample']


def section(result, title):
    return next(s['rows'] for s in result['sections'] if s['title'] == title)


def test_sample_matches_expect():
    result = solve(copy.deepcopy(SAMPLE))
    assert result['metrics'] == SPEC['expect'], (
        f"样例指标不符：\n实际 {result['metrics']}\n预期 {SPEC['expect']}")


def test_deterministic():
    first = solve(copy.deepcopy(SAMPLE))
    second = solve(copy.deepcopy(SAMPLE))
    assert first == second, '同一输入重跑结果不一致'


def test_out_of_order_buffered_then_resumed():
    result = solve(copy.deepcopy(SAMPLE))
    rows = section(result, '投递验收')
    first = rows[0]
    assert first['版本'] == 'F08-01' and first['判定'] == '暂存', first
    resumed = [row for row in rows if '补齐接续' in row['判定']]
    assert [row['版本'] for row in resumed] == ['F08-01', 'L17-1121'], resumed
    assert all(row['判定'].startswith('验收') for row in resumed), resumed


def test_baseline_digest_mismatch_rejected():
    result = solve(copy.deepcopy(SAMPLE))
    rows = section(result, '投递验收')
    forged = [row for row in rows if row['注入故障'] == '伪造基准摘要']
    assert len(forged) == 1 and forged[0]['判定'] == '拒收', forged
    assert '基准编号一致但内容摘要不符' in forged[0]['说明'], forged


def test_bad_package_does_not_block_other_assets():
    result = solve(copy.deepcopy(SAMPLE))
    rows = section(result, '投递验收')
    corrupt = next(row for row in rows if row['注入故障'] == '块损坏')
    assert corrupt['判定'] == '拒收' and '块摘要与地址不符' in corrupt['说明'], corrupt
    later = rows[rows.index(corrupt):]
    assert any(row['底片'] == 'L17-frame08.dpx' and row['判定'] == '验收' for row in later), later


def test_retry_after_interruption_is_idempotent():
    result = solve(copy.deepcopy(SAMPLE))
    ledger = section(result, '接收台账')
    blocks = [row['内容块 SHA-256'] for row in ledger if row['类型'] == '块入库']
    versions = [(row['底片'], row['版本']) for row in ledger if row['类型'] == '版本验收']
    assert len(blocks) == len(set(blocks)) == 8, ledger
    assert len(versions) == len(set(versions)) == 5, ledger
    skipped = [row for row in section(result, '投递验收') if row['判定'] == '重复跳过']
    assert len(skipped) == 2, skipped


def test_old_version_restorable_until_and_after_switch():
    result = solve(copy.deepcopy(SAMPLE))
    rows = section(result, '还原查验')
    stages = {row['阶段'] for row in rows}
    assert {'切换前旧版', '切换后新版', '终态复查'} <= stages, stages
    assert all(row['判定'] == '校验通过' for row in rows), rows
    before = [row for row in rows if row['阶段'] == '切换前旧版']
    assert [row['版本'] for row in before] == ['F08-01', 'L17-1119', 'L17-1120'], before


def test_drop_block_waits_then_retry_completes():
    payload = {
        'chunk_size': 4,
        'assets': [{'asset': 'A.dpx', 'versions': [
            {'version_id': 'V1', 'encoding': 'utf8', 'content': 'LITEGRAYSCANOLD!'},
            {'version_id': 'V2', 'encoding': 'utf8', 'content': 'LITEGRAYSCANEDIT'},
        ]}],
        'deliveries': [
            {'asset': 'A.dpx', 'version_id': 'V1'},
            {'asset': 'A.dpx', 'version_id': 'V2', 'fault': 'drop_block'},
            {'asset': 'A.dpx', 'version_id': 'V2'},
        ],
    }
    result = solve(payload)
    rows = section(result, '投递验收')
    assert rows[1]['判定'] == '暂存' and '尚未到齐' in rows[1]['说明'], rows[1]
    assert rows[2]['判定'] == '验收', rows[2]
    assert result['metrics']['验收版本数'] == 2, result['metrics']
    assert result['metrics']['暂存未决包数'] == 0, result['metrics']


def test_forge_digest_rejected():
    payload = {
        'chunk_size': 4,
        'assets': [{'asset': 'A.dpx', 'versions': [
            {'version_id': 'V1', 'encoding': 'utf8', 'content': 'LITEGRAYSCANOLD!'},
            {'version_id': 'V2', 'encoding': 'utf8', 'content': 'LITEGRAYSCANEDIT'},
        ]}],
        'deliveries': [
            {'asset': 'A.dpx', 'version_id': 'V1'},
            {'asset': 'A.dpx', 'version_id': 'V2', 'fault': 'forge_digest'},
        ],
    }
    result = solve(payload)
    rows = section(result, '投递验收')
    assert rows[1]['判定'] == '拒收' and '整份底片校验失败' in rows[1]['说明'], rows[1]
    assert result['metrics']['验收版本数'] == 1, result['metrics']
    packages = section(result, '增量包目录')
    assert packages[1]['最终状态'] == '拒收待重投', packages


def test_pending_duplicate_resolved_once_accepted():
    payload = {
        'chunk_size': 4,
        'assets': [{'asset': 'A.dpx', 'versions': [
            {'version_id': 'V1', 'encoding': 'utf8', 'content': 'LITEGRAYSCANOLD!'},
            {'version_id': 'V2', 'encoding': 'utf8', 'content': 'LITEGRAYSCANEDIT'},
        ]}],
        'deliveries': [
            {'asset': 'A.dpx', 'version_id': 'V2'},
            {'asset': 'A.dpx', 'version_id': 'V2'},
            {'asset': 'A.dpx', 'version_id': 'V1'},
        ],
    }
    result = solve(payload)
    metrics = result['metrics']
    assert metrics['乱序暂存次数'] == 2, metrics
    assert metrics['补齐接续验收数'] == 1, metrics
    assert metrics['重复投递跳过数'] == 1, metrics
    assert metrics['验收版本数'] == 2, metrics


def test_empty_version_accepted():
    payload = {
        'chunk_size': 4,
        'assets': [{'asset': 'A.dpx', 'versions': [
            {'version_id': 'V1', 'encoding': 'utf8', 'content': ''},
        ]}],
        'deliveries': [{'asset': 'A.dpx', 'version_id': 'V1'}],
    }
    result = solve(payload)
    assert result['metrics']['验收版本数'] == 1, result['metrics']
    assert result['metrics']['唯一块数'] == 0, result['metrics']


def test_validate_rejects_bad_input():
    def invalid(**patch):
        payload = copy.deepcopy(SAMPLE)
        for key, value in patch.items():
            payload[key] = value
        try:
            validate(payload)
        except ValueError:
            return True
        return False

    assert invalid(chunk_size=0), '块长下界'
    assert invalid(chunk_size=4.0), '块长须为整数'
    assert invalid(deliveries=[{'asset': 'L17-frame07.dpx', 'version_id': 'NOPE'}]), '未知版本'
    assert invalid(deliveries=[{'asset': 'L17-frame07.dpx', 'version_id': 'L17-1120', 'fault': 'x'}]), '未知故障'
    assert invalid(deliveries=[{'asset': 'L17-frame07.dpx', 'version_id': 'L17-1119',
                                'fault': 'forge_baseline'}]), '首版无基准可伪造'
    assert not invalid(deliveries=[{'asset': 'L17-frame07.dpx', 'version_id': 'L17-1121',
                                    'fault': 'corrupt_block'}]), 'L17-1121 有随包新块，应可注入'
    dup = copy.deepcopy(SAMPLE)
    dup['assets'][0]['versions'][1]['version_id'] = 'L17-1119'
    try:
        validate(dup)
        raise AssertionError('版本编号重复应报错')
    except ValueError:
        pass
    no_block = {
        'chunk_size': 4,
        'assets': [{'asset': 'A.dpx', 'versions': [
            {'version_id': 'V1', 'encoding': 'utf8', 'content': 'LITEGRAY'},
            {'version_id': 'V2', 'encoding': 'utf8', 'content': 'LITEGRAY'},
        ]}],
        'deliveries': [{'asset': 'A.dpx', 'version_id': 'V2', 'fault': 'corrupt_block'}],
    }
    try:
        validate(no_block)
        raise AssertionError('V2 的块全部复用在库，无随包新块可注入')
    except ValueError:
        pass


def test_shared_blocks_shipped_once():
    result = solve(copy.deepcopy(SAMPLE))
    packages = section(result, '增量包目录')
    carried = sum(row['随包块数'] for row in packages)
    reused = sum(row['复用在库块数'] for row in packages)
    assert carried == 8, packages
    assert reused == 10, packages  # L17-1120 复用 3、L17-1121 复用 3、F08-01 与 F08-02 各复用 2
    wire = sum(row['随包字节数'] for row in packages)
    assert wire == 31, packages


if __name__ == '__main__':
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith('test_')]
    failures = 0
    for name, fn in tests:
        try:
            fn()
            print(f'PASS {name}')
        except Exception as exc:
            failures += 1
            print(f'FAIL {name}: {exc}')
    print(f'{len(tests) - failures}/{len(tests)} 通过')
    raise SystemExit(bool(failures))
