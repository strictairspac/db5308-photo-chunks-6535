from base64 import b64decode
from collections import Counter

from .offline_sync import FAULTS, Pending, Receiver, build_packages, tamper

MAX_BYTES = 256 * 1024
MAX_BLOCK_REFERENCES = 2048
MAX_VERSIONS = 100
MAX_ASSETS = 20
MAX_DELIVERIES = 200

SPEC = {
    'name': '光坞影像·异地底片库离线同步验收',
    'summary': '按接收方已验收的基准从发件接口取增量包，共享块只传一次；接收方验块、验整份后一次性切换在役版本。',
    'customer': '光坞影像·数字底片归档组',
    'entity_labels': ['增量包', '投递验收', '接收台账'],
    'field_labels': {
        'chunk_size': '固定块大小（字节）',
        'assets': '底片版本链',
        'asset': '底片文件名',
        'versions': '版本序列（按从旧到新）',
        'version_id': '版本编号',
        'encoding': '内容编码',
        'content': '内容',
        'deliveries': '投递序列（按到达顺序）',
        'fault': '注入故障',
    },
    'guidance': '内容编码用 utf8 或 base64。发件接口按版本链顺序出增量包，共享块只随首次需要的包传一次。投递按到达顺序验收，可注入故障：corrupt_block 翻转随包首块一位，drop_block 丢失随包首块，forge_digest 篡改整份摘要，forge_baseline 篡改基准摘要。乱序包先暂存，基准补齐后接续验收。',
    'sample': {
        'chunk_size': 4,
        'assets': [
            {'asset': 'L17-frame07.dpx', 'versions': [
                {'version_id': 'L17-1119', 'encoding': 'utf8', 'content': 'LITEGRAYSCANOLD!'},
                {'version_id': 'L17-1120', 'encoding': 'utf8', 'content': 'LITEGRAYSCANEDIT'},
                {'version_id': 'L17-1121', 'encoding': 'utf8', 'content': 'LITESCANEDITSCANEND'},
            ]},
            {'asset': 'L17-frame08.dpx', 'versions': [
                {'version_id': 'F08-01', 'encoding': 'utf8', 'content': 'LITESCANHEAD'},
                {'version_id': 'F08-02', 'encoding': 'utf8', 'content': 'LITESCANTAIL'},
            ]},
        ],
        'deliveries': [
            {'asset': 'L17-frame08.dpx', 'version_id': 'F08-01'},
            {'asset': 'L17-frame07.dpx', 'version_id': 'L17-1121'},
            {'asset': 'L17-frame07.dpx', 'version_id': 'L17-1119'},
            {'asset': 'L17-frame07.dpx', 'version_id': 'L17-1120', 'fault': 'corrupt_block'},
            {'asset': 'L17-frame08.dpx', 'version_id': 'F08-02'},
            {'asset': 'L17-frame07.dpx', 'version_id': 'L17-1120', 'fault': 'forge_baseline'},
            {'asset': 'L17-frame07.dpx', 'version_id': 'L17-1120'},
            {'asset': 'L17-frame07.dpx', 'version_id': 'L17-1120'},
            {'asset': 'L17-frame07.dpx', 'version_id': 'L17-1121'},
        ],
    },
    'expect': {
        '版本总数': 5,
        '验收版本数': 5,
        '逻辑字节数': 75,
        '唯一块数': 8,
        '去重后传输字节数': 31,
        '去重节省字节数': 44,
        '实际线路字节数': 46,
        '乱序暂存次数': 2,
        '补齐接续验收数': 2,
        '拒收包数': 2,
        '重复投递跳过数': 2,
        '暂存未决包数': 0,
        '台账条目数': 13,
        '还原查验通过数': 13,
    },
}

FAULT_LABELS = {
    'corrupt_block': '块损坏',
    'drop_block': '块丢失',
    'forge_digest': '伪造整份摘要',
    'forge_baseline': '伪造基准摘要',
    None: '无',
}
VERDICT_LABELS = {'accepted': '验收', 'pending': '暂存', 'rejected': '拒收', 'duplicate': '重复跳过'}


def _rows(payload, key, minimum, maximum):
    rows = payload.get(key)
    label = SPEC['field_labels'][key]
    if not isinstance(rows, list) or not minimum <= len(rows) <= maximum:
        raise ValueError(f'「{label}」须提供 {minimum} 至 {maximum} 条记录')
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError(f'「{label}」须由对象记录组成')
    return rows


def _name(value, label, limit=120):
    if not isinstance(value, str) or not 1 <= len(value) <= limit or value != value.strip():
        raise ValueError(f'{label}须为 1 至 {limit} 个字符，且首尾不能有空白')
    return value


def _decode(row, version_id):
    content = row.get('content')
    if not isinstance(content, str):
        raise ValueError(f'版本 {version_id} 的内容须为字符串')
    if len(content) > 4 * ((MAX_BYTES + 2) // 3):
        raise ValueError(f'底片内容合计最多 {MAX_BYTES} 字节')
    encoding = row.get('encoding')
    try:
        if encoding == 'utf8':
            return content.encode('utf-8')
        if encoding == 'base64':
            return b64decode(content, validate=True)
    except ValueError:
        raise ValueError(f'版本 {version_id} 的 {encoding} 内容无效') from None
    raise ValueError(f'版本 {version_id} 的内容编码须为 utf8 或 base64')


def _prepare(payload):
    if not isinstance(payload, dict):
        raise ValueError('业务输入须为对象')
    chunk_size = payload.get('chunk_size')
    if type(chunk_size) is not int or not 1 <= chunk_size <= MAX_BYTES:
        raise ValueError(f'固定块大小须为 1 至 {MAX_BYTES} 之间的整数')

    chains, seen_assets = [], set()
    size = references = total_versions = 0
    for row in _rows(payload, 'assets', 1, MAX_ASSETS):
        asset = _name(row.get('asset'), '底片文件名')
        if asset in seen_assets:
            raise ValueError(f'底片文件名重复：{asset}')
        seen_assets.add(asset)
        version_rows = row.get('versions')
        if not isinstance(version_rows, list) or not 1 <= len(version_rows) <= MAX_VERSIONS:
            raise ValueError(f'底片 {asset} 须提供 1 至 {MAX_VERSIONS} 个版本')
        versions, seen_ids = [], set()
        for item in version_rows:
            if not isinstance(item, dict):
                raise ValueError(f'底片 {asset} 的版本记录须为对象')
            version_id = _name(item.get('version_id'), '版本编号', 64)
            if version_id in seen_ids:
                raise ValueError(f'底片 {asset} 的版本编号重复：{version_id}')
            seen_ids.add(version_id)
            content = _decode(item, version_id)
            size += len(content)
            references += (len(content) + chunk_size - 1) // chunk_size
            total_versions += 1
            if size > MAX_BYTES or references > MAX_BLOCK_REFERENCES or total_versions > MAX_VERSIONS:
                raise ValueError(f'底片内容合计最多 {MAX_BYTES} 字节，版本最多 {MAX_VERSIONS} 个，'
                                 f'清单中的块引用最多 {MAX_BLOCK_REFERENCES} 次')
            versions.append((version_id, content))
        chains.append((asset, versions))

    packages, sender_store = build_packages(chains, chunk_size)
    deliveries = []
    for row in _rows(payload, 'deliveries', 1, MAX_DELIVERIES):
        asset = _name(row.get('asset'), '投递底片文件名')
        version_id = _name(row.get('version_id'), '投递版本编号', 64)
        package = packages.get((asset, version_id))
        if package is None:
            raise ValueError(f'投递引用了未定义的版本：{asset} {version_id}')
        fault = row.get('fault')
        if fault is not None:
            if fault not in FAULTS:
                raise ValueError('注入故障须为 corrupt_block、drop_block、forge_digest 或 forge_baseline')
            if fault in ('corrupt_block', 'drop_block') and not package.blocks:
                raise ValueError(f'版本 {version_id} 的增量包没有随包新块，无法注入{fault}')
            if fault == 'forge_baseline' and package.baseline_id is None:
                raise ValueError(f'版本 {version_id} 是首版，没有可伪造的基准')
        deliveries.append((asset, version_id, fault))
    return chains, packages, sender_store, deliveries


def validate(payload):
    _prepare(payload)


def _delivery_row(seq, package, fault, verdict, detail, source):
    return {
        '投递序号': seq,
        '底片': package.asset,
        '版本': package.version_id,
        '注入故障': FAULT_LABELS[fault],
        '判定': VERDICT_LABELS[verdict] if source == '投递' else f'{VERDICT_LABELS[verdict]}（补齐接续）',
        '说明': detail,
    }


def _restore_row(asset, stage, manifest, restored):
    if restored.issues:
        verdict = '块查验失败'
    elif restored.content is None:
        verdict = '整份文件校验失败'
    else:
        verdict = '校验通过'
    return {
        '底片': asset,
        '阶段': stage,
        '版本': manifest.snapshot_id,
        '预期字节数': manifest.size,
        '实测字节数': restored.size,
        '预期 SHA-256': manifest.digest,
        '实测 SHA-256': restored.digest,
        '判定': verdict,
    }


def solve(payload, engine=None):
    chains, packages, sender_store, deliveries = _prepare(payload)
    receiver = Receiver()
    delivery_rows = []
    counts = Counter()
    wire_bytes = 0
    for seq, (asset, version_id, fault) in enumerate(deliveries, start=1):
        package = tamper(packages[(asset, version_id)], fault)
        wire_bytes += sum(map(len, package.blocks.values()))
        verdict, detail = receiver.receive(package)
        counts[verdict] += 1
        if verdict == 'pending':
            receiver.pending.append(Pending(seq, package, fault, detail))
        delivery_rows.append(_delivery_row(seq, package, fault, verdict, detail, '投递'))
        for entry, resumed_verdict, resumed_detail in receiver.drain():
            counts[resumed_verdict] += 1
            counts['resumed'] += resumed_verdict == 'accepted'
            delivery_rows.append(_delivery_row(entry.seq, entry.package, entry.fault,
                                               resumed_verdict, resumed_detail, '补齐接续'))

    for asset, versions in chains:
        for version_id, _ in versions:
            if version_id in receiver.history.get(asset, []):
                receiver.record_restore('终态复查', packages[(asset, version_id)].manifest)

    delivered = Counter((asset, version_id) for asset, version_id, _ in deliveries)
    pending_keys = {(entry.package.asset, entry.package.version_id) for entry in receiver.pending}
    package_rows = []
    for asset, versions in chains:
        for version_id, _ in versions:
            package = packages[(asset, version_id)]
            if version_id in receiver.history.get(asset, []):
                status = '已验收'
            elif (asset, version_id) in pending_keys:
                status = '暂存待齐'
            elif delivered[(asset, version_id)]:
                status = '拒收待重投'
            else:
                status = '未投递'
            package_rows.append({
                '底片': asset,
                '目标版本': version_id,
                '基准版本': package.baseline_id or '（首版）',
                '基准 SHA-256': package.baseline_digest or '',
                '文件字节数': package.size,
                '文件 SHA-256': package.digest,
                '清单块数': len(package.addresses),
                '随包块数': len(package.blocks),
                '随包字节数': sum(map(len, package.blocks.values())),
                '复用在库块数': len(set(package.addresses)) - len(package.blocks),
                '最终状态': status,
            })

    restore_rows = [_restore_row(manifest.asset, stage, manifest, restored)
                    for stage, manifest, restored in receiver.restores]
    ledger_rows = [dict({'序号': index}, **entry) for index, entry in enumerate(receiver.ledger, start=1)]
    pending_rows = [{
        '投递序号': entry.seq,
        '底片': entry.package.asset,
        '版本': entry.package.version_id,
        '等待原因': entry.note,
    } for entry in receiver.pending]

    accepted = sum(len(ids) for ids in receiver.history.values())
    logical_bytes = sum(package.size for package in packages.values())
    dedup_bytes = sum(map(len, sender_store.values()))
    metrics = {
        '版本总数': len(packages),
        '验收版本数': accepted,
        '逻辑字节数': logical_bytes,
        '唯一块数': len(sender_store),
        '去重后传输字节数': dedup_bytes,
        '去重节省字节数': logical_bytes - dedup_bytes,
        '实际线路字节数': wire_bytes,
        '乱序暂存次数': counts['pending'],
        '补齐接续验收数': counts['resumed'],
        '拒收包数': counts['rejected'],
        '重复投递跳过数': counts['duplicate'],
        '暂存未决包数': len(receiver.pending),
        '台账条目数': len(receiver.ledger),
        '还原查验通过数': sum(row['判定'] == '校验通过' for row in restore_rows),
    }
    summary = (f'验收 {accepted}/{len(packages)} 个版本，拒收 {counts["rejected"]} 包，'
               f'重复跳过 {counts["duplicate"]} 包，暂存未决 {len(receiver.pending)} 包。')
    return {
        'summary': summary,
        'metrics': metrics,
        'sections': [
            {'title': '增量包目录', 'rows': package_rows},
            {'title': '投递验收', 'rows': delivery_rows},
            {'title': '还原查验', 'rows': restore_rows},
            {'title': '接收台账', 'rows': ledger_rows},
            {'title': '暂存区（验收结束）', 'rows': pending_rows},
        ],
    }
