"""异地底片库离线同步的发件接口与接收方。

发件接口按接收方已验收的基准出增量包，共享内容块只随包传一次。
接收方按到达顺序验收：基准编号与内容摘要都对得上才套用，先验随包块，
清单块到齐后验整份底片，全部通过才一次性切换在役版本；切换前旧版仍能还原。
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256

from .chunk_store import Manifest, ingest, restore

FAULTS = ('corrupt_block', 'drop_block', 'forge_digest', 'forge_baseline')


@dataclass(frozen=True)
class Package:
    """发件接口出的一份增量包：基准指针、目标清单和本次随包携带的新块。"""
    asset: str
    version_id: str
    baseline_id: str | None
    baseline_digest: str | None
    size: int
    digest: str
    addresses: tuple[str, ...]
    blocks: dict[str, bytes]

    @property
    def manifest(self):
        return Manifest(self.version_id, self.asset, self.size, self.digest, self.addresses)


@dataclass
class Pending:
    """接收方暂存的在途包，等待基准补齐或内容块到齐。"""
    seq: int
    package: Package
    fault: str | None
    note: str


def build_packages(chains, chunk_size):
    """按接口顺序（底片依次、版本依次）出增量包。共享块只随首次需要的包传一次。

    返回 (packages, store)：packages 以 (底片, 版本) 为键，store 为全量唯一块目录。
    """
    sent, store, packages = set(), {}, {}
    for asset, versions in chains:
        baseline = None
        for version_id, content in versions:
            manifest = ingest(version_id, asset, content, chunk_size, store)
            carried = {address: store[address]
                       for address in dict.fromkeys(manifest.addresses) if address not in sent}
            sent.update(carried)
            packages[(asset, version_id)] = Package(
                asset, version_id,
                baseline.snapshot_id if baseline else None,
                baseline.digest if baseline else None,
                manifest.size, manifest.digest, manifest.addresses, carried)
            baseline = manifest
    return packages, store


def _flip_hex(digest):
    return ('1' if digest[0] != '1' else '2') + digest[1:]


def tamper(package, fault):
    """按投递故障改造在途包；故障只作用于本次投递，不改发件接口里的原包。"""
    if fault is None:
        return package
    if fault == 'corrupt_block':
        address, block = next(iter(package.blocks.items()))
        blocks = dict(package.blocks)
        blocks[address] = bytes([block[0] ^ 1]) + block[1:]
        return replace(package, blocks=blocks)
    if fault == 'drop_block':
        blocks = dict(package.blocks)
        blocks.pop(next(iter(blocks)))
        return replace(package, blocks=blocks)
    if fault == 'forge_digest':
        return replace(package, digest=_flip_hex(package.digest))
    if fault == 'forge_baseline':
        return replace(package, baseline_digest=_flip_hex(package.baseline_digest))
    raise ValueError(f'未知投递故障：{fault}')


class Receiver:
    """接收方：内容寻址块库、在役版本指针、暂存区与接收台账。"""

    def __init__(self):
        self.store = {}
        self.live = {}
        self.history = {}
        self.pending = []
        self.ledger = []
        self.restores = []

    def record_restore(self, stage, manifest):
        self.restores.append((stage, manifest, restore(manifest, self.store)))

    def _commit_blocks(self, package):
        """随包块逐块验 SHA-256，过检的入内容寻址库（已在库不重复入账）。"""
        bad = [address for address, block in package.blocks.items()
               if sha256(block).hexdigest() != address]
        for address, block in package.blocks.items():
            if address not in bad and address not in self.store:
                self.store[address] = block
                self.ledger.append({
                    '类型': '块入库', '底片': package.asset, '版本': package.version_id,
                    '内容块 SHA-256': address, '字节数': len(block),
                    '说明': '随包到达，块校验通过',
                })
        return bad

    def receive(self, package):
        """验收一份在途包，返回 (判定, 说明)。判定：accepted/pending/rejected/duplicate。"""
        asset = package.asset
        current = self.live.get(asset)
        history = self.history.setdefault(asset, [])
        if current is not None and current.snapshot_id == package.version_id:
            if current.digest == package.digest:
                return 'duplicate', '该版本已在役，重复投递不再入账'
            return 'rejected', '在役版本编号相同但内容摘要不同，拒收'
        if package.version_id in history:
            return 'duplicate', '该版本此前已验收，重复投递不再入账'
        if package.baseline_id is None:
            if current is not None:
                return 'rejected', '首版包基准为空，但接收方已有在役版本，拒收'
        else:
            if current is None or current.snapshot_id != package.baseline_id:
                if package.baseline_id in history:
                    return 'rejected', f'基准版本 {package.baseline_id} 已被后续版本越过，不能套用'
                return 'pending', f'基准版本 {package.baseline_id} 尚未验收，整包暂存'
            if current.digest != package.baseline_digest:
                return 'rejected', '基准编号一致但内容摘要不符，不能套用'
        bad = self._commit_blocks(package)
        if bad:
            return 'rejected', f'{len(bad)} 个随包块摘要与地址不符，整包拒收'
        missing = [address for address in dict.fromkeys(package.addresses)
                   if address not in self.store]
        if missing:
            return 'pending', f'{len(missing)} 个内容块尚未到齐，整包暂存'
        content = b''.join(self.store[address] for address in package.addresses)
        if len(content) != package.size or sha256(content).hexdigest() != package.digest:
            return 'rejected', '整份底片校验失败，拒收'
        if current is not None:
            self.record_restore('切换前旧版', current)
        self.live[asset] = package.manifest
        history.append(package.version_id)
        self.ledger.append({
            '类型': '版本验收', '底片': asset, '版本': package.version_id,
            '内容块 SHA-256': '', '字节数': package.size,
            '说明': '首次验收，置为在役版本' if current is None
                    else f'在役版本 {current.snapshot_id} → {package.version_id}',
        })
        self.record_restore('切换后新版', package.manifest)
        return 'accepted', '块与整份底片均验过，一次性切换在役版本'

    def drain(self):
        """基准或内容块补齐后，扫描暂存区接续处理，直到没有可推进的包。"""
        resolved = []
        while True:
            progress = False
            for entry in list(self.pending):
                verdict, detail = self.receive(entry.package)
                if verdict == 'pending':
                    entry.note = detail
                    continue
                self.pending.remove(entry)
                resolved.append((entry, verdict, detail))
                progress = True
            if not progress:
                return resolved
