// Scan check: the TS engine rebuilds the UTXO tree from the same proxy logs and
// scans one wallet, and the result is diffed against the Rust scan_file output.
//
// node harness/scan.js <logs.jsonl> <mnemonic-file> [rust-scan.json]
// Without the Rust file it prints the engine's result as JSON (a vector).
// HARNESS_NODE_MODULES points at a node_modules with the engine and memdown.

const fs = require('fs');
const path = require('path');

const resolveFrom = process.env.HARNESS_NODE_MODULES
  ? { paths: [process.env.HARNESS_NODE_MODULES] }
  : undefined;
const engineRoot = path.dirname(require.resolve('@railgun-community/engine', resolveFrom));
const eng = (rel) => require(path.join(engineRoot, rel));
const req = (name) => require(require.resolve(name, resolveFrom ?? { paths: [engineRoot] }));
const { ethers } = req('ethers');
const memdown = req('memdown');

const { Database } = eng('database/database');
const { UTXOMerkletree } = eng('merkletree/utxo-merkletree');
const { RailgunWallet } = eng('wallet/railgun-wallet');
const { Prover } = eng('prover/prover');
const { V2Events } = eng('contracts/railgun-smart-wallet/V2/V2-events');
const { TXIDVersion } = eng('models/poi-types');
const { initPoseidonPromise } = eng('utils/poseidon');
const abi = require(path.join(engineRoot, 'abi/V2.1/RailgunSmartWallet.json'));

const hex32 = (x) => {
  const v = typeof x === 'string' && !x.startsWith('0x') ? BigInt('0x' + x) : BigInt(x);
  return '0x' + v.toString(16).padStart(64, '0');
};

const main = async () => {
  const [logsPath, mnemonicPath, rustPath] = process.argv.slice(2);
  if (initPoseidonPromise) await initPoseidonPromise;
  const chain = { type: 0, id: 11155111 };
  const txidVersion = TXIDVersion.V2_PoseidonMerkle;
  const iface = new ethers.Interface(abi);

  const db = new Database(memdown());
  const tree = await UTXOMerkletree.create(db, chain, txidVersion, async () => true);

  const lines = fs.readFileSync(logsPath, 'utf8').split('\n').filter(Boolean);
  const counts = { shield: 0, transact: 0, nullified: 0 };
  const nullifiers = [];
  for (const line of lines) {
    const l = JSON.parse(line);
    let parsed;
    try {
      parsed = iface.parseLog({ topics: l.topics, data: l.data });
    } catch {
      continue;
    }
    if (!parsed) continue;
    const block = parseInt(l.blockNumber, 16);
    if (parsed.name === 'Shield') {
      const ev = V2Events.formatShieldEvent(parsed.args, l.transactionHash, block, parsed.args.fees, undefined);
      await tree.queueLeaves(ev.treeNumber, ev.startPosition, ev.commitments);
      counts.shield += 1;
    } else if (parsed.name === 'Transact') {
      const ev = V2Events.formatTransactEvent(parsed.args, l.transactionHash, block, undefined);
      await tree.queueLeaves(ev.treeNumber, ev.startPosition, ev.commitments);
      counts.transact += 1;
    } else if (parsed.name === 'Nullified') {
      nullifiers.push(...V2Events.formatNullifiedEvents(parsed.args, l.transactionHash, block));
      counts.nullified += 1;
    }
  }
  await tree.updateTreesFromWriteQueue();
  await tree.nullify(nullifiers);

  const trees = [];
  for (let t = 0; ; t += 1) {
    const len = await tree.getTreeLength(t);
    if (len === 0) break;
    trees.push({ leaves: len, root: hex32(await tree.getRoot(t)) });
  }

  const mnemonic = fs.readFileSync(mnemonicPath, 'utf8').trim();
  const prover = new Prover({ getArtifacts: async () => { throw new Error('no artifacts'); } });
  const wallet = await RailgunWallet.fromMnemonic(db, '0'.repeat(64), mnemonic, 0, undefined, prover);
  await wallet.loadUTXOMerkletree(txidVersion, tree);
  await wallet.decryptBalances(txidVersion, chain, undefined, true);

  const txos = (await wallet.TXOs(txidVersion, chain))
    .map((t) => ({
      tree: t.tree,
      position: t.position,
      tokenHash: hex32(t.note.tokenHash),
      value: t.note.value.toString(),
      nullifier: hex32(t.nullifier),
      spentTxid: t.spendtxid ? hex32(t.spendtxid) : null,
    }))
    .sort((a, b) => a.tree - b.tree || a.position - b.position);
  const sent = (await wallet.getSentCommitments(txidVersion, chain, undefined))
    .map((s) => ({ tree: s.tree, position: s.position, tokenHash: hex32(s.note.tokenHash), value: s.note.value.toString() }))
    .sort((a, b) => a.tree - b.tree || a.position - b.position);
  const balances = {};
  for (const t of txos) {
    if (t.spentTxid) continue;
    balances[t.tokenHash] = (BigInt(balances[t.tokenHash] ?? 0) + BigInt(t.value)).toString();
  }

  const sortedBalances = Object.fromEntries(Object.entries(balances).sort(([a], [b]) => (a < b ? -1 : 1)));
  const ts = { counts, nullifiers: nullifiers.length, trees, txos, sent, balances: sortedBalances };
  if (!rustPath) {
    // No Rust output given: print the engine's result as a vector.
    console.log(JSON.stringify(ts, null, 2));
    return;
  }
  const rust = JSON.parse(fs.readFileSync(rustPath, 'utf8'));
  const rustView = {
    counts: { shield: rust.counts.shield, transact: rust.counts.transact, nullified: rust.counts.nullified },
    nullifiers: rust.nullifiers,
    trees: rust.trees,
    txos: rust.txos.map((t) => ({
      tree: t.tree,
      position: t.position,
      tokenHash: t.tokenHash,
      value: t.value,
      nullifier: t.nullifier,
      spentTxid: t.spentTxid,
    })),
    sent: rust.sent.map((s) => ({ tree: s.tree, position: s.position, tokenHash: s.tokenHash, value: s.value })),
    balances: rust.balances,
  };

  let failures = 0;
  for (const key of Object.keys(ts)) {
    const a = JSON.stringify(ts[key]);
    const b = JSON.stringify(rustView[key]);
    if (a === b) {
      console.log(`ok ${key}`);
    } else {
      failures += 1;
      console.log(`DIFF ${key}\n  ts:   ${a.slice(0, 600)}\n  rust: ${b.slice(0, 600)}`);
    }
  }
  console.log(`engine: ${trees.map((t) => `${t.leaves} leaves root ${t.root}`).join('; ')}; ${txos.length} TXOs, ${sent.length} sent`);
  process.exit(failures ? 1 : 0);
};

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
