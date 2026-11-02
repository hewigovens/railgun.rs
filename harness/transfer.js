// Transfer vectors: the TS engine builds and proves one 1x2 private transfer from the
// test wallet, spending a synthetic shield note appended to the first 200
// Sepolia logs. Randomness is a seeded stream, so reruns give the same inputs
// (Groth16's own blinding still differs per proof).
//
// ARTIFACTS_DIR=<dir with 1x2/circuit.wasm, circuit.zkey, vkey.json>
// node harness/transfer.js <head-logs.jsonl> <mnemonic-file> <out-dir>
// Writes shield-log.json, transfer.json and witness.json to out-dir.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const resolveFrom = process.env.HARNESS_NODE_MODULES
  ? { paths: [process.env.HARNESS_NODE_MODULES] }
  : undefined;
const engineRoot = path.dirname(require.resolve('@railgun-community/engine', resolveFrom));
const eng = (rel) => require(path.join(engineRoot, rel));
const req = (name) => require(require.resolve(name, resolveFrom ?? { paths: [engineRoot] }));
const { ethers } = req('ethers');
const memdown = req('memdown');
const snarkjs = req('snarkjs');

const { ByteUtils } = eng('utils/bytes');
const { Database } = eng('database/database');
const { UTXOMerkletree } = eng('merkletree/utxo-merkletree');
const { RailgunWallet } = eng('wallet/railgun-wallet');
const { Prover } = eng('prover/prover');
const { V2Events } = eng('contracts/railgun-smart-wallet/V2/V2-events');
const { TXIDVersion } = eng('models/poi-types');
const { OutputType } = eng('models/formatted-types');
const { ShieldNoteERC20 } = eng('note/erc20/shield-note-erc20');
const { TransactNote } = eng('note/transact-note');
const { getTokenDataERC20 } = eng('note/note-util');
const { TransactionBatch } = eng('transaction/transaction-batch');
const { initPoseidonPromise } = eng('utils/poseidon');
const { POI } = eng('poi/poi');
const WalletInfo = eng('wallet/wallet-info').default;
const WALLET_SOURCE = 'rgrustcore';
const abi = require(path.join(engineRoot, 'abi/V2.1/RailgunSmartWallet.json'));

const SEED = 'railgun-rust-core m4';
let counter = 0;
const stream = (n) => {
  const out = [];
  while (out.length < n) {
    out.push(...crypto.createHash('sha256').update(`${SEED}:${counter}`).digest());
    counter += 1;
  }
  return Buffer.from(out.slice(0, n));
};
const draws = [];
ByteUtils.randomHex = (length = 32) => {
  const h = stream(length).toString('hex');
  draws.push(h);
  return h;
};

const WETH = '0xfff9976782d46cc05630d1f6ebab18b2324d6b14';
const SHIELD_VALUE = 10_000_000_000_000_000n; // 0.01
const SEND_VALUE = 3_000_000_000_000_000n; // 0.003
const MEMO = 'rust core m4';
const dec = (x) => BigInt(x).toString();

const main = async () => {
  const [headPath, mnemonicPath, outDir] = process.argv.slice(2);
  const artifactsDir = process.env.ARTIFACTS_DIR;
  if (initPoseidonPromise) await initPoseidonPromise;
  fs.mkdirSync(outDir, { recursive: true });
  const chain = { type: 0, id: 11155111 };
  const txidVersion = TXIDVersion.V2_PoseidonMerkle;
  const iface = new ethers.Interface(abi);
  const mnemonic = fs.readFileSync(mnemonicPath, 'utf8').trim();
  const encryptionKey = '0'.repeat(64);

  // POI off: no node, nothing required, all balance buckets spendable.
  WalletInfo.setWalletSource(WALLET_SOURCE);
  POI.init([], { isActive: () => false, isRequired: async () => false });
  const db = new Database(memdown());
  const tree = await UTXOMerkletree.create(db, chain, txidVersion, async () => true);
  const artifactGetter = {
    getArtifacts: async ({ nullifiers, commitmentsOut }) => {
      const dir = path.join(artifactsDir, `${nullifiers.length}x${commitmentsOut.length}`);
      return {
        wasm: fs.readFileSync(path.join(dir, 'circuit.wasm')),
        zkey: fs.readFileSync(path.join(dir, 'circuit.zkey')),
        vkey: JSON.parse(fs.readFileSync(path.join(dir, 'vkey.json'), 'utf8')),
        dat: undefined,
      };
    },
    assertArtifactExists: () => {},
    getArtifactsPOI: async () => {
      throw new Error('no POI artifacts');
    },
  };
  const prover = new Prover(artifactGetter);
  prover.setSnarkJSGroth16(snarkjs.groth16);
  const sender = await RailgunWallet.fromMnemonic(db, encryptionKey, mnemonic, 0, undefined, prover);
  const receiver = await RailgunWallet.fromMnemonic(db, encryptionKey, mnemonic, 1, undefined, prover);

  // Synthetic shield to the sender, as a log after the head logs.
  const lines = fs.readFileSync(headPath, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  const last = lines[lines.length - 1];
  let start = 0;
  for (const l of lines) {
    const p = iface.parseLog({ topics: l.topics, data: l.data });
    if (p && (p.name === 'Shield' || p.name === 'Transact')) {
      const n = p.name === 'Shield' ? p.args.commitments.length : p.args.hash.length;
      start = Number(p.args.startPosition) + n;
    }
  }
  const shieldRandom = ByteUtils.randomHex(16);
  const shieldPrivateKey = Buffer.from(ByteUtils.randomHex(32), 'hex');
  const shieldNote = new ShieldNoteERC20(sender.masterPublicKey, shieldRandom, SHIELD_VALUE, WETH);
  const request = await shieldNote.serialize(shieldPrivateKey, sender.viewingKeyPair.pubkey);
  const encoded = iface.encodeEventLog('Shield', [
    0,
    start,
    [request.preimage],
    [request.ciphertext],
    [0],
  ]);
  const shieldLog = {
    address: last.address,
    topics: encoded.topics,
    data: encoded.data,
    blockNumber: '0x' + (parseInt(last.blockNumber, 16) + 1).toString(16),
    transactionHash: '0x' + stream(32).toString('hex'),
    logIndex: '0x0',
  };
  fs.writeFileSync(path.join(outDir, 'shield-log.json'), JSON.stringify(shieldLog, null, 1) + '\n');

  const nullifierEvents = [];
  for (const l of [...lines, shieldLog]) {
    const p = iface.parseLog({ topics: l.topics, data: l.data });
    if (!p) continue;
    const block = parseInt(l.blockNumber, 16);
    if (p.name === 'Shield') {
      const ev = V2Events.formatShieldEvent(p.args, l.transactionHash, block, p.args.fees, undefined);
      await tree.queueLeaves(ev.treeNumber, ev.startPosition, ev.commitments);
    } else if (p.name === 'Transact') {
      const ev = V2Events.formatTransactEvent(p.args, l.transactionHash, block, undefined);
      await tree.queueLeaves(ev.treeNumber, ev.startPosition, ev.commitments);
    } else if (p.name === 'Nullified') {
      nullifierEvents.push(...V2Events.formatNullifiedEvents(p.args, l.transactionHash, block));
    }
  }
  await tree.updateTreesFromWriteQueue();
  await tree.nullify(nullifierEvents);
  await sender.loadUTXOMerkletree(txidVersion, tree);
  await sender.decryptBalances(txidVersion, chain, undefined, true);
  const txos = await sender.TXOs(txidVersion, chain);
  if (txos.length !== 1) throw new Error(`expected 1 TXO, got ${txos.length}`);

  // Capture what the engine hands to snarkjs.
  let captured;
  const inner = prover.groth16.fullProveRailgun;
  prover.groth16.fullProveRailgun = async (inputs, ...rest) => {
    const t0 = Date.now();
    const out = await inner(inputs, ...rest);
    captured = { inputs, proof: out.proof, ms: Date.now() - t0 };
    return out;
  };

  const batch = new TransactionBatch(chain);
  batch.addOutput(
    TransactNote.createTransfer(
      receiver.addressKeys,
      sender.addressKeys,
      SEND_VALUE,
      getTokenDataERC20(WETH),
      false,
      OutputType.Transfer,
      MEMO,
    ),
  );
  const { provedTransactions } = await batch.generateTransactions(
    prover,
    sender,
    txidVersion,
    encryptionKey,
    () => {},
    false,
  );
  if (provedTransactions.length !== 1) throw new Error('expected one transaction');
  const tx = provedTransactions[0];

  const formatted = Object.fromEntries(
    Object.entries(captured.inputs).map(([k, v]) => [k, Array.isArray(v) ? v.map(dec) : dec(v)]),
  );
  const wasm = fs.readFileSync(path.join(artifactsDir, '1x2', 'circuit.wasm'));
  const wtns = { type: 'mem' };
  await snarkjs.wtns.calculate(captured.inputs, wasm, wtns);
  const witness = (await snarkjs.wtns.exportJson(wtns.data)).map(dec);

  const calldata = iface.encodeFunctionData('transact', [[tx]]);
  const out = {
    note: 'Generated by harness/transfer.js from the TS engine 9.6.0. Wallet index 0 sends to index 1.',
    shield: {
      random: shieldRandom,
      value: SHIELD_VALUE.toString(),
      token: WETH,
      position: start,
    },
    send: { value: SEND_VALUE.toString(), memo: MEMO, showSender: false, walletSource: WALLET_SOURCE },
    receiverAddress: receiver.getAddress(),
    formattedInputs: formatted,
    snarkjsProof: captured.proof,
    snarkjsProveMs: captured.ms,
    transaction: {
      merkleRoot: ethers.toBeHex(tx.merkleRoot, 32),
      nullifiers: tx.nullifiers.map((n) => ethers.toBeHex(n, 32)),
      commitments: tx.commitments.map((c) => ethers.toBeHex(c, 32)),
      boundParams: {
        treeNumber: Number(tx.boundParams.treeNumber),
        minGasPrice: tx.boundParams.minGasPrice.toString(),
        unshield: Number(tx.boundParams.unshield),
        chainID: BigInt(tx.boundParams.chainID).toString(),
        adaptContract: tx.boundParams.adaptContract,
        adaptParams: tx.boundParams.adaptParams,
        commitmentCiphertext: tx.boundParams.commitmentCiphertext.map((c) => ({
          ciphertext: c.ciphertext,
          blindedSenderViewingKey: c.blindedSenderViewingKey,
          blindedReceiverViewingKey: c.blindedReceiverViewingKey,
          annotationData: c.annotationData,
          memo: c.memo,
        })),
      },
    },
    calldata,
    randomDraws: draws,
  };
  fs.writeFileSync(path.join(outDir, 'transfer.json'), JSON.stringify(out, null, 1) + '\n');
  fs.writeFileSync(path.join(outDir, 'witness.json'), JSON.stringify(witness) + '\n');
  console.log(`ok: 1x2 proved by snarkjs in ${captured.ms} ms; witness ${witness.length} signals`);
  process.exit(0);
};

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
